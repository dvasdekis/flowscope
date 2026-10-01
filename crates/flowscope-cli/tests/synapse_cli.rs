use std::io::Write;
use std::process::{Command, Stdio};

fn analyze_mssql(sql: &str) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["-d", "mssql", "-f", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start FlowScope CLI");
    child
        .stdin
        .take()
        .expect("CLI stdin")
        .write_all(sql.as_bytes())
        .expect("write SQL");
    let output = child.wait_with_output().expect("read CLI output");
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI JSON result");
    let has_errors = result["issues"]
        .as_array()
        .expect("CLI issues")
        .iter()
        .any(|issue| issue["severity"] == "error");
    assert_eq!(
        output.status.code(),
        Some(if has_errors { 1 } else { 0 }),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    result
}

fn has_issue(result: &serde_json::Value, code: &str) -> bool {
    result["issues"]
        .as_array()
        .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code))
}

fn has_warning(result: &serde_json::Value, code: &str) -> bool {
    result["issues"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == code && issue["severity"] == "warning")
    })
}

#[test]
fn cli_analyzes_repeated_go_batches() {
    let result = analyze_mssql("SELECT 1;\nGO 2\nSELECT 2;\nGO\n");

    assert_eq!(result["statements"].as_array().unwrap().len(), 3);
    assert_eq!(result["summary"]["statementCount"], 3);
    assert_eq!(result["statements"][0]["span"]["start"], 0);
    assert_eq!(result["statements"][0]["span"]["end"], 8);
    assert_eq!(
        result["statements"][0]["span"],
        result["statements"][1]["span"]
    );
    assert_eq!(result["statements"][2]["span"]["start"], 15);
    assert_eq!(result["statements"][2]["span"]["end"], 23);
    assert!(!has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_analyzes_unparenthesized_synapse_procedure_parameters() {
    let sql = "CREATE OR ALTER PROC dbo.copy_rows @source_id INT = 7 OUTPUT, @rows dbo.RowList READONLY AS BEGIN SELECT N'CREATE PROC hidden @x INT OUTPUT'; END";
    let result = analyze_mssql(sql);

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert_eq!(result["statements"][0]["statementType"], "CREATE_PROCEDURE");
    assert_eq!(result["statements"][0]["span"]["start"], 0);
    assert_eq!(result["statements"][0]["span"]["end"], sql.len());
    assert!(result["nodes"].as_array().unwrap().is_empty());
    assert!(result["edges"].as_array().unwrap().is_empty());
    assert!(!has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_keeps_malformed_synapse_procedure_parameters_as_parse_errors() {
    let result = analyze_mssql("CREATE OR ALTER PROC dbo.copy_rows @source_id INT, AS SELECT 1;");

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_analyzes_synapse_openrowset_without_parse_errors() {
    let result = analyze_mssql(
        "SELECT file.id FROM OPENROWSET(BULK ('https://storage.example/data/a.parquet', 'https://storage.example/data/b.parquet'), FORMAT = 'PARQUET') WITH (id BIGINT) AS file",
    );

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert!(!result["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["code"] == "PARSE_ERROR"));
    assert!(result["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|node| node["type"] != "table"));
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
}

#[test]
fn cli_rejects_a_trailing_comma_in_bulk_file_lists() {
    let result = analyze_mssql(
        "SELECT * FROM OPENROWSET(BULK ('data/a.parquet',), FORMAT = 'PARQUET') AS file",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_keeps_malformed_synapse_openrowset_as_a_parse_error() {
    let result = analyze_mssql("SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'TEXT') AS file");

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_keeps_external_file_formats_out_of_lineage() {
    let sql = "/* synthetic metadata */ CREATE EXTERNAL FILE FORMAT [synthetic_csv] WITH (FORMAT_TYPE = DELIMITEDTEXT, FORMAT_OPTIONS (FIELD_TERMINATOR = ',', FIRST_ROW = 2))";
    let result = analyze_mssql(sql);

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["statements"][0]["statementType"],
        "CREATE_EXTERNAL_FILE_FORMAT"
    );
    assert!(result["nodes"].as_array().unwrap().is_empty());
    assert!(result["edges"].as_array().unwrap().is_empty());
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
    assert!(!has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_keeps_unsupported_external_file_format_options_as_parse_errors() {
    let result = analyze_mssql(
        "CREATE EXTERNAL FILE FORMAT synthetic_parquet WITH (FORMAT_TYPE = PARQUET, FORMAT_OPTIONS (FIELD_TERMINATOR = ','))",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_accepts_cetas_without_inventing_external_lineage() {
    let sql = "CREATE EXTERNAL TABLE dbo.export_rows ([export_id]) WITH (LOCATION = 'export/', DATA_SOURCE = storage_source, FILE_FORMAT = parquet_format) AS SELECT id FROM dbo.source_rows";
    let result = analyze_mssql(sql);

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["statements"][0]["statementType"],
        "CREATE_EXTERNAL_TABLE_AS_SELECT"
    );
    assert_eq!(result["statements"][0]["span"]["start"], 0);
    assert_eq!(result["statements"][0]["span"]["end"], sql.len());
    assert!(result["nodes"].as_array().unwrap().is_empty());
    assert!(result["edges"].as_array().unwrap().is_empty());
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
    assert!(!has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_rejects_cetas_with_a_malformed_select() {
    let result = analyze_mssql(
        "CREATE EXTERNAL TABLE dbo.export_rows WITH (LOCATION = 'export/', DATA_SOURCE = storage_source, FILE_FORMAT = parquet_format) AS SELECT FROM",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_rejects_typed_cetas_output_columns() {
    let result = analyze_mssql(
        "CREATE EXTERNAL TABLE dbo.export_rows (export_id INT) WITH (LOCATION = 'export/', DATA_SOURCE = storage_source, FILE_FORMAT = parquet_format) AS SELECT id FROM dbo.source_rows",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_accepts_inline_tvf_cte_without_outer_parentheses() {
    let sql = "CREATE FUNCTION dbo.demo_rows() RETURNS TABLE AS RETURN WITH demo_cte AS (SELECT 1 AS demo_value) SELECT demo_value FROM demo_cte";
    let result = analyze_mssql(sql);

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert_eq!(result["statements"][0]["span"]["start"], 0);
    assert_eq!(result["statements"][0]["span"]["end"], sql.len());
    assert!(!has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_accepts_measured_external_metadata_and_batch_shapes() {
    for (sql, count) in [
        (
            "CREATE EXTERNAL TABLE dbo.demo_rows (id INT, label VARCHAR(20)) WITH (LOCATION = 'data/', DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet)",
            1,
        ),
        (
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); END",
            1,
        ),
        (
            "SELECT src.label FROM OPENROWSET(BULK ('data/a.csv'), FORMAT = 'CSV') WITH (label VARCHAR(20) COLLATE Latin1_General_100_BIN2_UTF8) AS src",
            1,
        ),
        ("SELECT 1\nSET NOCOUNT ON", 2),
    ] {
        let result = analyze_mssql(sql);
        assert_eq!(result["statements"].as_array().unwrap().len(), count);
        assert!(!has_issue(&result, "PARSE_ERROR"));
    }
}

#[test]
fn cli_accepts_bare_metadata_guard_and_both_data_source_placements() {
    for sql in [
        "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET)",
        "SELECT src.id FROM OPENROWSET(BULK ('data/a.parquet'), FORMAT = 'PARQUET', DATA_SOURCE = 'demo_storage') WITH (id INT) AS src",
        "SELECT 1 WHERE TRIM = 'demo'",
    ] {
        let result = analyze_mssql(sql);
        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert!(!has_issue(&result, "PARSE_ERROR"));
    }
}

#[test]
fn cli_preserves_nonreserved_keyword_expression_forms() {
    for sql in [
        "SELECT INTERVAL FROM dbo.synthetic_table",
        "SELECT INTERVAL + 1 AS interval_value, INTERVAL implicit_alias FROM dbo.synthetic_table WHERE INTERVAL IS NULL",
        "SELECT TRY_PARSE(INTERVAL AS DATE USING DATE) FROM dbo.synthetic_table",
        "SELECT CAST(INTERVAL AS INT), CONVERT(INT, INTERVAL), TRY_CAST(INTERVAL AS INT), TRY_CONVERT(INT, INTERVAL) FROM dbo.synthetic_table",
    ] {
        let result = analyze_mssql(sql);
        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert_eq!(result["statements"][0]["span"]["end"], sql.len());
        assert!(!has_issue(&result, "PARSE_ERROR"), "{sql}");
    }

    assert!(has_issue(
        &analyze_mssql("SELECT INTERVAL FROM dbo."),
        "PARSE_ERROR"
    ));
}

#[test]
fn cli_accepts_right_nested_mssql_joins_with_deferred_conditions() {
    for join_type in ["INNER", "LEFT", "RIGHT", "FULL"] {
        let sql = format!(
            "SELECT a.id FROM dbo.synthetic_a AS a {join_type} JOIN dbo.synthetic_b AS b INNER JOIN dbo.synthetic_c AS c ON b.id = c.id ON a.id = b.id"
        );
        let result = analyze_mssql(&sql);
        assert!(!has_issue(&result, "PARSE_ERROR"), "{sql}");
        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert_eq!(result["statements"][0]["span"]["end"], sql.len());
        assert_eq!(
            result["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|node| node["type"] == "table")
                .count(),
            3,
        );
    }

    let sql = "SELECT a.id FROM OPENROWSET(BULK('demo/a.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS a LEFT JOIN OPENROWSET(BULK('demo/b.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS b INNER JOIN OPENROWSET(BULK('demo/c.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS c ON b.id = c.id ON a.id = b.id";
    let result = analyze_mssql(sql);
    assert!(!has_issue(&result, "PARSE_ERROR"));
    assert_eq!(result["statements"][0]["span"]["end"], sql.len());
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
    assert!(result["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|node| node["type"] != "table"));

    assert!(has_issue(
        &analyze_mssql("SELECT a.id FROM dbo.synthetic_a AS a LEFT JOIN dbo.synthetic_b AS b INNER JOIN dbo.synthetic_c AS c ON b.id = c.id ON"),
        "PARSE_ERROR",
    ));
}

#[test]
fn cli_accepts_mssql_table_column_trailing_comma_only() {
    for sql in [
        "CREATE TABLE #synthetic_result (demo_value NVARCHAR(MAX),);",
        "CREATE PROCEDURE dbo.synthetic_proc AS BEGIN CREATE TABLE #synthetic_result (demo_value NVARCHAR(MAX),); END;",
    ] {
        let result = analyze_mssql(sql);
        assert!(!has_issue(&result, "PARSE_ERROR"), "{sql}");
        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert_eq!(result["statements"][0]["span"]["end"], sql.len());
    }

    for sql in [
        "CREATE TABLE #synthetic_result (,);",
        "CREATE TABLE #synthetic_result (demo_value INT,,);",
        "CREATE TABLE #synthetic_result (demo_value INT,;",
        "SELECT COALESCE(1,);",
    ] {
        assert!(has_issue(&analyze_mssql(sql), "PARSE_ERROR"), "{sql}");
    }
}

#[test]
fn cli_accepts_bulk_lists_without_horizontal_whitespace() {
    for separator in ["", "\n", "\r\n", "/* list boundary */"] {
        let sql = format!(
            "SELECT src.id FROM OPENROWSET(BULK{separator}('demo/a.parquet', 'demo/b.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS src"
        );
        let result = analyze_mssql(&sql);

        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert_eq!(result["statements"][0]["span"]["end"], sql.len());
        assert!(!has_issue(&result, "PARSE_ERROR"));
        assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
        assert!(result["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|node| node["type"] != "table"));
    }
}

#[test]
fn cli_accepts_openrowset_schemas_in_procedure_bodies() {
    let sql = "CREATE OR ALTER PROCEDURE dbo.synthetic_rows AS BEGIN SELECT src.id FROM OPENROWSET(BULK\n('demo/a.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS src; END";
    let result = analyze_mssql(sql);

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert_eq!(result["statements"][0]["statementType"], "CREATE_PROCEDURE");
    assert_eq!(result["statements"][0]["span"]["end"], sql.len());
    assert!(!has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn cli_accepts_guarded_external_tables_without_lineage() {
    for (condition, begin, end, data_source_first) in [
        ("NOT EXISTS (SELECT 1)", "", "", false),
        ("NOT EXISTS (SELECT 1)", "BEGIN ", "; END", true),
        (
            "OBJECT_ID(N'dbo.synthetic_rows', N'U') IS NULL",
            "",
            "",
            true,
        ),
        (
            "OBJECT_ID('dbo.synthetic_rows') IS NULL",
            "BEGIN ",
            "; END",
            false,
        ),
    ] {
        let options = if data_source_first {
            "DATA_SOURCE = synthetic_store, LOCATION = 'demo/'"
        } else {
            "LOCATION = 'demo/', DATA_SOURCE = synthetic_store"
        };
        let sql = format!(
            "IF {condition} {begin}CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH ({options}, FILE_FORMAT = synthetic_format){end}"
        );
        let result = analyze_mssql(&sql);

        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["statements"][0]["statementType"],
            "CREATE_EXTERNAL_TABLE"
        );
        assert_eq!(result["statements"][0]["span"]["end"], sql.len());
        assert!(!has_issue(&result, "PARSE_ERROR"));
        assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
        assert!(result["nodes"].as_array().unwrap().is_empty());
        assert!(result["edges"].as_array().unwrap().is_empty());
    }
}

#[test]
fn cli_keeps_malformed_rowset_boundaries_and_table_guards_as_errors() {
    for sql in [
        "SELECT * FROM OPENROWSET(BULK\n('demo/a.parquet',), FORMAT = 'PARQUET') AS src",
        "SELECT * FROM OPENROWSET(BULK(), FORMAT = 'PARQUET') AS src",
        "CREATE PROCEDURE dbo.synthetic_rows AS BEGIN SELECT * FROM OPENROWSET(BULK('demo/a.parquet'), FORMAT = 'PARQUET') WITH (id) AS src; END",
        "IF NOT EXISTS (SELECT FROM) CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
        "IF NOT EXISTS (SELECT 1) BEGIN CREATE EXTERNAL TABLE dbo.synthetic_rows (id) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format); END",
        "IF NOT EXISTS (SELECT 1) CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format) ELSE SELECT 1",
        "IF OBJECT_ID() IS NULL CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
        "IF OBJECT_ID('dbo.synthetic_rows') CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
        "CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (DATA_SOURCE = synthetic_store, DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
        "CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (DATA_SOURCE = synthetic_store, LOCATION = '', FILE_FORMAT = synthetic_format)",
    ] {
        assert!(has_issue(&analyze_mssql(sql), "PARSE_ERROR"));
    }
}

#[test]
fn cli_accepts_mssql_collation_and_try_parse_expressions() {
    for sql in [
        "CREATE OR ALTER VIEW dbo.synthetic_view AS SELECT t.demo_value FROM dbo.synthetic_table AS t WHERE t.demo_value COLLATE Latin1_General_100_CI_AS = N'demo'",
        "CREATE OR ALTER VIEW dbo.synthetic_view AS SELECT TRY_PARSE(N'2024-01-02' AS DATETIME USING N'en-US') AS parsed_value",
    ] {
        let result = analyze_mssql(sql);
        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert_eq!(result["statements"][0]["span"]["end"], sql.len());
        assert!(!has_issue(&result, "PARSE_ERROR"));
    }
    for sql in [
        "SELECT t.demo_value COLLATE FROM dbo.synthetic_table AS t",
        "SELECT TRY_PARSE(N'2024-01-02' AS)",
    ] {
        assert!(has_issue(&analyze_mssql(sql), "PARSE_ERROR"));
    }
}

#[test]
fn cli_accepts_optional_terminators_in_procedural_bodies() {
    for sql in [
        "CREATE OR ALTER PROCEDURE dbo.synthetic_proc AS BEGIN DECLARE @value INT SELECT @value = 1 END",
        "BEGIN DECLARE @value INT SELECT @value = 1 END",
    ] {
        let result = analyze_mssql(sql);
        assert_eq!(result["statements"].as_array().unwrap().len(), 1);
        assert_eq!(result["statements"][0]["span"]["end"], sql.len());
        assert!(!has_issue(&result, "PARSE_ERROR"));
    }
    assert!(has_issue(
        &analyze_mssql(
            "CREATE PROCEDURE dbo.synthetic_proc AS BEGIN DECLARE @value SELECT FROM END"
        ),
        "PARSE_ERROR"
    ));
}
