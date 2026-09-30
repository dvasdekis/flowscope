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
