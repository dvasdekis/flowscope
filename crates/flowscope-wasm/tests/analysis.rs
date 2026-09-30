use flowscope_wasm::{analyze_sql_json, split_statements_json};
use serde_json::Value;

fn analyze_mssql(sql: &str) -> Value {
    let request = serde_json::json!({
        "sql": sql,
        "dialect": "mssql"
    });

    serde_json::from_str(&analyze_sql_json(&request.to_string()))
        .expect("analysis result should be valid JSON")
}

fn has_issue(result: &Value, code: &str) -> bool {
    result["issues"]
        .as_array()
        .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code))
}

fn has_warning(result: &Value, code: &str) -> bool {
    result["issues"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == code && issue["severity"] == "warning")
    })
}

#[test]
fn analyze_sql_json_handles_mssql_go_batch_separators() {
    let result = analyze_mssql("SELECT 1;\nGO 2\nSELECT 2;\nGO\n");
    let statements = result
        .get("statements")
        .and_then(Value::as_array)
        .expect("analysis result should contain statements");
    let issues = result
        .get("issues")
        .and_then(Value::as_array)
        .expect("analysis result should contain issues");

    assert_eq!(statements.len(), 3);
    assert_eq!(result["summary"]["statementCount"], 3);
    assert_eq!(statements[0]["span"]["start"], 0);
    assert_eq!(statements[0]["span"]["end"], 8);
    assert_eq!(statements[0]["span"], statements[1]["span"]);
    assert_eq!(statements[2]["span"]["start"], 15);
    assert_eq!(statements[2]["span"]["end"], 23);
    assert!(!issues.iter().any(|issue| issue["code"] == "PARSE_ERROR"));
}

#[test]
fn split_statements_json_handles_mssql_go_batch_separators() {
    let sql = "SELECT 1;\nGO\nSELECT 2;\nGO\n";
    let request = serde_json::json!({
        "sql": sql,
        "dialect": "mssql"
    });

    let result: Value = serde_json::from_str(&split_statements_json(&request.to_string()))
        .expect("statement split result should be valid JSON");
    let statements = result
        .get("statements")
        .and_then(Value::as_array)
        .expect("statement split result should contain statements");

    assert_eq!(statements.len(), 2);
    assert_eq!(statements[0]["start"], 0);
    assert_eq!(statements[0]["end"], 8);
    assert_eq!(statements[1]["start"], 13);
    assert_eq!(statements[1]["end"], 21);
}

#[test]
fn split_statements_json_preserves_ranges_for_repeated_mssql_batches() {
    let sql = "SELECT 1;\nGO 2\nSELECT 2;\nGO\n";
    let request = serde_json::json!({ "sql": sql, "dialect": "mssql" });

    let result: Value = serde_json::from_str(&split_statements_json(&request.to_string()))
        .expect("statement split result should be valid JSON");
    assert!(result["error"].is_null());
    let statements = result["statements"]
        .as_array()
        .expect("statement split result should contain statements");

    assert_eq!(statements.len(), 3);
    assert_eq!(statements[0]["start"], statements[1]["start"]);
    assert_eq!(statements[0]["end"], statements[1]["end"]);
    assert_eq!(statements[0]["start"], 0);
    assert_eq!(statements[0]["end"], 8);
    assert_eq!(statements[2]["start"], 15);
    assert_eq!(statements[2]["end"], 23);
}

#[test]
fn analyze_sql_json_accepts_synapse_openrowset_bulk_source() {
    let result = analyze_mssql(
        "SELECT file.id FROM OPENROWSET(BULK ('https://storage.example/data/a.parquet', 'https://storage.example/data/b.parquet'), FORMAT = 'PARQUET') WITH (id BIGINT) AS file",
    );
    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert!(!has_issue(&result, "PARSE_ERROR"));
    assert!(result["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|node| node["type"] != "table"));
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
}

#[test]
fn analyze_sql_json_rejects_a_trailing_comma_in_bulk_file_lists() {
    let result = analyze_mssql(
        "SELECT * FROM OPENROWSET(BULK ('data/a.parquet',), FORMAT = 'PARQUET') AS file",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn analyze_sql_json_keeps_malformed_synapse_openrowset_as_a_parse_error() {
    let result = analyze_mssql("SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'TEXT') AS file");

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn analyze_sql_json_classifies_external_file_format_without_lineage() {
    let result = analyze_mssql(
        "/* synthetic metadata */ CREATE EXTERNAL FILE FORMAT [synthetic_csv] WITH (FORMAT_TYPE = DELIMITEDTEXT, FORMAT_OPTIONS (FIELD_TERMINATOR = ',', FIRST_ROW = 2))",
    );
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
fn analyze_sql_json_keeps_unsupported_external_file_format_options_as_parse_errors() {
    let result = analyze_mssql(
        "CREATE EXTERNAL FILE FORMAT synthetic_parquet WITH (FORMAT_TYPE = PARQUET, FORMAT_OPTIONS (FIELD_TERMINATOR = ','))",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn analyze_sql_json_accepts_unparenthesized_synapse_procedure_parameters() {
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
fn analyze_sql_json_keeps_malformed_synapse_procedure_parameters_as_parse_errors() {
    let result = analyze_mssql("CREATE OR ALTER PROC dbo.copy_rows @source_id INT, AS SELECT 1;");

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn analyze_sql_json_accepts_cetas_without_inventing_external_lineage() {
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
fn analyze_sql_json_rejects_cetas_with_a_malformed_select() {
    let result = analyze_mssql(
        "CREATE EXTERNAL TABLE dbo.export_rows WITH (LOCATION = 'export/', DATA_SOURCE = storage_source, FILE_FORMAT = parquet_format) AS SELECT FROM",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn analyze_sql_json_rejects_typed_cetas_output_columns() {
    let result = analyze_mssql(
        "CREATE EXTERNAL TABLE dbo.export_rows (export_id INT) WITH (LOCATION = 'export/', DATA_SOURCE = storage_source, FILE_FORMAT = parquet_format) AS SELECT id FROM dbo.source_rows",
    );

    assert!(has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn analyze_sql_json_accepts_inline_tvf_cte_without_outer_parentheses() {
    let sql = "CREATE FUNCTION dbo.demo_rows() RETURNS TABLE AS RETURN WITH demo_cte AS (SELECT 1 AS demo_value) SELECT demo_value FROM demo_cte";
    let result = analyze_mssql(sql);

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert_eq!(result["statements"][0]["span"]["start"], 0);
    assert_eq!(result["statements"][0]["span"]["end"], sql.len());
    assert!(!has_issue(&result, "PARSE_ERROR"));
}

#[test]
fn analyze_sql_json_accepts_external_table_metadata_without_lineage() {
    let result = analyze_mssql(
        "CREATE EXTERNAL TABLE dbo.demo_rows (id INT, label VARCHAR(20)) WITH (LOCATION = 'data/', DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet)",
    );

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert!(!has_issue(&result, "PARSE_ERROR"));
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
    assert!(result["nodes"].as_array().unwrap().is_empty());
    assert!(result["edges"].as_array().unwrap().is_empty());
}

#[test]
fn analyze_sql_json_accepts_guarded_file_format_metadata() {
    let result = analyze_mssql(
        "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); END",
    );

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert!(!has_issue(&result, "PARSE_ERROR"));
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
    assert!(result["nodes"].as_array().unwrap().is_empty());
    assert!(result["edges"].as_array().unwrap().is_empty());
}

#[test]
fn analyze_sql_json_accepts_openrowset_column_collation() {
    let result = analyze_mssql(
        "SELECT src.label FROM OPENROWSET(BULK ('data/a.csv'), FORMAT = 'CSV') WITH (label VARCHAR(20) COLLATE Latin1_General_100_BIN2_UTF8) AS src",
    );

    assert_eq!(result["statements"].as_array().unwrap().len(), 1);
    assert!(!has_issue(&result, "PARSE_ERROR"));
    assert!(has_warning(&result, "UNSUPPORTED_SYNTAX"));
}

#[test]
fn analyze_sql_json_accepts_semicolon_optional_batch_boundaries() {
    let result = analyze_mssql("SELECT 1\nSET NOCOUNT ON");

    assert_eq!(result["statements"].as_array().unwrap().len(), 2);
    assert!(!has_issue(&result, "PARSE_ERROR"));
}
