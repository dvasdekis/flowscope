#[cfg(feature = "duckdb")]
use duckdb::Connection;
use flowscope_core::{
    analyze,
    types::{LintConfidence, LintEngine, LintFallbackSource},
    AnalyzeRequest, AnalyzeResult, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit, Span,
    StatementMeta,
};
#[cfg(feature = "duckdb")]
use flowscope_core::{AggregationInfo, FilterClauseType, FilterPredicate, Node, NodeType, Summary};
#[cfg(feature = "duckdb")]
use flowscope_export::export_sql;
use flowscope_export::{export_csv_bundle, export_html, export_json, export_xlsx, ExportNaming};
use flowscope_export::{export_mermaid, MermaidView};
#[cfg(feature = "duckdb")]
use serde_json::json;
#[cfg(feature = "duckdb")]
use std::collections::HashMap;
use std::io::Read;

fn analyze_sample() -> flowscope_core::AnalyzeResult {
    analyze(&AnalyzeRequest {
        sql: "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id".to_string(),
        files: None,
        dialect: Dialect::Postgres,
        source_name: None,
        options: None,
        schema: None,
        #[cfg(feature = "templating")]
        template_config: None,
    })
}

#[test]
fn exports_mermaid_views() {
    let result = analyze_sample();
    let mermaid = export_mermaid(&result, MermaidView::Table).expect("mermaid export");
    assert!(mermaid.contains("flowchart LR"));
    assert!(mermaid.contains("users"));
    assert!(mermaid.contains("orders"));
}

#[test]
fn exports_json_pretty() {
    let result = analyze_sample();
    let json = export_json(&result, false).expect("json export");
    assert!(json.contains("\n"));
    assert!(json.contains("summary"));
}

#[test]
fn exports_html_report() {
    let result = analyze_sample();
    let naming = ExportNaming::new("Test Project");
    let html = export_html(&result, "Test Project", naming.exported_at()).expect("html export");
    assert!(html.contains("<title>Test Project - Lineage Export</title>"));
    assert!(html.contains("mermaid"));
}

#[test]
fn exports_csv_archive() {
    let result = analyze_sample();
    let bytes = export_csv_bundle(&result).expect("csv bundle");

    let reader = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).expect("zip archive");
    let mut file = archive
        .by_name("column_mappings.csv")
        .expect("column mappings file");
    let mut content = String::new();
    file.read_to_string(&mut content).expect("read csv content");
    assert!(content.contains("Source Table"));
    drop(file);

    let mut issues = archive.by_name("issues.csv").expect("issues file");
    let mut issues_content = String::new();
    issues
        .read_to_string(&mut issues_content)
        .expect("read issues content");
    assert!(issues_content.starts_with(
        "Severity,Code,Message,Statement,Span Start,Span End,Source Name,SQLFluff Name,Lint Engine,Lint Confidence,Lint Fallback Source,Autofix Applicability,Autofix Edit Count,Autofix JSON"
    ));
}

#[test]
fn exports_xlsx_bytes() {
    let result = analyze_sample();
    let bytes = export_xlsx(&result).expect("xlsx export");
    assert!(!bytes.is_empty());
}

#[test]
fn exports_issue_metadata_in_html_and_csv() {
    let issue = Issue::warning("LINT_TEST", "<unsafe>, \"message\"\nnext")
        .with_statement(7)
        .with_span(Span::new(11, 16))
        .with_sqlfluff_name("layout.test")
        .with_lint_engine(LintEngine::Lexical)
        .with_lint_confidence(LintConfidence::Medium)
        .with_lint_fallback_source(LintFallbackSource::TokenizerFallback)
        .with_autofix_edits(
            IssueAutofixApplicability::Safe,
            vec![
                IssuePatchEdit::new(Span::new(11, 13), "  "),
                IssuePatchEdit::new(Span::new(14, 16), "=value"),
            ],
        );
    let mut result = AnalyzeResult {
        statements: vec![StatementMeta {
            statement_index: 7,
            statement_type: "SELECT".to_string(),
            source_name: Some("models/orders.sql".to_string()),
            span: Some(Span::new(0, 20)),
            join_count: 0,
            complexity_score: 1,
            resolved_sql: None,
        }],
        issues: vec![issue],
        ..Default::default()
    };
    result.summary.issue_count.warnings = 1;

    let html = export_html(
        &result,
        "Test Project",
        ExportNaming::new("Test Project").exported_at(),
    )
    .expect("html export");
    assert!(html.contains("Source"));
    assert!(html.contains("models/orders.sql"));
    assert!(html.contains("layout.test"));
    assert!(html.contains("&lt;unsafe&gt;"));
    assert!(!html.contains("<unsafe>"));

    let bytes = export_csv_bundle(&result).expect("csv bundle");
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("zip archive");
    let mut file = archive.by_name("issues.csv").expect("issues file");
    let mut content = String::new();
    file.read_to_string(&mut content)
        .expect("read issues content");
    let mut reader = csv::Reader::from_reader(content.as_bytes());
    let headers = reader.headers().expect("csv headers").clone();
    assert_eq!(headers.get(0), Some("Severity"));
    assert_eq!(headers.get(6), Some("Source Name"));
    assert_eq!(headers.get(13), Some("Autofix JSON"));
    let row = reader
        .records()
        .next()
        .expect("issue row")
        .expect("csv row");
    assert_eq!(&row[1], "LINT_TEST");
    assert_eq!(&row[3], "7");
    assert_eq!(&row[6], "models/orders.sql");
    assert_eq!(&row[8], "lexical");
    assert_eq!(&row[9], "medium");
    assert_eq!(&row[10], "tokenizer_fallback");
    assert_eq!(&row[11], "safe");
    assert_eq!(&row[12], "2");
    let autofix: serde_json::Value = serde_json::from_str(&row[13]).expect("autofix JSON");
    assert_eq!(autofix["edits"][1]["replacement"], "=value");
}

/// Multi-statement regression for `representative_join_edge_ids`.
///
/// The same logical `users JOIN orders` appears in two statements, each
/// selecting different columns. Column-level dataflow carries join metadata
/// per selected column, so without representative-edge collapsing the
/// `joins` table would contain one row per column per statement. The
/// representative logic should emit exactly one join row *per statement*
/// (dedup across column-level edges sharing the same relation pair + join
/// metadata) — so with two statements we expect exactly two join rows.
#[cfg(feature = "duckdb")]
#[test]
fn sql_export_dedups_column_level_joins_and_preserves_per_statement_rows() {
    let sql = "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id;\n\
               SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id;";
    let result = analyze(&AnalyzeRequest {
        sql: sql.to_string(),
        files: None,
        dialect: Dialect::Postgres,
        source_name: None,
        options: None,
        schema: None,
        #[cfg(feature = "templating")]
        template_config: None,
    });
    assert_eq!(result.statements.len(), 2, "expected two statements");

    let exported = export_sql(&result, None).expect("sql export");

    let join_rows: Vec<&str> = exported
        .lines()
        .filter(|line| line.contains("INSERT INTO joins"))
        .collect();
    assert_eq!(
        join_rows.len(),
        2,
        "expected one representative join row per statement, got {}:\n{}",
        join_rows.len(),
        join_rows.join("\n")
    );

    // Every representative join row must carry the shared INNER + condition
    // (the column-level dataflow edges all agree on this metadata).
    for row in &join_rows {
        assert!(
            row.contains("'INNER'") && row.contains("u.id = o.user_id"),
            "join row missing expected metadata: {row}"
        );
    }
}

#[cfg(feature = "duckdb")]
#[test]
fn sql_export_preserves_statement_scoped_filters_and_aggregations() {
    let mut table_metadata = HashMap::new();
    table_metadata.insert(
        "statementFilters".to_string(),
        json!({
            "0": [{ "expression": "active = true", "clauseType": "where" }],
            "1": [],
        }),
    );

    let mut column_metadata = HashMap::new();
    column_metadata.insert(
        "statementAggregations".to_string(),
        json!({
            "0": { "isGroupingKey": false, "function": "COUNT" },
            "1": null,
        }),
    );

    let result = AnalyzeResult {
        statements: vec![
            StatementMeta {
                statement_index: 0,
                statement_type: "SELECT".to_string(),
                source_name: Some("models/filtered.sql".to_string()),
                span: Some(Span::new(0, 10)),
                join_count: 0,
                complexity_score: 1,
                resolved_sql: None,
            },
            StatementMeta {
                statement_index: 1,
                statement_type: "SELECT".to_string(),
                source_name: Some("models/plain.sql".to_string()),
                span: Some(Span::new(11, 20)),
                join_count: 0,
                complexity_score: 1,
                resolved_sql: None,
            },
        ],
        nodes: vec![
            Node {
                id: "table_users".into(),
                node_type: NodeType::Table,
                label: "users".into(),
                qualified_name: Some("public.users".into()),
                statement_ids: vec![0, 1],
                filters: vec![FilterPredicate {
                    expression: "active = true".to_string(),
                    clause_type: FilterClauseType::Where,
                }],
                metadata: Some(table_metadata),
                ..Default::default()
            },
            Node {
                id: "column_users_count".into(),
                node_type: NodeType::Column,
                label: "user_count".into(),
                qualified_name: Some("public.users.user_count".into()),
                statement_ids: vec![0, 1],
                aggregation: Some(AggregationInfo {
                    is_grouping_key: false,
                    function: Some("COUNT".to_string()),
                    distinct: None,
                }),
                metadata: Some(column_metadata),
                ..Default::default()
            },
        ],
        edges: vec![],
        issues: vec![],
        summary: Summary {
            statement_count: 2,
            table_count: 1,
            column_count: 1,
            ..Default::default()
        },
        resolved_schema: None,
    };

    let exported = export_sql(&result, None).expect("sql export");
    let conn = Connection::open_in_memory().expect("duckdb connection");
    conn.execute_batch(&exported)
        .expect("generated SQL should execute");

    let filter_rows: Vec<(i64, String)> = conn
        .prepare("SELECT statement_id, predicate FROM filters ORDER BY statement_id, predicate")
        .expect("prepare filter query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query filters")
        .map(|row| row.expect("filter row"))
        .collect();
    assert_eq!(filter_rows, vec![(0, "active = true".to_string())]);

    let aggregation_rows: Vec<(i64, Option<String>)> = conn
        .prepare("SELECT statement_id, function FROM aggregations ORDER BY statement_id, function")
        .expect("prepare aggregation query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query aggregations")
        .map(|row| row.expect("aggregation row"))
        .collect();
    assert_eq!(aggregation_rows, vec![(0, Some("COUNT".to_string()))]);
}

#[cfg(feature = "duckdb")]
#[test]
fn sql_export_reindexes_statement_references_and_preserves_occurrence_spans() {
    let mut column_metadata = HashMap::new();
    column_metadata.insert(
        "occurrenceSpans".to_string(),
        json!([
            { "start": 1, "end": 2 },
            { "start": 10, "end": 12 }
        ]),
    );
    column_metadata.insert("occurrenceStatementIds".to_string(), json!([7, 7]));

    let result = AnalyzeResult {
        statements: vec![StatementMeta {
            statement_index: 7,
            statement_type: "SELECT".to_string(),
            source_name: Some("models/scoped.sql".to_string()),
            span: Some(Span::new(0, 20)),
            join_count: 0,
            complexity_score: 1,
            resolved_sql: None,
        }],
        nodes: vec![
            Node {
                id: "table_src".into(),
                node_type: NodeType::Table,
                label: "src".into(),
                qualified_name: Some("public.src".into()),
                statement_ids: vec![7],
                ..Default::default()
            },
            Node {
                id: "table_dst".into(),
                node_type: NodeType::Table,
                label: "dst".into(),
                qualified_name: Some("public.dst".into()),
                statement_ids: vec![7],
                ..Default::default()
            },
            Node {
                id: "column_shared".into(),
                node_type: NodeType::Column,
                label: "id".into(),
                qualified_name: Some("public.src.id".into()),
                statement_ids: vec![7],
                metadata: Some(column_metadata),
                ..Default::default()
            },
        ],
        edges: vec![flowscope_core::Edge {
            id: "edge_stmt_7".into(),
            from: "table_src".into(),
            to: "table_dst".into(),
            edge_type: flowscope_core::EdgeType::DataFlow,
            expression: None,
            operation: None,
            join_type: None,
            join_condition: None,
            metadata: None,
            approximate: None,
            statement_ids: vec![7],
        }],
        issues: vec![Issue::warning("TEST_001", "scoped issue").with_statement(7)],
        summary: Summary {
            statement_count: 1,
            table_count: 2,
            column_count: 1,
            join_count: 0,
            complexity_score: 1,
            issue_count: flowscope_core::IssueCount {
                errors: 0,
                warnings: 1,
                infos: 0,
            },
            has_errors: false,
        },
        resolved_schema: None,
    };

    let exported = export_sql(&result, None).expect("sql export");
    let conn = Connection::open_in_memory().expect("duckdb connection");
    conn.execute_batch(&exported)
        .expect("generated SQL should execute for non-zero statement indices");

    let node_statement_ids: Vec<i64> = conn
        .prepare("SELECT statement_id FROM node_statements ORDER BY node_id")
        .expect("prepare node statement query")
        .query_map([], |row| row.get(0))
        .expect("query node statements")
        .map(|row| row.expect("node statement row"))
        .collect();
    assert_eq!(node_statement_ids, vec![0, 0, 0]);

    let edge_statement_ids: Vec<i64> = conn
        .prepare("SELECT statement_id FROM edge_statements")
        .expect("prepare edge statement query")
        .query_map([], |row| row.get(0))
        .expect("query edge statements")
        .map(|row| row.expect("edge statement row"))
        .collect();
    assert_eq!(edge_statement_ids, vec![0]);

    let issue_statement_ids: Vec<i64> = conn
        .prepare("SELECT statement_id FROM issues")
        .expect("prepare issue query")
        .query_map([], |row| row.get(0))
        .expect("query issues")
        .map(|row| row.expect("issue row"))
        .collect();
    assert_eq!(issue_statement_ids, vec![0]);

    let occurrence_spans: Vec<(i64, i64)> = conn
        .prepare(
            "SELECT span_start, span_end FROM node_name_spans WHERE node_id = 'column_shared' ORDER BY span_start, span_end",
        )
        .expect("prepare name spans query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query name spans")
        .map(|row| row.expect("name span row"))
        .collect();
    assert_eq!(occurrence_spans, vec![(1, 2), (10, 12)]);
}
