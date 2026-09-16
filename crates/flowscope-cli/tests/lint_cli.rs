use std::process::Command;

use tempfile::tempdir;

/// SQL that triggers LINT_AM_002 (bare UNION) without LT011 layout noise.
const SQL_WITH_VIOLATIONS: &str = "SELECT 1 AS c\nUNION\nSELECT 2 AS c\n";

/// Clean SQL with no lint violations.
const SQL_CLEAN: &str = "SELECT 1\n";
/// Invalid SQL used to verify parser/analysis errors fail lint mode.
const SQL_INVALID: &str = "SELECT FROM";
/// Templated SQL used to verify lint-mode Jinja fallback without explicit --template.
const SQL_TEMPLATED_ST05: &str = r#"SELECT
    a_table.id,
    b_table.id
FROM a_table
INNER JOIN (
    SELECT
        id,
        {{"mrgn"}} AS margin
    FROM b_tbl
) AS b_table ON a_table.some_column = b_table.some_column"#;
/// Representative SQL with comments and one deterministic safe fix candidate.
const SQL_COMMENTED_SAFE_FIX: &str =
    "-- keep:lead\nSELECT COUNT(1) AS row_count /* keep:mid */\nFROM t -- keep:tail\n";
/// Representative query used to validate safe-vs-unsafe fix behavior.
const SQL_UNSAFE_FIX_REPRESENTATIVE: &str =
    "SELECT t.id\nFROM t\nINNER JOIN (\n    SELECT id\n    FROM u\n) AS u2 ON t.id = u2.id\n";

fn run_flowscope(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(args)
        .output()
        .expect("run CLI")
}

fn combined_output(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{stdout}\n{stderr}")
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let lowercase = haystack.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| lowercase.contains(&needle.to_ascii_lowercase()))
}

fn assert_flag_was_accepted(output: &std::process::Output, flag: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected {flag} to be accepted by the CLI, got clap parse failure: {stderr}"
    );
    assert!(
        !stderr.contains("unexpected argument"),
        "Expected {flag} to be accepted, but CLI reported an unexpected argument: {stderr}"
    );
}

fn lint_violation_codes(sql_path: &std::path::Path) -> Vec<String> {
    let output = run_flowscope(&[
        "--lint",
        "--format",
        "json",
        sql_path.to_str().expect("sql path"),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("Expected valid lint JSON output, got error: {err}; stdout: {stdout}")
    });
    let files = parsed.as_array().expect("Expected top-level JSON array");
    assert_eq!(files.len(), 1, "Expected exactly one file result: {stdout}");
    files[0]["violations"]
        .as_array()
        .expect("Expected violations array")
        .iter()
        .map(|violation| {
            violation["code"]
                .as_str()
                .unwrap_or("<unknown>")
                .to_string()
        })
        .collect()
}

#[test]
fn test_lint_clean_file() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("clean.sql");
    std::fs::write(&sql_path, SQL_CLEAN).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "Expected exit 0, got: {stdout}");
    assert!(stdout.contains("PASS"), "Expected PASS in output: {stdout}");
    assert!(
        stdout.contains("0 violations"),
        "Expected 0 violations: {stdout}"
    );
}

#[test]
fn test_lint_file_with_violations() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("bad.sql");
    std::fs::write(&sql_path, SQL_WITH_VIOLATIONS).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1, got: {stdout}"
    );
    assert!(stdout.contains("FAIL"), "Expected FAIL in output: {stdout}");
    assert!(stdout.contains("AM02"), "Expected AM02: {stdout}");
    assert!(
        stdout.contains("1 violations"),
        "Expected 1 violation: {stdout}"
    );
}

#[test]
fn test_lint_invalid_sql_fails() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("invalid.sql");
    std::fs::write(&sql_path, SQL_INVALID).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1 for invalid SQL, got: {stdout}"
    );
    assert!(stdout.contains("FAIL"), "Expected FAIL in output: {stdout}");
    assert!(
        stdout.contains("1 file failed"),
        "Expected failed summary for invalid SQL: {stdout}"
    );
}

#[test]
fn test_lint_exclude_rules() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("excluded.sql");
    std::fs::write(&sql_path, SQL_WITH_VIOLATIONS).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--exclude-rules",
            "LINT_AM_002",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Expected exit 0 when rule excluded, got: {stdout}"
    );
    assert!(
        stdout.contains("PASS"),
        "Expected PASS when rule excluded: {stdout}"
    );
}

#[test]
fn test_lint_fix_respects_exclude_rules() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("excluded_fix.sql");
    std::fs::write(&sql_path, SQL_WITH_VIOLATIONS).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_AM_002",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Expected exit 0 when excluded rule is the only violation, got: {stdout}"
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, SQL_WITH_VIOLATIONS,
        "Expected file to remain unchanged when fix rule is excluded"
    );
}

#[test]
fn test_lint_fix_excluded_rule_not_rewritten_when_other_fixes_apply() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("excluded_mixed_fix.sql");
    let sql = "SELECT COUNT(1) FROM t WHERE a<>b";
    std::fs::write(&sql_path, sql).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_CV_001",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1 due remaining non-excluded violations"
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.to_ascii_uppercase().contains("COUNT(*)"),
        "Expected non-excluded fix to apply: {after}"
    );
    assert!(
        after.contains("<>"),
        "Expected excluded CV_005 to remain '<>' (not '!='): {after}"
    );
    assert!(
        !after.contains("!="),
        "Expected excluded CV_005 to avoid not-equal rewrite: {after}"
    );
}

#[test]
fn test_lint_output_file_has_no_ansi_sequences() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("bad.sql");
    let report_path = dir.path().join("lint.txt");
    std::fs::write(&sql_path, SQL_WITH_VIOLATIONS).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--output",
            report_path.to_str().expect("report path"),
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1 for violations"
    );

    let report = std::fs::read_to_string(report_path).expect("read lint report");
    assert!(
        !report.contains('\u{1b}'),
        "Expected no ANSI escape sequences in output file: {report}"
    );
}

#[test]
fn test_lint_json_format() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("json.sql");
    std::fs::write(&sql_path, SQL_WITH_VIOLATIONS).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--format",
            "json",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1 for violations: {stdout}"
    );

    // Validate it's valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Expected valid JSON output");
    let arr = parsed.as_array().expect("Expected JSON array");
    assert_eq!(arr.len(), 1);
    assert!(!arr[0]["violations"].as_array().unwrap().is_empty());

    let violation = &arr[0]["violations"][0];
    assert_eq!(violation["sourceName"], sql_path.to_string_lossy().as_ref());
    assert_eq!(violation["statementIndex"], 0);
    assert!(violation["span"]["start"].is_number());
    assert!(violation["span"]["end"].is_number());
    assert_eq!(violation["sqlfluffName"], "ambiguous.union");
    assert_eq!(violation["lintEngine"], "semantic");
    assert_eq!(violation["lintConfidence"], "high");
    assert_eq!(violation["autofix"]["applicability"], "safe");
    assert!(violation["autofix"]["edits"].is_array());
}

#[test]
fn test_lint_unsupported_format() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("test.sql");
    std::fs::write(&sql_path, SQL_CLEAN).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--format",
            "html",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    assert_eq!(
        output.status.code(),
        Some(66),
        "Expected exit 66 for unsupported format"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only supports"),
        "Expected helpful error message: {stderr}"
    );
}

#[test]
fn test_lint_unsupported_format_fails_before_fix_mutation() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("test.sql");
    std::fs::write(&sql_path, SQL_WITH_VIOLATIONS).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--format",
            "html",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    assert_eq!(
        output.status.code(),
        Some(66),
        "Expected exit 66 for unsupported lint format"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only supports"),
        "Expected helpful error message: {stderr}"
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after failed command");
    assert_eq!(
        after, SQL_WITH_VIOLATIONS,
        "Expected file to remain unchanged for unsupported format"
    );
}

#[test]
fn test_lint_stdin() {
    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(SQL_WITH_VIOLATIONS.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1 for stdin violations: {stdout}"
    );
    assert!(
        stdout.contains("AM02"),
        "Expected AM02 from stdin: {stdout}"
    );
}

#[test]
fn test_lint_fix_only_skips_post_fix_lint_for_file_inputs() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("fix_only.sql");
    std::fs::write(&sql_path, SQL_WITH_VIOLATIONS).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--fix-only",
            "--format",
            "html",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI");

    assert!(
        output.status.success(),
        "Expected --fix-only to complete successfully"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("phase 2/2 linting post-fix inputs"),
        "Expected --fix-only to skip post-fix lint phase: {stderr}"
    );
    assert!(
        stderr.contains("phase timing: fix="),
        "Expected --fix-only timing output to include fix phase: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "Expected no lint report output for file-based --fix-only run"
    );

    let fixed_sql = std::fs::read_to_string(&sql_path).expect("read fixed sql");
    assert!(
        fixed_sql.contains("DISTINCT"),
        "Expected --fix-only to apply file fixes in place: {fixed_sql}"
    );
}

#[test]
fn test_lint_fix_only_emits_fixed_sql_for_stdin() {
    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", "--fix-only"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(SQL_WITH_VIOLATIONS.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("run CLI");

    assert!(
        output.status.success(),
        "Expected --fix-only stdin run to succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DISTINCT"),
        "Expected --fix-only stdin output to contain fixed SQL: {stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("phase 2/2 linting post-fix inputs"),
        "Expected --fix-only to skip post-fix lint phase: {stderr}"
    );
}

#[test]
fn test_lint_templated_sql_without_template_flag_uses_jinja_fallback() {
    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--format", "json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(SQL_TEMPLATED_ST05.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("run CLI");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected violations in fallback lint"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Expected valid JSON output");
    let violations = parsed[0]["violations"]
        .as_array()
        .expect("violations array");

    let has_st05 = violations
        .iter()
        .any(|v| v["code"].as_str() == Some("ST05"));
    let has_parse_error = violations
        .iter()
        .any(|v| v["code"].as_str() == Some("PARSE_ERROR"));

    assert!(
        has_st05,
        "Expected ST05 violation in templated fallback: {stdout}"
    );
    assert!(
        !has_parse_error,
        "Did not expect PARSE_ERROR after Jinja fallback: {stdout}"
    );
}

#[test]
fn test_lint_rule_configs_flag_applies_rule_options() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("subquery.sql");
    std::fs::write(&sql_path, "SELECT * FROM (SELECT * FROM t) sub\n").expect("write sql");

    let no_cfg = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--format",
            "json",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI without rule configs");

    let no_cfg_stdout = String::from_utf8_lossy(&no_cfg.stdout);
    let no_cfg_json: serde_json::Value =
        serde_json::from_str(&no_cfg_stdout).expect("valid json without rule configs");
    let no_cfg_has_st05 = no_cfg_json[0]["violations"]
        .as_array()
        .expect("violations array")
        .iter()
        .any(|v| v["code"].as_str() == Some("ST05"));
    assert!(
        !no_cfg_has_st05,
        "Expected default ST05 config (join) to ignore FROM subquery: {no_cfg_stdout}"
    );

    let with_cfg = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--format",
            "json",
            "--rule-configs",
            r#"{"structure.subquery":{"forbid_subquery_in":"from"}}"#,
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with rule configs");

    let with_cfg_stdout = String::from_utf8_lossy(&with_cfg.stdout);
    let with_cfg_json: serde_json::Value =
        serde_json::from_str(&with_cfg_stdout).expect("valid json with rule configs");
    let with_cfg_has_st05 = with_cfg_json[0]["violations"]
        .as_array()
        .expect("violations array")
        .iter()
        .any(|v| v["code"].as_str() == Some("ST05"));
    assert!(
        with_cfg_has_st05,
        "Expected ST05 with forbid_subquery_in=from: {with_cfg_stdout}"
    );
}

#[test]
fn test_lint_fix_rule_configs_enable_cv006_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("missing_final_semicolon.sql");
    std::fs::write(&sql_path, "SELECT 1").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--rule-configs",
            r#"{"convention.terminator":{"require_final_semicolon":true}}"#,
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix + rule configs");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.trim_end().ends_with(';'),
        "Expected CV06 core autofix to append a final semicolon in patch mode: {after}"
    );
}

#[test]
fn test_lint_fix_applies_cv006_spacing_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("terminator_spacing_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a FROM foo  ;").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a FROM foo;",
        "Expected CV06 core autofix to remove whitespace before statement terminator"
    );
}

#[test]
fn test_lint_fix_applies_cv002_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("coalesce_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT IFNULL(foo, 0) FROM t").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.to_ascii_uppercase().contains("COALESCE"),
        "Expected CV02 core autofix to rewrite IFNULL to COALESCE in patch mode: {after}"
    );
}

#[test]
fn test_lint_fix_applies_cv001_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("not_equal_style_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT * FROM t WHERE a <> b AND c != d").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    let compact: String = after.chars().filter(|ch| !ch.is_whitespace()).collect();
    let has_c_style = compact.contains("a!=b") && compact.contains("c!=d");
    let has_ansi_style = compact.contains("a<>b") && compact.contains("c<>d");
    assert!(
        has_c_style || has_ansi_style,
        "Expected CV01 core autofix to normalize not-equal operators to one style: {after}"
    );
}

#[test]
fn test_lint_fix_applies_cv005_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("null_comparison_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT * FROM t WHERE a = NULL AND b <> NULL").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.contains("a IS NULL"),
        "Expected CV05 core autofix to rewrite '= NULL' to 'IS NULL': {after}"
    );
    assert!(
        after.contains("b IS NOT NULL"),
        "Expected CV05 core autofix to rewrite '<> NULL' to 'IS NOT NULL': {after}"
    );
}

#[test]
fn test_lint_fix_applies_cv007_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("statement_brackets_patch_fix.sql");
    std::fs::write(&sql_path, "(SELECT 1)").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1\n",
        "Expected CV07 core autofix to remove outer wrapper brackets in patch mode"
    );
}

#[test]
fn test_lint_fix_applies_lt006_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("function_spacing_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT COUNT (1) FROM t").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.contains("COUNT("),
        "Expected LT06 core autofix to keep function call parenthesis tight: {after}"
    );
    assert!(
        !after.contains("COUNT ("),
        "Expected LT06 core autofix to remove spacing before function parenthesis: {after}"
    );
}

#[test]
fn test_lint_fix_applies_lt005_core_autofix_in_patch_mode_with_config() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("long_line_patch_fix.sql");
    let sql = format!("SELECT {} FROM t\n", vec!["column_name"; 60].join(" "));
    std::fs::write(&sql_path, sql).expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--rule-configs",
            r#"{"layout.long_lines":{"max_line_length":300}}"#,
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.lines().all(|line| line.len() <= 300),
        "Expected LT005 core autofix output lines to stay under configured threshold: {after:?}"
    );
    assert!(
        after.lines().count() > 1,
        "Expected LT005 core autofix to split an extremely long line: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_al005_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("unused_table_alias_patch_fix.sql");
    std::fs::write(
        &sql_path,
        "SELECT users.name FROM users AS u JOIN orders AS o ON users.id = orders.user_id\n",
    )
    .expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_AM_005",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT users.name FROM users JOIN orders ON users.id = orders.user_id\n",
        "Expected AL005 core autofix to remove unused table aliases: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_al001_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("aliasing_table_style_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT u.id FROM users u\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT u.id FROM users AS u\n",
        "Expected AL001 core autofix to insert explicit AS for table aliases: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_al009_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("self_alias_column_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a AS a FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a FROM t\n",
        "Expected AL009 core autofix to remove self-aliasing projection alias: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_st001_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("else_null_patch_fix.sql");
    std::fs::write(
        &sql_path,
        "SELECT CASE WHEN x > 1 THEN 'a' ELSE NULL END FROM t\n",
    )
    .expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT CASE WHEN x > 1 THEN 'a' END FROM t\n",
        "Expected ST001 core autofix to remove redundant ELSE NULL branch: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_am001_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("distinct_group_by_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT DISTINCT a FROM t GROUP BY a\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_LT_014",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a FROM t GROUP BY a\n",
        "Expected AM001 core autofix to remove DISTINCT when GROUP BY is present: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_am002_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("bare_union_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 1 UNION SELECT 2\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_LT_011",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1 UNION DISTINCT SELECT 2\n",
        "Expected AM002 core autofix to expand bare UNION to explicit UNION DISTINCT: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_am003_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("ambiguous_order_by_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT * FROM t ORDER BY a DESC, b NULLS LAST\n")
        .expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_LT_014",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT * FROM t ORDER BY a DESC, b ASC NULLS LAST\n",
        "Expected AM003 core autofix to add ASC to implicit ORDER BY terms in mixed clauses: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_am005_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("ambiguous_join_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a FROM t JOIN u ON t.id = u.id\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a FROM t INNER JOIN u ON t.id = u.id\n",
        "Expected AM005 core autofix to qualify bare JOIN with INNER: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_am008_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("ambiguous_join_condition_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT foo.a, bar.b FROM foo INNER JOIN bar\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT\n    foo.a,\n    bar.b\nFROM foo CROSS JOIN bar\n",
        "Expected AM008 core autofix to rewrite conditionless INNER JOIN to CROSS JOIN: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_st006_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("structure_column_order_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a + 1, a FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT\n    a,\n    a + 1\nFROM t\n",
        "Expected ST006 core autofix to reorder simple projection targets ahead of complex expressions: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_st009_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir
        .path()
        .join("structure_join_condition_order_patch_fix.sql");
    std::fs::write(
        &sql_path,
        "SELECT foo.a, bar.b FROM foo LEFT JOIN bar ON bar.a = foo.a\n",
    )
    .expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT\n    foo.a,\n    bar.b\nFROM foo LEFT JOIN bar ON foo.a = bar.a\n",
        "Expected ST009 core autofix to reorder join predicate source sides: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_st002_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("structure_simple_case_patch_fix.sql");
    std::fs::write(
        &sql_path,
        "SELECT CASE WHEN x > 0 THEN true ELSE false END FROM t\n",
    )
    .expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT coalesce(x > 0, false) FROM t\n",
        "Expected ST002 core autofix to rewrite unnecessary CASE to coalesce: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_st008_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("distinct_parenthesized_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT DISTINCT(a) FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT DISTINCT a FROM t\n",
        "Expected ST008 core autofix to remove DISTINCT parentheses: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt004_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("comma_spacing_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a,b FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        !after.contains("a,b"),
        "Expected LT004 core autofix to enforce spacing after comma: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt003_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("operator_layout_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a +\n b FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a\n    + b FROM t\n",
        "Expected LT003 core autofix to move trailing operator to leading style: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt001_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("layout_spacing_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT payload->>'id' FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT payload ->> 'id' FROM t\n",
        "Expected LT001 core autofix to normalize json arrow spacing: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt002_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("layout_indent_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 1\n   -- comment\nFROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1\n   -- comment\nFROM t\n",
        "Expected LT002 core autofix to normalize comment-line indentation: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_tq003_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("tsql_empty_batch_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 1\nGO\nGO\nSELECT 2\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--dialect",
            "mssql",
            "--lint",
            "--fix",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1\nGO\nSELECT 2\n",
        "Expected TQ003 core autofix to collapse redundant GO batch separators: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_tq002_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("tsql_procedure_begin_end_patch_fix.sql");
    std::fs::write(&sql_path, "CREATE PROCEDURE p AS SELECT 1; SELECT 2;\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--dialect",
            "mssql",
            "--lint",
            "--fix",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.to_ascii_uppercase().contains(" AS BEGIN "),
        "Expected TQ002 core autofix to insert BEGIN: {after:?}"
    );
    assert!(
        after.to_ascii_uppercase().contains(" END"),
        "Expected TQ002 core autofix to insert END: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_st005_core_autofix_in_unsafe_mode_with_from_config() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("st005_from_subquery_core_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT * FROM (SELECT 1) sub\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--unsafe-fixes",
            "--rule-configs",
            r#"{"structure.subquery":{"forbid_subquery_in":"from"}}"#,
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with unsafe fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "WITH sub AS (SELECT 1)\n\nSELECT * FROM sub\n",
        "Expected unsafe ST005 core autofix to rewrite FROM subquery to CTE: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_cp001_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("keyword_capitalisation_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a from t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a FROM t\n",
        "Expected CP001 core autofix to normalize keyword capitalisation: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_cp003_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("function_capitalisation_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT COUNT(*), sum(a) FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT\n    COUNT(*),\n    SUM(a)\nFROM t\n",
        "Expected CP003 core autofix to normalize function capitalisation: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_cp002_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("identifier_capitalisation_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT Col, col FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    // Col refutes lower/upper, leaving capitalise. col then violates capitalise.
    // Consistent policy resolves to capitalise, fixing all identifiers.
    assert_eq!(
        after, "SELECT\n    Col,\n    Col\nFROM T\n",
        "Expected CP002 core autofix to normalize identifier capitalisation: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_cp004_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("literal_capitalisation_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT NULL, true FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT\n    NULL,\n    TRUE\nFROM t\n",
        "Expected CP004 core autofix to normalize literal capitalisation: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_cp005_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("type_capitalisation_patch_fix.sql");
    std::fs::write(&sql_path, "CREATE TABLE t (a INT, b varchar(10))\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "CREATE TABLE t (a INT, b VARCHAR(10))\n",
        "Expected CP005 core autofix to normalize type capitalisation: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_cv010_core_autofix_in_patch_mode() {
    // CV10 only fires in dialects where both quote styles are string literals.
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("quoted_literal_style_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 'abc', \"def\"\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--unsafe-fixes",
            "--dialect",
            "bigquery",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    // In consistent mode, first literal is single-quoted so double-quoted
    // literals should be converted to single-quoted.
    assert!(
        !after.contains("\"def\""),
        "Expected CV010 core autofix to convert double-quoted string to single-quoted: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_rf004_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("references_keywords_patch_fix.sql");
    std::fs::write(&sql_path, "select a from users as select\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "select a from users\n",
        "Expected RF004 core autofix to rewrite keyword table alias safely: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_rf003_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("references_consistent_patch_fix.sql");
    std::fs::write(&sql_path, "select a.id, id2 from a\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "select\n    a.id,\n    a.id2\nfrom a\n",
        "Expected RF003 core autofix to qualify unqualified references consistently: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_rf006_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("references_quoting_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT \"good_name\" FROM t\n").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT good_name FROM t\n",
        "Expected RF006 core autofix to unquote safe identifiers: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_cv003_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("select_trailing_comma_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a, FROM t").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a FROM t\n",
        "Expected CV003 core autofix to remove trailing comma in patch mode"
    );
}

#[test]
fn test_lint_fix_rule_configs_enable_cv003_require_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir
        .path()
        .join("select_trailing_comma_require_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a FROM t").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--rule-configs",
            r#"{"convention.select_trailing_comma":{"select_clause_trailing_comma":"require"}}"#,
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix + rule configs");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT a, FROM t\n",
        "Expected CV003 require-mode core autofix to insert trailing comma before FROM"
    );
}

#[test]
fn test_lint_fix_applies_st012_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("consecutive_semicolons_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 1;;").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1;",
        "Expected ST012 core autofix to collapse consecutive semicolons"
    );
}

#[test]
fn test_lint_fix_applies_lt012_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("single_trailing_newline_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 1\nFROM t").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1\nFROM t\n",
        "Expected LT012 core autofix to enforce exactly one trailing newline"
    );
}

#[test]
fn test_lint_fix_applies_lt013_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("leading_blank_lines_patch_fix.sql");
    std::fs::write(&sql_path, "\n\nSELECT 1").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.starts_with("SELECT 1"),
        "Expected LT013 core autofix to remove leading blank lines: {after:?}"
    );
    assert!(
        !after.starts_with('\n'),
        "Expected LT013 core autofix output to start with SQL text: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt014_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("keyword_newline_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT a FROM t\nWHERE a = 1").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert!(
        after.contains("\nFROM t"),
        "Expected LT014 core autofix to line-break major clause keyword: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt010_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("select_modifier_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT\nDISTINCT a\nFROM t").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT DISTINCT a\nFROM t\n",
        "Expected LT010 core autofix to place DISTINCT on SELECT line: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt011_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("set_operator_layout_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 1 UNION SELECT 2\nUNION SELECT 3").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_AM_002",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1\nUNION\nSELECT 2\nUNION\nSELECT 3\n",
        "Expected LT011 core autofix to put set operators on their own line: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt007_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("cte_bracket_patch_fix.sql");
    std::fs::write(&sql_path, "WITH cte AS (\n  SELECT 1)\nSELECT * FROM cte").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "WITH cte AS (\n    SELECT 1\n)\n\nSELECT * FROM cte\n",
        "Expected LT007 core autofix output in patch mode: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt009_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("select_target_layout_patch_fix.sql");
    std::fs::write(&sql_path, "select\n  a,\n  b,\n  c from x").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--exclude-rules",
            "LINT_LT_014",
            sql_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "select\n    a,\n    b,\n    c\nfrom x\n",
        "Expected LT009 core autofix to place FROM on a new line after final target: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt008_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("cte_newline_patch_fix.sql");
    std::fs::write(&sql_path, "WITH cte AS (SELECT 1) SELECT * FROM cte").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "WITH cte AS (SELECT 1)\n\nSELECT * FROM cte\n",
        "Expected LT008 core autofix to place SELECT on a new line after CTE close: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_lt015_core_autofix_in_patch_mode() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("layout_newlines_patch_fix.sql");
    std::fs::write(&sql_path, "SELECT 1\n\n\nFROM t").expect("write sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", sql_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with fix");

    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&output)
    );

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_eq!(
        after, "SELECT 1\n\nFROM t\n",
        "Expected LT015 core autofix to collapse excessive blank lines: {after:?}"
    );
}

#[test]
fn test_lint_fix_applies_jj001_core_autofix_only_in_unsafe_mode() {
    let dir = tempdir().expect("temp dir");
    let safe_path = dir.path().join("jinja_padding_safe.sql");
    std::fs::write(&safe_path, "SELECT '{{foo}}' AS templated").expect("write sql");

    let safe_output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", "--fix", safe_path.to_str().expect("sql path")])
        .output()
        .expect("run CLI with safe fix");
    assert_ne!(
        safe_output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&safe_output)
    );
    let safe_after = std::fs::read_to_string(&safe_path).expect("read SQL after safe fix");
    assert!(
        safe_after.contains("{{foo}}"),
        "safe mode should keep template edits protected: {safe_after}"
    );

    let unsafe_path = dir.path().join("jinja_padding_unsafe.sql");
    std::fs::write(&unsafe_path, "SELECT '{{foo}}' AS templated").expect("write sql");
    let unsafe_output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            "--fix",
            "--unsafe-fixes",
            unsafe_path.to_str().expect("sql path"),
        ])
        .output()
        .expect("run CLI with unsafe fix");
    assert_ne!(
        unsafe_output.status.code(),
        Some(2),
        "Expected CLI invocation to succeed: {}",
        combined_output(&unsafe_output)
    );
    let unsafe_after = std::fs::read_to_string(&unsafe_path).expect("read SQL after unsafe fix");
    assert!(
        unsafe_after.contains("{{ foo }}"),
        "unsafe mode should apply JJ001 core autofix: {unsafe_after}"
    );
}

#[test]
fn test_lint_multiple_files() {
    let dir = tempdir().expect("temp dir");
    let clean_path = dir.path().join("clean.sql");
    let bad_path = dir.path().join("bad.sql");
    std::fs::write(&clean_path, SQL_CLEAN).expect("write clean sql");
    std::fs::write(&bad_path, SQL_WITH_VIOLATIONS).expect("write bad sql");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args([
            "--lint",
            clean_path.to_str().expect("clean path"),
            bad_path.to_str().expect("bad path"),
        ])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1 when any file fails: {stdout}"
    );
    assert!(
        stdout.contains("PASS"),
        "Expected PASS for clean file: {stdout}"
    );
    assert!(
        stdout.contains("FAIL"),
        "Expected FAIL for bad file: {stdout}"
    );
    assert!(
        stdout.contains("1 file passed"),
        "Expected 1 file passed: {stdout}"
    );
    assert!(
        stdout.contains("1 file failed"),
        "Expected 1 file failed: {stdout}"
    );
    assert!(
        stdout.contains("All Finished in "),
        "Expected elapsed time in summary: {stdout}"
    );
}

#[test]
fn test_lint_directory_recursively() {
    let dir = tempdir().expect("temp dir");
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).expect("create nested directory");

    let clean_path = dir.path().join("clean.sql");
    let bad_path = nested.join("bad.sql");
    let ignored = nested.join("notes.txt");

    std::fs::write(&clean_path, SQL_CLEAN).expect("write clean sql");
    std::fs::write(&bad_path, SQL_WITH_VIOLATIONS).expect("write bad sql");
    std::fs::write(&ignored, SQL_WITH_VIOLATIONS).expect("write ignored file");

    let output = Command::new(env!("CARGO_BIN_EXE_flowscope"))
        .args(["--lint", dir.path().to_str().expect("dir path")])
        .output()
        .expect("run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit 1 when one discovered SQL file fails: {stdout}"
    );
    assert!(
        stdout.contains("1 file passed"),
        "Expected one clean SQL file in recursive lint output: {stdout}"
    );
    assert!(
        stdout.contains("1 file failed"),
        "Expected one failing SQL file in recursive lint output: {stdout}"
    );
    assert!(
        stdout.contains("AM02"),
        "Expected lint violation from nested SQL file: {stdout}"
    );
    assert!(
        !stdout.contains("notes.txt"),
        "Expected non-sql files to be ignored: {stdout}"
    );
}

#[test]
fn test_lint_fix_can_modify_commented_sql_while_preserving_comment_bytes() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("commented_safe_fix.sql");
    std::fs::write(&sql_path, SQL_COMMENTED_SAFE_FIX).expect("write sql");

    let output = run_flowscope(&["--lint", "--fix", sql_path.to_str().expect("sql path")]);

    let after = std::fs::read_to_string(&sql_path).expect("read SQL after fix");
    assert_ne!(
        after, SQL_COMMENTED_SAFE_FIX,
        "Expected --lint --fix to modify commented SQL file"
    );
    assert!(
        after.to_ascii_uppercase().contains("COUNT(*)"),
        "Expected safe fix to rewrite COUNT(1): {after}"
    );
    for comment in ["-- keep:lead", "/* keep:mid */", "-- keep:tail"] {
        assert_eq!(
            after.matches(comment).count(),
            1,
            "Expected comment bytes to be preserved exactly once: {comment}; SQL: {after}"
        );
    }

    let output_text = combined_output(&output);
    assert!(
        !output_text
            .to_ascii_lowercase()
            .contains("comments are present"),
        "Expected comment-aware fixer to avoid whole-file comment skip: {output_text}"
    );
}

#[test]
fn test_lint_fix_default_safe_mode_skips_unsafe_or_display_only_candidates() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("unsafe_candidate.sql");
    std::fs::write(&sql_path, SQL_UNSAFE_FIX_REPRESENTATIVE).expect("write sql");

    let output = run_flowscope(&["--lint", "--fix", sql_path.to_str().expect("sql path")]);
    let output_text = combined_output(&output);

    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected remaining violations in safe mode when unsafe/display-only fixes are skipped: {output_text}"
    );

    let remaining_codes = lint_violation_codes(&sql_path);
    assert!(
        remaining_codes.iter().any(|code| code == "ST05"),
        "Expected representative unsafe violation ST05 to remain in default safe mode: {remaining_codes:?}"
    );

    assert!(
        contains_any(
            &output_text,
            &[
                "unsafe",
                "blocked",
                "display-only",
                "display only",
                "safety",
                "not applied"
            ]
        ),
        "Expected safe-mode output to report blocked unsafe/display-only fixes: {output_text}"
    );
}

#[test]
fn test_lint_unsafe_fixes_with_legacy_ast_rewrites_enables_additional_fixes_over_safe_mode() {
    let dir = tempdir().expect("temp dir");
    let safe_path = dir.path().join("safe_mode.sql");
    let unsafe_path = dir.path().join("unsafe_mode.sql");
    std::fs::write(&safe_path, SQL_UNSAFE_FIX_REPRESENTATIVE).expect("write safe sql");
    std::fs::write(&unsafe_path, SQL_UNSAFE_FIX_REPRESENTATIVE).expect("write unsafe sql");

    let safe_output = run_flowscope(&["--lint", "--fix", safe_path.to_str().expect("safe path")]);
    assert_ne!(
        safe_output.status.code(),
        Some(2),
        "Expected baseline safe fix run to execute, got parse error: {}",
        combined_output(&safe_output)
    );

    let unsafe_output = run_flowscope(&[
        "--lint",
        "--fix",
        "--unsafe-fixes",
        "--legacy-ast-fixes",
        unsafe_path.to_str().expect("unsafe path"),
    ]);
    assert_flag_was_accepted(&unsafe_output, "--unsafe-fixes");
    assert_flag_was_accepted(&unsafe_output, "--legacy-ast-fixes");

    let safe_codes = lint_violation_codes(&safe_path);
    let unsafe_codes = lint_violation_codes(&unsafe_path);
    assert!(
        safe_codes.iter().any(|code| code == "ST05"),
        "Expected safe mode to retain representative ST05 violation: {safe_codes:?}"
    );
    assert!(
        !unsafe_codes.iter().any(|code| code == "ST05"),
        "Expected --unsafe-fixes --legacy-ast-fixes to apply additional structural rewrites and clear ST05. unsafe={unsafe_codes:?}"
    );
    assert!(
        unsafe_codes != safe_codes,
        "Expected --unsafe-fixes --legacy-ast-fixes to produce a different lint outcome than safe mode. safe={safe_codes:?}, unsafe={unsafe_codes:?}"
    );
}

#[test]
fn test_lint_unsafe_fixes_without_legacy_ast_rewrites_clears_st05_via_core_patch() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("unsafe_without_legacy.sql");
    std::fs::write(&sql_path, SQL_UNSAFE_FIX_REPRESENTATIVE).expect("write sql");

    let output = run_flowscope(&[
        "--lint",
        "--fix",
        "--unsafe-fixes",
        sql_path.to_str().expect("sql path"),
    ]);
    assert_flag_was_accepted(&output, "--unsafe-fixes");
    assert_ne!(
        output.status.code(),
        Some(2),
        "Expected run to execute without clap/parser failure: {}",
        combined_output(&output)
    );

    let codes = lint_violation_codes(&sql_path);
    assert!(
        !codes.iter().any(|code| code == "ST05"),
        "Expected --unsafe-fixes to clear ST05 via core patch rewriter: {codes:?}"
    );
}

#[test]
fn test_lint_show_fixes_surfaces_blocked_or_suggested_fix_info() {
    let dir = tempdir().expect("temp dir");
    let sql_path = dir.path().join("show_fixes.sql");
    std::fs::write(&sql_path, SQL_UNSAFE_FIX_REPRESENTATIVE).expect("write baseline sql");

    let baseline_output = run_flowscope(&["--lint", "--fix", sql_path.to_str().expect("sql path")]);
    assert_ne!(
        baseline_output.status.code(),
        Some(2),
        "Expected baseline run to execute: {}",
        combined_output(&baseline_output)
    );

    std::fs::write(&sql_path, SQL_UNSAFE_FIX_REPRESENTATIVE).expect("reset sql");

    let output = run_flowscope(&[
        "--lint",
        "--fix",
        "--show-fixes",
        sql_path.to_str().expect("sql path"),
    ]);
    assert_flag_was_accepted(&output, "--show-fixes");

    let baseline_stderr = String::from_utf8_lossy(&baseline_output.stderr);
    let output_stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(
        output_stderr, baseline_stderr,
        "Expected --show-fixes to change stderr by surfacing additional fix visibility details"
    );
    assert!(
        output_stderr.len() > baseline_stderr.len(),
        "Expected --show-fixes to provide more stderr detail than baseline --fix output. baseline={baseline_stderr}, show={output_stderr}"
    );
    assert!(
        contains_any(
            &output_stderr,
            &[
                "blocked",
                "suggested",
                "display-only",
                "display only",
                "unsafe"
            ]
        ),
        "Expected --show-fixes output to include blocked/suggested fix details: {output_stderr}"
    );
}
