//! Opt-in, parse-only measurement for the private SQL corpus.
//!
//! Bounded acceptance harness for parser-coverage issue #24. Never emit SQL, ASTs, paths,
//! filenames, or formatted parser diagnostics to standard output.

use flowscope_core::{
    analyzer::parse_only_sql_with_dialect_output,
    error::{ParseError, ParseErrorKind, Position},
    split_statements,
    types::{Dialect, StatementSplitRequest},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Instant,
};

const DEFAULT_MAX_FILES: usize = 10_000;
const HARD_MAX_FILES: usize = 100_000;
const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
const HARD_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_WORKERS: usize = 4;
const HARD_MAX_WORKERS: usize = 16;
const HARD_MAX_INVENTORY_BYTES: usize = 32 * 1024 * 1024;
const HARD_MAX_PATH_BYTES: usize = 16 * 1024;
const HARD_MAX_TREE_RECORD_BYTES: usize = HARD_MAX_PATH_BYTES + 256;
const PROGRESS_INTERVAL: usize = 100;
const HARD_MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const HARD_MAX_PRIVATE_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const HARD_MAX_PRIVATE_DIAGNOSTIC_MESSAGE_BYTES: usize = 4 * 1024;
const GIT_ENV_TO_CLEAR: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_QUARANTINE_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_TRACE_CURL_NO_DATA",
    "GIT_TRACE2_BRIEF",
];
const GIT_TRACE_ENV_TO_SINK: &[&str] = &[
    "GIT_TRACE",
    "GIT_TRACE_SETUP",
    "GIT_TRACE_PACKET",
    "GIT_TRACE_PACKFILE",
    "GIT_TRACE_CURL",
    "GIT_TRACE_PACK_ACCESS",
    "GIT_TRACE_SHALLOW",
    "GIT_TRACE_FSMONITOR",
    "GIT_TRACE2",
    "GIT_TRACE2_EVENT",
    "GIT_TRACE2_PERF",
    "GIT_TRACE_PERFORMANCE",
];

#[derive(Clone, Copy)]
struct Config {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    workers: usize,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct Summary {
    completed: usize,
    parsed: usize,
    parser_errors: usize,
    input_errors: usize,
    statements: usize,
    fallback_used: usize,
    syntax_errors: usize,
    missing_clause_errors: usize,
    unexpected_eof_errors: usize,
    unsupported_feature_errors: usize,
    lexer_errors: usize,
    dialect_counts: HashMap<&'static str, usize>,
    standalone_sql: usize,
    batch_scripts: usize,
    intentional_fragments: usize,
    authored_files: usize,
    generated_files: usize,
    unknown_artifact_files: usize,
    utf8_bom_files: usize,
    sqlcmd_reviewed_present: usize,
    flyway_reviewed_present: usize,
    jinja_reviewed_present: usize,
    unreviewed_marker_files: usize,
    mssql_go_batches: usize,
    external_context_required: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusManifest {
    schema_version: u32,
    expected_commit: String,
    files: Vec<ManifestFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    dialect: String,
    input_class: InputClass,
    artifact_class: ArtifactClass,
    encoding: InputEncoding,
    markers: MarkerReview,
    batch_context: BatchContext,
    preprocessing: Vec<String>,
    classification_reason: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputClass {
    StandaloneSql,
    BatchScript,
    IntentionalFragment,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactClass {
    Authored,
    Generated,
    Unknown,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputEncoding {
    Utf8,
    Utf8Bom,
    Unknown,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MarkerStatus {
    ReviewedPresent,
    ReviewedAbsent,
    Unreviewed,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerReview {
    sqlcmd_variables: MarkerStatus,
    flyway_placeholders: MarkerStatus,
    jinja_dbt_markers: MarkerStatus,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BatchContext {
    None,
    MssqlGoBatches,
    ExternalContextRequired,
}

#[derive(Clone, Copy)]
struct SqlClassification {
    dialect: Dialect,
    input_class: InputClass,
    artifact_class: ArtifactClass,
    encoding: InputEncoding,
    markers: MarkerReview,
    batch_context: BatchContext,
}

struct TrackedSqlFile {
    path: PathBuf,
    object_id: String,
    bytes: u64,
    classification: Option<SqlClassification>,
}

struct FileResult {
    classification: SqlClassification,
    parsed: bool,
    input_error: bool,
    statements: usize,
    fallback_used: bool,
    utf8_bom_present: bool,
    error_kind: Option<ParseErrorKind>,
    private_diagnostic: Option<PrivateDiagnostic>,
}

#[derive(Debug)]
struct ParseDiagnostic {
    message: String,
    position: Option<Position>,
    message_truncated: bool,
}

struct PrivateDiagnostic {
    path: String,
    dialect: &'static str,
    kind: ParseErrorKind,
    detail: ParseDiagnostic,
}

#[derive(Serialize)]
struct PrivateDiagnosticRecord<'a> {
    path: &'a str,
    dialect: &'a str,
    kind: &'static str,
    message: &'a str,
    line: Option<usize>,
    column: Option<usize>,
    message_truncated: bool,
}

/// Owns a child process and guarantees it is reaped on every early return.
struct GitChild(Child);

impl GitChild {
    fn take_stdout(&mut self) -> Result<std::process::ChildStdout, &'static str> {
        self.0
            .stdout
            .take()
            .ok_or("git command output is unavailable")
    }
    fn kill(&mut self) {
        let _ = self.0.kill();
    }
    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.0.wait()
    }
}

impl Drop for GitChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct PrivateReportWriter {
    path: PathBuf,
    writer: Option<BufWriter<fs::File>>,
    written_bytes: u64,
    finished: bool,
}

impl PrivateReportWriter {
    fn create(path: &Path, workspace: &Path, corpus_root: &Path) -> Result<Self, &'static str> {
        let path = validate_private_report_path(path, workspace, corpus_root)?;
        let file = create_private_report_file(&path)?;
        Ok(Self {
            path,
            writer: Some(BufWriter::new(file)),
            written_bytes: 0,
            finished: false,
        })
    }

    fn write(&mut self, diagnostic: &PrivateDiagnostic) -> Result<(), &'static str> {
        let writer = self
            .writer
            .as_mut()
            .ok_or("private diagnostic report is unavailable")?;
        write_private_diagnostic(writer, &mut self.written_bytes, diagnostic)
    }

    fn finish(mut self) -> Result<(), &'static str> {
        let mut writer = self
            .writer
            .take()
            .ok_or("private diagnostic report is unavailable")?;
        writer
            .flush()
            .map_err(|_| "private diagnostic report could not be written")?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|_| "private diagnostic report could not be written")?;
        drop(writer);
        self.finished = true;
        Ok(())
    }
}

impl Drop for PrivateReportWriter {
    fn drop(&mut self) {
        if !self.finished {
            drop(self.writer.take());
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn validate_private_report_path(
    path: &Path,
    workspace: &Path,
    corpus_root: &Path,
) -> Result<PathBuf, &'static str> {
    use std::os::unix::fs::PermissionsExt;

    if !path.is_absolute() {
        return Err("private diagnostic report path must be absolute");
    }
    let file_name = path
        .file_name()
        .ok_or("private diagnostic report path is invalid")?;
    let parent = path
        .parent()
        .ok_or("private diagnostic report path is invalid")?;
    let parent = fs::canonicalize(parent)
        .map_err(|_| "private diagnostic report directory is unavailable")?;
    let metadata =
        fs::metadata(&parent).map_err(|_| "private diagnostic report directory is unavailable")?;
    if !metadata.is_dir() {
        return Err("private diagnostic report directory is invalid");
    }
    let workspace = fs::canonicalize(workspace).map_err(|_| "workspace root is invalid")?;
    let corpus_root = fs::canonicalize(corpus_root).map_err(|_| "repository root is invalid")?;
    if paths_overlap(&parent, &workspace) || paths_overlap(&parent, &corpus_root) {
        return Err("private diagnostic report must be separate from the workspace and corpus");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("private diagnostic report directory must be owner-only");
    }
    Ok(parent.join(file_name))
}

#[cfg(not(unix))]
fn validate_private_report_path(
    _path: &Path,
    _workspace: &Path,
    _corpus_root: &Path,
) -> Result<PathBuf, &'static str> {
    Err("private diagnostic reports require Unix file permissions")
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

#[cfg(unix)]
fn create_private_report_file(path: &Path) -> Result<fs::File, &'static str> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "private diagnostic report could not be created")?;
    if file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .is_err()
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err("private diagnostic report permissions could not be restricted");
    }
    let private_mode = file
        .metadata()
        .map(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
        .unwrap_or(false);
    if !private_mode {
        drop(file);
        let _ = fs::remove_file(path);
        return Err("private diagnostic report permissions could not be restricted");
    }
    Ok(file)
}

#[cfg(not(unix))]
fn create_private_report_file(_path: &Path) -> Result<fs::File, &'static str> {
    Err("private diagnostic reports require Unix file permissions")
}

fn encode_private_diagnostic(diagnostic: &PrivateDiagnostic) -> Result<Vec<u8>, &'static str> {
    let record = PrivateDiagnosticRecord {
        path: &diagnostic.path,
        dialect: diagnostic.dialect,
        kind: parse_error_kind_name(diagnostic.kind),
        message: &diagnostic.detail.message,
        line: diagnostic.detail.position.map(|position| position.line),
        column: diagnostic.detail.position.map(|position| position.column),
        message_truncated: diagnostic.detail.message_truncated,
    };
    serde_json::to_vec(&record).map_err(|_| "private diagnostic report could not be encoded")
}

fn write_private_diagnostic(
    writer: &mut impl Write,
    written_bytes: &mut u64,
    diagnostic: &PrivateDiagnostic,
) -> Result<(), &'static str> {
    let bytes = encode_private_diagnostic(diagnostic)?;
    let record_bytes = u64::try_from(bytes.len())
        .ok()
        .and_then(|size| size.checked_add(1))
        .ok_or("private diagnostic report size overflowed")?;
    let next_written_bytes = written_bytes
        .checked_add(record_bytes)
        .ok_or("private diagnostic report size overflowed")?;
    if next_written_bytes > HARD_MAX_PRIVATE_REPORT_BYTES {
        return Err("private diagnostic report exceeds the supported size");
    }
    writer
        .write_all(&bytes)
        .and_then(|()| writer.write_all(b"\n"))
        .map_err(|_| "private diagnostic report could not be written")?;
    *written_bytes = next_written_bytes;
    Ok(())
}

#[test]
#[ignore = "requires explicit access to an external, pinned SQL corpus"]
fn parses_private_corpus_without_emitting_file_details() {
    let started = Instant::now();
    match run_corpus() {
        Ok((commit, tracked_files, tracked_bytes, summary)) => {
            println!(
                "{}",
                format_summary(
                    &commit,
                    tracked_files,
                    tracked_bytes,
                    started.elapsed().as_millis(),
                    &summary,
                )
            )
        }
        Err(message) => panic!("private corpus parse harness failed: {message}"),
    }
}

/// Produces the sole completion report. Deliberately accepts aggregate metadata only.
fn format_summary(
    commit: &str,
    tracked_files: usize,
    tracked_bytes: u64,
    elapsed_ms: u128,
    summary: &Summary,
) -> String {
    format!(
        "private_corpus_parse_summary commit={commit} dialects={} tracked_files={tracked_files} tracked_bytes={tracked_bytes} elapsed_ms={elapsed_ms} parsed={} parser_errors={} input_errors={} statements={} fallback_used={} syntax_errors={} missing_clause_errors={} unexpected_eof_errors={} unsupported_feature_errors={} lexer_errors={} standalone_sql={} batch_scripts={} intentional_fragments={} authored_files={} generated_files={} unknown_artifact_files={} utf8_bom_files={} sqlcmd_reviewed_present={} flyway_reviewed_present={} jinja_dbt_reviewed_present={} unreviewed_marker_files={} mssql_go_batches={} external_context_required={}",
        format_dialect_counts(&summary.dialect_counts),
        summary.parsed,
        summary.parser_errors,
        summary.input_errors,
        summary.statements,
        summary.fallback_used,
        summary.syntax_errors,
        summary.missing_clause_errors,
        summary.unexpected_eof_errors,
        summary.unsupported_feature_errors,
        summary.lexer_errors,
        summary.standalone_sql,
        summary.batch_scripts,
        summary.intentional_fragments,
        summary.authored_files,
        summary.generated_files,
        summary.unknown_artifact_files,
                summary.utf8_bom_files,
        summary.sqlcmd_reviewed_present,
        summary.flyway_reviewed_present,
        summary.jinja_reviewed_present,
        summary.unreviewed_marker_files,
        summary.mssql_go_batches,
        summary.external_context_required,
    )
}

fn format_dialect_counts(counts: &HashMap<&'static str, usize>) -> String {
    let mut counts: Vec<_> = counts.iter().collect();
    counts.sort_unstable_by_key(|(dialect, _)| **dialect);
    counts
        .into_iter()
        .map(|(dialect, count)| format!("{dialect}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn run_corpus() -> Result<(String, usize, u64, Summary), &'static str> {
    let root = required_path("FLOWSCOPE_SQL_CORPUS_DIR")?;
    let commit = required_env("FLOWSCOPE_SQL_CORPUS_COMMIT")?;
    let manifest_path = required_path("FLOWSCOPE_SQL_CORPUS_MANIFEST")?;
    let private_report_path = optional_private_report_path()?;
    let workspace = workspace_root()?;
    let manifest = load_manifest(&manifest_path, &workspace)?;
    run_pinned_classified_corpus(
        &root,
        &commit,
        manifest,
        load_config()?,
        &workspace,
        private_report_path.as_deref(),
    )
}

fn run_pinned_corpus(
    directory: &Path,
    expected_commit: &str,
    dialect: Dialect,
    config: Config,
    workspace: &Path,
) -> Result<(String, Dialect, usize, u64, Summary), &'static str> {
    let (root, commit) = verify_pinned_checkout(directory, expected_commit, workspace)?;
    let (inventory, tracked_bytes) = tracked_sql_files(&root, &commit, config)?;
    if inventory.is_empty() {
        return Err("pinned repository contains no tracked SQL files");
    }
    let classification = default_classification(dialect);
    let inventory = inventory
        .into_iter()
        .map(|mut file| {
            file.classification = Some(classification);
            file
        })
        .collect();
    let summary = parse_inventory(&root, inventory, config, None)?;
    validate_summary(&summary)?;
    Ok((commit, dialect, summary.completed, tracked_bytes, summary))
}

fn run_pinned_classified_corpus(
    directory: &Path,
    expected_commit: &str,
    manifest: CorpusManifest,
    config: Config,
    workspace: &Path,
    private_report_path: Option<&Path>,
) -> Result<(String, usize, u64, Summary), &'static str> {
    let (root, commit) = verify_pinned_checkout(directory, expected_commit, workspace)?;
    if manifest.schema_version != 1 {
        return Err("corpus manifest schema version is unsupported");
    }
    if !manifest.expected_commit.eq_ignore_ascii_case(&commit) {
        return Err("corpus manifest commit does not match the pinned commit");
    }
    let (inventory, tracked_bytes) = tracked_sql_files(&root, &commit, config)?;
    if inventory.is_empty() {
        return Err("pinned repository contains no tracked SQL files");
    }
    let inventory = apply_manifest(inventory, manifest)?;
    let mut private_report = private_report_path
        .map(|path| PrivateReportWriter::create(path, workspace, &root))
        .transpose()?;
    let summary = parse_inventory(&root, inventory, config, private_report.as_mut())?;
    validate_summary(&summary)?;
    if let Some(report) = private_report {
        report.finish()?;
    }
    Ok((commit, summary.completed, tracked_bytes, summary))
}

fn verify_pinned_checkout(
    directory: &Path,
    expected_commit: &str,
    workspace: &Path,
) -> Result<(PathBuf, String), &'static str> {
    if !is_full_object_id(expected_commit) {
        return Err("expected commit must be a full hexadecimal object ID");
    }
    let provided_root =
        fs::canonicalize(directory).map_err(|_| "repository directory is invalid")?;
    let root = git_output(&provided_root, &["rev-parse", "--show-toplevel"])?;
    let root = fs::canonicalize(root.trim_end_matches(['\r', '\n']))
        .map_err(|_| "repository root is invalid")?;
    if provided_root != root {
        return Err("corpus directory must be the repository root");
    }
    let workspace = fs::canonicalize(workspace).map_err(|_| "workspace root is invalid")?;
    if root.starts_with(&workspace) || workspace.starts_with(&root) {
        return Err("corpus repository must be outside and separate from the workspace");
    }
    let commit = git_output(&root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let commit = commit.trim().to_ascii_lowercase();
    if commit != expected_commit.to_ascii_lowercase() {
        return Err("repository commit does not match the pinned commit");
    }
    Ok((root, commit))
}

fn validate_summary(summary: &Summary) -> Result<(), &'static str> {
    if summary.completed != summary.parsed + summary.parser_errors + summary.input_errors {
        return Err("aggregate input and parser counts are inconsistent");
    }
    let dialect_files: usize = summary.dialect_counts.values().copied().sum();
    let input_classes =
        summary.standalone_sql + summary.batch_scripts + summary.intentional_fragments;
    let artifact_classes =
        summary.authored_files + summary.generated_files + summary.unknown_artifact_files;
    let parser_error_kinds = summary.syntax_errors
        + summary.missing_clause_errors
        + summary.unexpected_eof_errors
        + summary.unsupported_feature_errors
        + summary.lexer_errors;
    if dialect_files != summary.completed
        || input_classes != summary.completed
        || artifact_classes != summary.completed
        || parser_error_kinds != summary.parser_errors
        || summary.fallback_used > summary.completed
        || summary.utf8_bom_files > summary.completed
        || summary.unreviewed_marker_files > summary.completed
        || summary.sqlcmd_reviewed_present > summary.completed
        || summary.flyway_reviewed_present > summary.completed
        || summary.jinja_reviewed_present > summary.completed
        || summary.mssql_go_batches + summary.external_context_required > summary.completed
    {
        return Err("aggregate classification counts are inconsistent");
    }
    Ok(())
}

fn required_path(name: &'static str) -> Result<PathBuf, &'static str> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or("required corpus configuration is missing or invalid")
}

fn optional_private_report_path() -> Result<Option<PathBuf>, &'static str> {
    match env::var_os("FLOWSCOPE_SQL_CORPUS_PRIVATE_REPORT") {
        None => Ok(None),
        Some(value) => parse_private_report_path(PathBuf::from(value)).map(Some),
    }
}

fn parse_private_report_path(path: PathBuf) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("private diagnostic report path is invalid");
    }
    Ok(path)
}

fn load_manifest(path: &Path, workspace: &Path) -> Result<CorpusManifest, &'static str> {
    let path = fs::canonicalize(path).map_err(|_| "corpus manifest path is invalid")?;
    if path.starts_with(workspace) {
        return Err("corpus manifest must be outside the FlowScope workspace");
    }
    let metadata = fs::metadata(&path).map_err(|_| "corpus manifest is unavailable")?;
    if !metadata.is_file() || metadata.len() > HARD_MAX_MANIFEST_BYTES {
        return Err("corpus manifest exceeds the supported size or file type");
    }
    let file = fs::File::open(path).map_err(|_| "corpus manifest could not be read")?;
    let bytes = read_bounded_manifest(file)?;
    serde_json::from_slice(&bytes).map_err(|_| "corpus manifest is invalid")
}

fn read_bounded_manifest(reader: impl Read) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    reader
        .take(HARD_MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "corpus manifest could not be read")?;
    if bytes.len() as u64 > HARD_MAX_MANIFEST_BYTES {
        return Err("corpus manifest exceeds the supported size or file type");
    }
    Ok(bytes)
}

fn apply_manifest(
    mut inventory: Vec<TrackedSqlFile>,
    manifest: CorpusManifest,
) -> Result<Vec<TrackedSqlFile>, &'static str> {
    if manifest.schema_version != 1 {
        return Err("corpus manifest schema version is unsupported");
    }
    let mut classifications = HashMap::with_capacity(manifest.files.len());
    for file in manifest.files {
        let path = Path::new(&file.path);
        if file.path.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || path.to_str() != Some(file.path.as_str())
        {
            return Err("corpus manifest contains an invalid path");
        }
        if !file.preprocessing.is_empty() {
            return Err("corpus manifest requests unsupported preprocessing");
        }
        let classification = SqlClassification {
            dialect: parse_dialect(&file.dialect)?,
            input_class: file.input_class,
            artifact_class: file.artifact_class,
            encoding: file.encoding,
            markers: file.markers,
            batch_context: file.batch_context,
        };
        if classification_requires_reason(classification)
            && file
                .classification_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err("corpus manifest classification exception has no rationale");
        }
        if matches!(classification.batch_context, BatchContext::MssqlGoBatches)
            && (!matches!(classification.dialect, Dialect::Mssql)
                || !matches!(classification.input_class, InputClass::BatchScript))
        {
            return Err("MSSQL GO batch context requires an MSSQL batch-script classification");
        }
        if classifications.insert(file.path, classification).is_some() {
            return Err("corpus manifest contains duplicate paths");
        }
    }
    if classifications.len() != inventory.len() {
        return Err("corpus manifest does not match the tracked SQL inventory");
    }
    for file in &mut inventory {
        let path = file
            .path
            .to_str()
            .ok_or("tracked SQL inventory contains an unsupported path")?;
        file.classification = Some(
            classifications
                .remove(path)
                .ok_or("corpus manifest does not match the tracked SQL inventory")?,
        );
    }
    if !classifications.is_empty() {
        return Err("corpus manifest contains paths outside the tracked SQL inventory");
    }
    Ok(inventory)
}

fn default_classification(dialect: Dialect) -> SqlClassification {
    SqlClassification {
        dialect,
        input_class: InputClass::StandaloneSql,
        artifact_class: ArtifactClass::Authored,
        encoding: InputEncoding::Utf8,
        markers: MarkerReview {
            sqlcmd_variables: MarkerStatus::ReviewedAbsent,
            flyway_placeholders: MarkerStatus::ReviewedAbsent,
            jinja_dbt_markers: MarkerStatus::ReviewedAbsent,
        },
        batch_context: BatchContext::None,
    }
}

fn classification_requires_reason(classification: SqlClassification) -> bool {
    matches!(classification.input_class, InputClass::IntentionalFragment)
        || matches!(classification.artifact_class, ArtifactClass::Unknown)
        || matches!(classification.encoding, InputEncoding::Unknown)
        || matches!(
            classification.batch_context,
            BatchContext::ExternalContextRequired
        )
        || [
            classification.markers.sqlcmd_variables,
            classification.markers.flyway_placeholders,
            classification.markers.jinja_dbt_markers,
        ]
        .into_iter()
        .any(|status| {
            matches!(
                status,
                MarkerStatus::ReviewedPresent | MarkerStatus::Unreviewed
            )
        })
}

fn record_classification(summary: &mut Summary, classification: SqlClassification) {
    *summary
        .dialect_counts
        .entry(dialect_name(classification.dialect))
        .or_default() += 1;
    match classification.input_class {
        InputClass::StandaloneSql => summary.standalone_sql += 1,
        InputClass::BatchScript => summary.batch_scripts += 1,
        InputClass::IntentionalFragment => summary.intentional_fragments += 1,
    }
    match classification.artifact_class {
        ArtifactClass::Authored => summary.authored_files += 1,
        ArtifactClass::Generated => summary.generated_files += 1,
        ArtifactClass::Unknown => summary.unknown_artifact_files += 1,
    }
    let marker_statuses = [
        classification.markers.sqlcmd_variables,
        classification.markers.flyway_placeholders,
        classification.markers.jinja_dbt_markers,
    ];
    if marker_statuses
        .iter()
        .any(|status| matches!(status, MarkerStatus::Unreviewed))
    {
        summary.unreviewed_marker_files += 1;
    }
    if matches!(
        classification.markers.sqlcmd_variables,
        MarkerStatus::ReviewedPresent
    ) {
        summary.sqlcmd_reviewed_present += 1;
    }
    if matches!(
        classification.markers.flyway_placeholders,
        MarkerStatus::ReviewedPresent
    ) {
        summary.flyway_reviewed_present += 1;
    }
    if matches!(
        classification.markers.jinja_dbt_markers,
        MarkerStatus::ReviewedPresent
    ) {
        summary.jinja_reviewed_present += 1;
    }
    match classification.batch_context {
        BatchContext::None => {}
        BatchContext::MssqlGoBatches => summary.mssql_go_batches += 1,
        BatchContext::ExternalContextRequired => summary.external_context_required += 1,
    }
}

fn required_env(name: &'static str) -> Result<String, &'static str> {
    env::var(name).map_err(|_| "required corpus configuration is missing or invalid")
}

fn load_config() -> Result<Config, &'static str> {
    Ok(Config {
        max_files: env_limit(
            "FLOWSCOPE_SQL_CORPUS_MAX_FILES",
            DEFAULT_MAX_FILES,
            HARD_MAX_FILES,
        )?,
        max_file_bytes: env_byte_limit(
            "FLOWSCOPE_SQL_CORPUS_MAX_FILE_BYTES",
            DEFAULT_MAX_FILE_BYTES,
            HARD_MAX_FILE_BYTES,
        )?,
        max_total_bytes: env_byte_limit(
            "FLOWSCOPE_SQL_CORPUS_MAX_TOTAL_BYTES",
            DEFAULT_MAX_TOTAL_BYTES,
            HARD_MAX_TOTAL_BYTES,
        )?,
        workers: env_limit(
            "FLOWSCOPE_SQL_CORPUS_WORKERS",
            DEFAULT_WORKERS,
            HARD_MAX_WORKERS,
        )?,
    })
}

fn env_limit(name: &'static str, default: usize, maximum: usize) -> Result<usize, &'static str> {
    match env::var(name) {
        Ok(value) => parse_positive_limit(&value, maximum),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err("configured limit is invalid"),
    }
}
fn env_byte_limit(name: &'static str, default: u64, maximum: u64) -> Result<u64, &'static str> {
    match env::var(name) {
        Ok(value) => parse_byte_limit(&value, maximum),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err("configured byte limit is invalid"),
    }
}
fn parse_positive_limit(value: &str, maximum: usize) -> Result<usize, &'static str> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "configured limit is invalid")?;
    if parsed == 0 || parsed > maximum {
        return Err("configured limit is outside the supported range");
    }
    Ok(parsed)
}
fn parse_byte_limit(value: &str, maximum: u64) -> Result<u64, &'static str> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "configured byte limit is invalid")?;
    if parsed == 0 || parsed > maximum {
        return Err("configured byte limit is outside the supported range");
    }
    Ok(parsed)
}

fn parse_dialect(value: &str) -> Result<Dialect, &'static str> {
    match value.to_ascii_lowercase().as_str() {
        "generic" => Ok(Dialect::Generic),
        "ansi" => Ok(Dialect::Ansi),
        "bigquery" => Ok(Dialect::Bigquery),
        "clickhouse" => Ok(Dialect::Clickhouse),
        "databricks" => Ok(Dialect::Databricks),
        "duckdb" => Ok(Dialect::Duckdb),
        "hive" => Ok(Dialect::Hive),
        "mssql" => Ok(Dialect::Mssql),
        "mysql" => Ok(Dialect::Mysql),
        "oracle" => Ok(Dialect::Oracle),
        "postgres" => Ok(Dialect::Postgres),
        "redshift" => Ok(Dialect::Redshift),
        "snowflake" => Ok(Dialect::Snowflake),
        "sqlite" => Ok(Dialect::Sqlite),
        _ => Err("SQL dialect is unsupported"),
    }
}
fn dialect_name(d: Dialect) -> &'static str {
    match d {
        Dialect::Generic => "generic",
        Dialect::Ansi => "ansi",
        Dialect::Bigquery => "bigquery",
        Dialect::Clickhouse => "clickhouse",
        Dialect::Databricks => "databricks",
        Dialect::Duckdb => "duckdb",
        Dialect::Hive => "hive",
        Dialect::Mssql => "mssql",
        Dialect::Mysql => "mysql",
        Dialect::Oracle => "oracle",
        Dialect::Postgres => "postgres",
        Dialect::Redshift => "redshift",
        Dialect::Snowflake => "snowflake",
        Dialect::Sqlite => "sqlite",
    }
}
fn parse_error_kind_name(kind: ParseErrorKind) -> &'static str {
    match kind {
        ParseErrorKind::SyntaxError => "syntax_error",
        ParseErrorKind::MissingClause => "missing_clause",
        ParseErrorKind::UnexpectedEof => "unexpected_eof",
        ParseErrorKind::UnsupportedFeature => "unsupported_feature",
        ParseErrorKind::LexerError => "lexer_error",
    }
}
fn is_full_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn workspace_root() -> Result<PathBuf, &'static str> {
    let root = git_output(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &["rev-parse", "--show-toplevel"],
    )?;
    fs::canonicalize(root.trim_end_matches(['\r', '\n'])).map_err(|_| "workspace root is invalid")
}

fn git_command(directory: &Path) -> Command {
    let mut cmd = Command::new("git");
    for &name in GIT_ENV_TO_CLEAR {
        cmd.env_remove(name);
    }
    for &name in GIT_TRACE_ENV_TO_SINK {
        cmd.env(name, git_null_device());
    }
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .arg("-C")
        .arg(directory)
        .stderr(Stdio::null());
    cmd
}

fn git_null_device() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}
fn git_output(directory: &Path, args: &[&str]) -> Result<String, &'static str> {
    let out = git_command(directory)
        .args(args)
        .output()
        .map_err(|_| "git command could not be started")?;
    if !out.status.success() {
        return Err("git command failed");
    }
    String::from_utf8(out.stdout).map_err(|_| "git returned invalid text")
}

fn tracked_sql_files(
    root: &Path,
    commit: &str,
    config: Config,
) -> Result<(Vec<TrackedSqlFile>, u64), &'static str> {
    let mut child = GitChild(
        git_command(root)
            .args(["ls-tree", "-r", "-l", "--full-tree", "-z", commit])
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| "git inventory command could not be started")?,
    );
    let stdout = child.take_stdout()?;
    let mut reader = BufReader::new(stdout);
    let mut record = Vec::new();
    let mut inventory = Vec::new();
    let mut inventory_bytes = 0usize;
    let mut total_sql_bytes = 0u64;
    loop {
        record.clear();
        match read_bounded_tree_record(&mut reader, &mut record) {
            Ok(false) => break,
            Ok(true) => {}
            Err(()) => {
                child.kill();
                let _ = child.wait();
                return Err("git inventory exceeds a bounded record size");
            }
        }
        inventory_bytes = inventory_bytes
            .checked_add(record.len())
            .ok_or("git inventory size overflowed")?;
        if inventory_bytes > HARD_MAX_INVENTORY_BYTES {
            child.kill();
            let _ = child.wait();
            return Err("git inventory exceeds its memory safety limit");
        }
        let separator = record
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("git inventory record has no metadata separator")?;
        let (metadata, path_and_tab) = record.split_at(separator);
        let path_bytes = &path_and_tab[1..];
        if path_bytes.is_empty() || path_bytes.len() > HARD_MAX_PATH_BYTES {
            child.kill();
            let _ = child.wait();
            return Err("tracked path exceeds the inventory limits");
        }
        let path = path_from_git_bytes(path_bytes).ok_or("tracked path is unsupported")?;
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            child.kill();
            let _ = child.wait();
            return Err("pinned tree contains an invalid path");
        }
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"))
        {
            continue;
        }

        let mut fields = metadata
            .split(|b| b.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        let mode = fields
            .next()
            .ok_or("git inventory metadata is incomplete")?;
        let object_type = fields
            .next()
            .ok_or("git inventory metadata is incomplete")?;
        let object_id = fields
            .next()
            .ok_or("git inventory metadata is incomplete")?;
        let object_size = fields
            .next()
            .ok_or("git inventory metadata is incomplete")?;
        if fields.next().is_some() {
            child.kill();
            let _ = child.wait();
            return Err("git inventory metadata has an unexpected field");
        }
        if mode != b"100644" && mode != b"100755" {
            child.kill();
            let _ = child.wait();
            return Err("tracked SQL entry is not a regular file");
        }
        if object_type != b"blob" {
            child.kill();
            let _ = child.wait();
            return Err("tracked SQL entry is not a blob");
        }
        let object_id = std::str::from_utf8(object_id)
            .map_err(|_| "git object identifier is invalid")?
            .to_owned();
        if !is_full_object_id(&object_id) {
            child.kill();
            let _ = child.wait();
            return Err("git object identifier is invalid");
        }
        let bytes = std::str::from_utf8(object_size)
            .ok()
            .and_then(|size| size.parse::<u64>().ok())
            .ok_or("git object size is invalid")?;
        if bytes > config.max_file_bytes {
            child.kill();
            let _ = child.wait();
            return Err("tracked SQL file exceeds the configured per-file limit");
        }
        total_sql_bytes = total_sql_bytes
            .checked_add(bytes)
            .ok_or("tracked SQL byte count overflowed")?;
        if total_sql_bytes > config.max_total_bytes {
            child.kill();
            let _ = child.wait();
            return Err("tracked SQL byte total exceeds the configured limit");
        }
        if inventory.len() == config.max_files {
            child.kill();
            let _ = child.wait();
            return Err("tracked SQL file count exceeds the configured limit");
        }
        inventory.push(TrackedSqlFile {
            path,
            object_id,
            bytes,
            classification: None,
        });
    }
    let status = child.wait().map_err(|_| "git inventory process failed")?;
    if !status.success() {
        return Err("git inventory command failed");
    }
    Ok((inventory, total_sql_bytes))
}

fn read_bounded_tree_record(reader: &mut impl BufRead, record: &mut Vec<u8>) -> Result<bool, ()> {
    loop {
        let buf = reader.fill_buf().map_err(|_| ())?;
        if buf.is_empty() {
            return if record.is_empty() {
                Ok(false)
            } else {
                Err(())
            };
        }
        let nul = buf.iter().position(|b| *b == 0);
        let consumed = nul.map_or(buf.len(), |i| i + 1);
        let content = nul.unwrap_or(consumed);
        if record.len().saturating_add(content) > HARD_MAX_TREE_RECORD_BYTES {
            return Err(());
        }
        record.extend_from_slice(&buf[..content]);
        reader.consume(consumed);
        if nul.is_some() {
            return Ok(true);
        }
    }
}
#[cfg(unix)]
fn path_from_git_bytes(bytes: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Some(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}
#[cfg(not(unix))]
fn path_from_git_bytes(bytes: &[u8]) -> Option<PathBuf> {
    String::from_utf8(bytes.to_vec()).ok().map(PathBuf::from)
}

fn parse_inventory(
    root: &Path,
    inventory: Vec<TrackedSqlFile>,
    config: Config,
    mut private_report: Option<&mut PrivateReportWriter>,
) -> Result<Summary, &'static str> {
    let total = inventory.len();
    let inventory = Arc::new(inventory);
    let next = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::sync_channel::<Result<FileResult, &'static str>>(config.workers);
    let mut summary = Summary::default();
    let capture_diagnostics = private_report.is_some();
    thread::scope(|scope| {
        for _ in 0..config.workers.min(total) {
            let files = Arc::clone(&inventory);
            let sender = sender.clone();
            let root = root.to_path_buf();
            let next = &next;
            scope.spawn(move || loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(file) = files.get(i) else {
                    break;
                };
                let result = parse_blob(&root, file, config.max_file_bytes, capture_diagnostics);
                let failed = result.is_err();
                if sender.send(result).is_err() || failed {
                    break;
                }
            });
        }
        drop(sender);
        for result in receiver {
            match result {
                Ok(result) => {
                    summary.completed += 1;
                    record_classification(&mut summary, result.classification);
                    summary.utf8_bom_files += usize::from(result.utf8_bom_present);
                    if result.parsed {
                        summary.parsed += 1;
                    } else if result.input_error {
                        summary.input_errors += 1;
                    } else {
                        summary.parser_errors += 1;
                        match result.error_kind {
                            Some(ParseErrorKind::SyntaxError) => summary.syntax_errors += 1,
                            Some(ParseErrorKind::MissingClause) => {
                                summary.missing_clause_errors += 1
                            }
                            Some(ParseErrorKind::UnexpectedEof) => {
                                summary.unexpected_eof_errors += 1
                            }
                            Some(ParseErrorKind::UnsupportedFeature) => {
                                summary.unsupported_feature_errors += 1
                            }
                            Some(ParseErrorKind::LexerError) | None => summary.lexer_errors += 1,
                        }
                    }
                    summary.statements = summary
                        .statements
                        .checked_add(result.statements)
                        .ok_or("aggregate statement count overflowed")?;
                    summary.fallback_used += usize::from(result.fallback_used);
                    if let Some(diagnostic) = result.private_diagnostic {
                        private_report
                            .as_deref_mut()
                            .ok_or("private diagnostic report is unavailable")?
                            .write(&diagnostic)?;
                    }
                    if summary.completed % PROGRESS_INTERVAL == 0 || summary.completed == total {
                        println!(
                            "private_corpus_parse_progress completed={} total={total}",
                            summary.completed
                        );
                    }
                }
                Err(message) => return Err(message),
            }
        }
        Ok(())
    })?;
    if summary.completed != total {
        return Err("not every tracked SQL file was processed");
    }
    Ok(summary)
}

fn parse_blob(
    root: &Path,
    file: &TrackedSqlFile,
    max_file_bytes: u64,
    capture_diagnostics: bool,
) -> Result<FileResult, &'static str> {
    if file.bytes > max_file_bytes {
        return Err("tracked SQL file exceeds the configured per-file limit");
    }
    let classification = file
        .classification
        .ok_or("tracked SQL file has no classification")?;
    if matches!(classification.encoding, InputEncoding::Unknown) {
        return Ok(FileResult {
            classification,
            parsed: false,
            input_error: true,
            statements: 0,
            fallback_used: false,
            utf8_bom_present: false,
            error_kind: None,
            private_diagnostic: None,
        });
    }
    let mut child = GitChild(
        git_command(root)
            .args(["cat-file", "blob", &file.object_id])
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| "git blob reader could not be started")?,
    );
    let stdout = child.take_stdout()?;
    let mut contents = Vec::with_capacity(file.bytes as usize);
    if stdout
        .take(max_file_bytes.saturating_add(1))
        .read_to_end(&mut contents)
        .is_err()
    {
        child.kill();
        let _ = child.wait();
        return Err("git blob could not be read");
    }
    if contents.len() as u64 != file.bytes || contents.len() as u64 > max_file_bytes {
        child.kill();
        let _ = child.wait();
        return Err("git blob size does not match the pinned inventory");
    }
    let status = child.wait().map_err(|_| "git blob process failed")?;
    if !status.success() {
        return Err("git blob command failed");
    }
    let has_utf8_bom = contents.starts_with(b"\xef\xbb\xbf");
    let sql = match String::from_utf8(contents) {
        Ok(sql) => sql,
        Err(_) => {
            return Ok(FileResult {
                classification,
                parsed: false,
                input_error: true,
                statements: 0,
                fallback_used: false,
                utf8_bom_present: has_utf8_bom,
                error_kind: None,
                private_diagnostic: None,
            });
        }
    };
    if has_utf8_bom != matches!(classification.encoding, InputEncoding::Utf8Bom) {
        return Ok(FileResult {
            classification,
            parsed: false,
            input_error: true,
            statements: 0,
            fallback_used: false,
            utf8_bom_present: has_utf8_bom,
            error_kind: None,
            private_diagnostic: None,
        });
    }
    Ok(
        match parse_classified_sql_with_diagnostics(&sql, classification, capture_diagnostics) {
            Ok((statements, fallback_used)) => FileResult {
                classification,
                parsed: true,
                input_error: false,
                statements,
                fallback_used,
                utf8_bom_present: has_utf8_bom,
                error_kind: None,
                private_diagnostic: None,
            },
            Err(ParseAttemptError::Parser {
                kind,
                statements,
                fallback_used,
                diagnostic,
            }) => {
                let private_diagnostic = match diagnostic {
                    Some(detail) => Some(PrivateDiagnostic {
                        path: file
                            .path
                            .to_str()
                            .ok_or("private diagnostic report path is unsupported")?
                            .to_owned(),
                        dialect: dialect_name(classification.dialect),
                        kind,
                        detail,
                    }),
                    None => None,
                };
                FileResult {
                    classification,
                    parsed: false,
                    input_error: false,
                    statements,
                    fallback_used,
                    utf8_bom_present: has_utf8_bom,
                    error_kind: Some(kind),
                    private_diagnostic,
                }
            }
            Err(ParseAttemptError::Input) => FileResult {
                classification,
                parsed: false,
                input_error: true,
                statements: 0,
                fallback_used: false,
                utf8_bom_present: has_utf8_bom,
                error_kind: None,
                private_diagnostic: None,
            },
        },
    )
}

#[derive(Debug)]
enum ParseAttemptError {
    Input,
    Parser {
        kind: ParseErrorKind,
        statements: usize,
        fallback_used: bool,
        diagnostic: Option<ParseDiagnostic>,
    },
}

fn parse_classified_sql(
    sql: &str,
    classification: SqlClassification,
) -> Result<(usize, bool), ParseAttemptError> {
    parse_classified_sql_with_diagnostics(sql, classification, false)
}

fn parse_classified_sql_with_diagnostics(
    sql: &str,
    classification: SqlClassification,
    capture_diagnostics: bool,
) -> Result<(usize, bool), ParseAttemptError> {
    if !matches!(classification.input_class, InputClass::BatchScript) {
        return match parse_only_sql_with_dialect_output(sql, classification.dialect) {
            Ok(output) => Ok((output.statement_count, output.parser_fallback_used)),
            Err(error) => {
                let kind = error.kind;
                let diagnostic = capture_diagnostics.then(|| parse_diagnostic(error));
                let (statements, fallback_used) =
                    standalone_successful_statement_counts(sql, classification.dialect);
                Err(ParseAttemptError::Parser {
                    kind,
                    statements,
                    fallback_used,
                    diagnostic,
                })
            }
        };
    }

    let split = split_statements(&StatementSplitRequest {
        sql: sql.to_owned(),
        dialect: classification.dialect,
    });
    if split.error.is_some() {
        return Err(ParseAttemptError::Input);
    }

    let mut statement_count = 0usize;
    let mut fallback_used = false;
    let mut first_error = None;
    for span in split.statements {
        let statement_sql = sql
            .get(span.start..span.end)
            .ok_or(ParseAttemptError::Input)?;
        match parse_only_sql_with_dialect_output(statement_sql, classification.dialect) {
            Ok(output) => {
                statement_count = statement_count
                    .checked_add(output.statement_count)
                    .ok_or(ParseAttemptError::Input)?;
                fallback_used |= output.parser_fallback_used;
            }
            Err(error) => {
                if first_error.is_none() {
                    let kind = error.kind;
                    let diagnostic = capture_diagnostics.then(|| {
                        let mut diagnostic = parse_diagnostic(error);
                        remap_diagnostic_position(&mut diagnostic, sql, span.start);
                        diagnostic
                    });
                    first_error = Some((kind, diagnostic));
                }
            }
        }
    }

    match first_error {
        Some((kind, diagnostic)) => Err(ParseAttemptError::Parser {
            kind,
            statements: statement_count,
            fallback_used,
            diagnostic,
        }),
        None => Ok((statement_count, fallback_used)),
    }
}

fn standalone_successful_statement_counts(sql: &str, dialect: Dialect) -> (usize, bool) {
    let split = split_statements(&StatementSplitRequest {
        sql: sql.to_owned(),
        dialect,
    });
    if split.error.is_some() {
        return (0, false);
    }
    if matches!(dialect, Dialect::Mssql) {
        let generic_split = split_statements(&StatementSplitRequest {
            sql: sql.to_owned(),
            dialect: Dialect::Generic,
        });
        if generic_split.error.is_some() || generic_split.statements != split.statements {
            return (0, false);
        }
    }

    let mut statement_count = 0usize;
    let mut fallback_used = false;
    for span in split.statements {
        let Some(statement_sql) = sql.get(span.start..span.end) else {
            return (0, false);
        };
        if let Ok(output) = parse_only_sql_with_dialect_output(statement_sql, dialect) {
            let Some(next_count) = statement_count.checked_add(output.statement_count) else {
                return (0, false);
            };
            statement_count = next_count;
            fallback_used |= output.parser_fallback_used;
        }
    }
    (statement_count, fallback_used)
}

fn remap_diagnostic_position(diagnostic: &mut ParseDiagnostic, source: &str, offset: usize) {
    diagnostic.position = diagnostic.position.and_then(|position| {
        let prefix = source.get(..offset)?;
        let source_line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let source_column = prefix.rsplit('\n').next()?.chars().count().checked_add(1)?;
        let line = source_line.checked_add(position.line.checked_sub(1)?)?;
        let column = if position.line == 1 {
            source_column.checked_add(position.column.checked_sub(1)?)?
        } else {
            position.column
        };
        Some(Position { line, column })
    });
}

fn parse_diagnostic(error: ParseError) -> ParseDiagnostic {
    let mut message = error.message;
    let message_truncated = message.len() > HARD_MAX_PRIVATE_DIAGNOSTIC_MESSAGE_BYTES;
    if message_truncated {
        let mut end = HARD_MAX_PRIVATE_DIAGNOSTIC_MESSAGE_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    ParseDiagnostic {
        message,
        position: error.position,
        message_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct TempRepo(PathBuf, PathBuf);
    impl TempRepo {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let workspace = workspace_root().expect("workspace root");
            let scratch_root = workspace.join("target");
            match fs::symlink_metadata(&scratch_root) {
                Ok(metadata) => assert!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "synthetic test directory must be a workspace-local directory"
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(&scratch_root).expect("create workspace-local test directory");
                }
                Err(_) => panic!("workspace-local test directory is unavailable"),
            }
            let scratch_root = fs::canonicalize(scratch_root)
                .expect("canonicalize workspace-local test directory");
            assert!(
                scratch_root.starts_with(&workspace),
                "synthetic test directory must be inside the workspace"
            );
            let area = loop {
                let candidate = scratch_root.join(format!(
                    "flowscope-private-parse-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&candidate) {
                    Ok(()) => break candidate,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(_) => panic!("create synthetic test area"),
                }
            };
            let test_workspace = area.join("workspace");
            fs::create_dir(&test_workspace).expect("create synthetic workspace");
            let template = area.join("template");
            fs::create_dir(&template).expect("create empty git template");
            fs::write(area.join("global-config"), b"").expect("create isolated git config");
            let path = area.join("repo");
            fs::create_dir(&path).expect("create synthetic repository");
            let template_arg = format!("--template={}", template.display());
            git(&path, &["init", "-q", &template_arg]);
            git(&path, &["config", "user.name", "Harness Test"]);
            git(&path, &["config", "user.email", "harness@example.invalid"]);
            Self(path, test_workspace)
        }
        fn write(&self, name: &str, contents: &[u8]) {
            let path = self.0.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create synthetic directory");
            }
            fs::write(path, contents).expect("write synthetic file");
        }
        fn commit(&self) -> String {
            git(&self.0, &["add", "--all"]);
            git(&self.0, &["commit", "-qm", "synthetic parser harness test"]);
            git(&self.0, &["rev-parse", "HEAD"])
        }
    }
    impl Drop for TempRepo {
        fn drop(&mut self) {
            if let Some(area) = self.0.parent() {
                let _ = fs::remove_dir_all(area);
            }
        }
    }
    fn git(root: &Path, args: &[&str]) -> String {
        let global_config = root
            .parent()
            .expect("synthetic repository parent")
            .join("global-config");
        let mut command = git_command(root);
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", global_config)
            .args(args);
        let output = command.output().expect("start test git command");
        assert!(output.status.success());
        String::from_utf8(output.stdout).expect("test git output is UTF-8")
    }
    fn config() -> Config {
        Config {
            max_files: 10,
            max_file_bytes: 1024,
            max_total_bytes: 4096,
            workers: 2,
        }
    }
    fn repo(files: &[(&str, &[u8])]) -> TempRepo {
        let repo = TempRepo::new();
        for (path, bytes) in files {
            repo.write(path, bytes);
        }
        repo.commit();
        repo
    }
    fn manifest_file(path: &str, dialect: &str) -> ManifestFile {
        ManifestFile {
            path: path.to_owned(),
            dialect: dialect.to_owned(),
            input_class: InputClass::StandaloneSql,
            artifact_class: ArtifactClass::Authored,
            encoding: InputEncoding::Utf8,
            markers: MarkerReview {
                sqlcmd_variables: MarkerStatus::ReviewedAbsent,
                flyway_placeholders: MarkerStatus::ReviewedAbsent,
                jinja_dbt_markers: MarkerStatus::ReviewedAbsent,
            },
            batch_context: BatchContext::None,
            preprocessing: Vec::new(),
            classification_reason: None,
        }
    }
    fn manifest(commit: &str, files: Vec<ManifestFile>) -> CorpusManifest {
        CorpusManifest {
            schema_version: 1,
            expected_commit: commit.to_owned(),
            files,
        }
    }

    fn private_diagnostic(path: &str, message: &str) -> PrivateDiagnostic {
        PrivateDiagnostic {
            path: path.to_owned(),
            dialect: "mssql",
            kind: ParseErrorKind::SyntaxError,
            detail: ParseDiagnostic {
                message: message.to_owned(),
                position: Some(Position { line: 1, column: 1 }),
                message_truncated: false,
            },
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("set synthetic path permissions");
    }

    #[test]
    fn git_commands_clear_repository_redirects_and_sink_trace_output() {
        let command = git_command(Path::new("."));
        assert!(
            GIT_TRACE_ENV_TO_SINK.contains(&"GIT_TRACE_PACKFILE"),
            "packfile trace output was not included in the sink list"
        );
        assert!(
            GIT_TRACE_ENV_TO_SINK.contains(&"GIT_TRACE_PERFORMANCE"),
            "performance trace output was not included in the sink list"
        );
        for &name in GIT_ENV_TO_CLEAR {
            assert!(
                command
                    .get_envs()
                    .any(|(key, value)| { key == std::ffi::OsStr::new(name) && value.is_none() }),
                "Git environment override {name} was not cleared"
            );
        }
        for &name in GIT_TRACE_ENV_TO_SINK {
            assert!(
                command.get_envs().any(|(key, value)| {
                    key == std::ffi::OsStr::new(name)
                        && value == Some(std::ffi::OsStr::new(git_null_device()))
                }),
                "Git trace output was not directed to the null device"
            );
        }
    }

    #[test]
    fn private_diagnostic_encoding_is_single_line_json_without_source_sql() {
        let diagnostic = PrivateDiagnostic {
            path: "nested/name\nfile.sql".to_owned(),
            dialect: "mssql",
            kind: ParseErrorKind::SyntaxError,
            detail: ParseDiagnostic {
                message: "unexpected token\nmore detail".to_owned(),
                position: Some(Position { line: 2, column: 3 }),
                message_truncated: false,
            },
        };
        let encoded = encode_private_diagnostic(&diagnostic).expect("encode diagnostic");
        assert!(!encoded.contains(&b'\n'));
        assert!(!encoded
            .windows(b"SYNTHETIC_PRIVATE_SQL_SENTINEL".len())
            .any(|window| window == b"SYNTHETIC_PRIVATE_SQL_SENTINEL"));

        let record: serde_json::Value =
            serde_json::from_slice(&encoded).expect("decode encoded diagnostic");
        let fields = record.as_object().expect("diagnostic object");
        assert_eq!(fields.len(), 7);
        assert_eq!(record["path"], "nested/name\nfile.sql");
        assert_eq!(record["dialect"], "mssql");
        assert_eq!(record["line"], 2);
        assert_eq!(record["column"], 3);
        assert!(!fields.contains_key("sql"));
    }

    #[test]
    fn private_report_opt_in_requires_an_absolute_file_path() {
        assert_eq!(
            parse_private_report_path(PathBuf::from("/owner-only/diagnostics.jsonl")),
            Ok(PathBuf::from("/owner-only/diagnostics.jsonl"))
        );
        assert!(matches!(
            parse_private_report_path(PathBuf::from("diagnostics.jsonl")),
            Err("private diagnostic report path is invalid")
        ));
        assert!(matches!(
            parse_private_report_path(PathBuf::from("/")),
            Err("private diagnostic report path is invalid")
        ));
    }

    #[test]
    fn parser_diagnostics_are_captured_only_when_requested() {
        let classification = default_classification(Dialect::Mssql);
        let sql = "SELECT FROM;";
        assert!(matches!(
            parse_classified_sql_with_diagnostics(sql, classification, false),
            Err(ParseAttemptError::Parser {
                diagnostic: None,
                ..
            })
        ));
        match parse_classified_sql_with_diagnostics(sql, classification, true) {
            Err(ParseAttemptError::Parser {
                diagnostic: Some(diagnostic),
                ..
            }) => {
                assert!(!diagnostic.message.is_empty());
                assert!(diagnostic.message.len() <= HARD_MAX_PRIVATE_DIAGNOSTIC_MESSAGE_BYTES);
            }
            _ => panic!("synthetic parse failure did not produce a private diagnostic"),
        }
    }

    #[test]
    fn dialect_names_round_trip() {
        for d in [
            Dialect::Generic,
            Dialect::Ansi,
            Dialect::Bigquery,
            Dialect::Clickhouse,
            Dialect::Databricks,
            Dialect::Duckdb,
            Dialect::Hive,
            Dialect::Mssql,
            Dialect::Mysql,
            Dialect::Oracle,
            Dialect::Postgres,
            Dialect::Redshift,
            Dialect::Snowflake,
            Dialect::Sqlite,
        ] {
            assert_eq!(parse_dialect(dialect_name(d)), Ok(d));
        }
        assert!(parse_dialect("unknown").is_err());
    }

    #[test]
    fn completion_report_contains_aggregate_fields_only() {
        let mut summary = Summary {
            completed: 2,
            parsed: 1,
            parser_errors: 1,
            statements: 3,
            fallback_used: 0,
            syntax_errors: 1,
            missing_clause_errors: 0,
            unexpected_eof_errors: 0,
            unsupported_feature_errors: 0,
            lexer_errors: 0,
            ..Summary::default()
        };
        summary.dialect_counts.insert("mssql", 1);
        summary.dialect_counts.insert("postgres", 1);
        summary.standalone_sql = 2;
        summary.authored_files = 2;

        let report = format_summary(
            "0123456789abcdef0123456789abcdef01234567",
            2,
            42,
            17,
            &summary,
        );
        assert!(report.contains(
            "dialects=mssql:1,postgres:1 tracked_files=2 tracked_bytes=42 elapsed_ms=17"
        ));
        assert!(report.contains("parsed=1 parser_errors=1 input_errors=0"));
        assert!(report.contains("utf8_bom_files=0"));
        assert!(!report.contains("filename"));
        assert!(!report.contains("diagnostic"));
    }

    #[test]
    fn aggregate_summary_rejects_inconsistent_dimensions() {
        let mut summary = Summary {
            completed: 1,
            parsed: 1,
            standalone_sql: 1,
            authored_files: 1,
            ..Summary::default()
        };
        summary.dialect_counts.insert("mssql", 1);
        assert!(validate_summary(&summary).is_ok());

        summary.dialect_counts.insert("postgres", 1);
        assert!(matches!(
            validate_summary(&summary),
            Err("aggregate classification counts are inconsistent")
        ));
    }

    #[test]
    fn manifest_must_match_every_tracked_sql_path_exactly_once() {
        let repo = repo(&[("one.sql", b"SELECT 1;"), ("two.sql", b"SELECT 2;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let manifest_with_one = manifest(&commit, vec![manifest_file("one.sql", "mssql")]);
        assert!(apply_manifest(
            tracked_sql_files(&repo.0, commit.trim(), config())
                .expect("inventory")
                .0,
            manifest_with_one,
        )
        .is_err());

        let duplicate = manifest(
            &commit,
            vec![
                manifest_file("one.sql", "mssql"),
                manifest_file("one.sql", "postgres"),
            ],
        );
        assert!(apply_manifest(
            tracked_sql_files(&repo.0, commit.trim(), config())
                .expect("inventory")
                .0,
            duplicate,
        )
        .is_err());

        let extra = manifest(
            &commit,
            vec![
                manifest_file("one.sql", "mssql"),
                manifest_file("two.sql", "mssql"),
                manifest_file("not-tracked.sql", "mssql"),
            ],
        );
        assert!(apply_manifest(
            tracked_sql_files(&repo.0, commit.trim(), config())
                .expect("inventory")
                .0,
            extra,
        )
        .is_err());
    }

    #[test]
    fn manifest_paths_must_be_safe_relative_git_paths() {
        let repo = repo(&[("one.sql", b"SELECT 1;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let invalid_paths = ["../one.sql", "/one.sql", "folder/../one.sql"];
        for path in invalid_paths {
            let result = apply_manifest(
                tracked_sql_files(&repo.0, commit.trim(), config())
                    .expect("inventory")
                    .0,
                manifest(&commit, vec![manifest_file(path, "mssql")]),
            );
            assert!(result.is_err(), "unsafe manifest path accepted");
        }
    }

    #[test]
    fn private_manifest_path_inside_workspace_is_rejected() {
        let workspace = workspace_root().expect("workspace root");
        let in_workspace = workspace.join("docs/guides/private-corpus-parser-harness.md");
        assert!(matches!(
            load_manifest(&in_workspace, &workspace),
            Err("corpus manifest must be outside the FlowScope workspace")
        ));
    }

    #[test]
    fn manifest_json_requires_all_fields_and_rejects_unknown_fields() {
        let valid = r#"{
            "schema_version": 1,
            "expected_commit": "0123456789abcdef0123456789abcdef01234567",
            "files": [{
                "path": "example.sql",
                "dialect": "mssql",
                "input_class": "batch_script",
                "artifact_class": "authored",
                "encoding": "utf8",
                "markers": {
                    "sqlcmd_variables": "reviewed_absent",
                    "flyway_placeholders": "reviewed_absent",
                    "jinja_dbt_markers": "reviewed_absent"
                },
                "batch_context": "mssql_go_batches",
                "preprocessing": [],
                "classification_reason": null
            }]
        }"#;
        let manifest: CorpusManifest =
            serde_json::from_str(valid).expect("documented manifest shape");
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.files.len(), 1);

        let missing_required = valid.replace("\"dialect\": \"mssql\",", "");
        assert!(serde_json::from_str::<CorpusManifest>(&missing_required).is_err());
        let unknown = valid.replace(
            "\"preprocessing\": []",
            "\"preprocessing\": [], \"private_note\": \"marker\"",
        );
        assert!(serde_json::from_str::<CorpusManifest>(&unknown).is_err());
    }

    #[test]
    fn manifest_reader_stops_at_the_hard_size_limit() {
        let oversized = vec![b' '; HARD_MAX_MANIFEST_BYTES as usize + 1];
        assert!(matches!(
            read_bounded_manifest(std::io::Cursor::new(oversized)),
            Err("corpus manifest exceeds the supported size or file type")
        ));
    }

    #[test]
    fn exceptional_classification_requires_a_private_nonempty_reason() {
        let mut entry = manifest_file("sample.sql", "mssql");
        entry.input_class = InputClass::IntentionalFragment;
        let inventory = vec![TrackedSqlFile {
            path: PathBuf::from("sample.sql"),
            object_id: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            bytes: 0,
            classification: None,
        }];
        assert!(matches!(
            apply_manifest(
                inventory,
                manifest("0123456789abcdef0123456789abcdef01234567", vec![entry]),
            ),
            Err("corpus manifest classification exception has no rationale")
        ));
    }

    #[test]
    fn manifest_commit_must_match_the_pinned_snapshot() {
        let repo = repo(&[("one.sql", b"SELECT 1;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let result = run_pinned_classified_corpus(
            &repo.0,
            commit.trim(),
            manifest(
                "0123456789abcdef0123456789abcdef01234567",
                vec![manifest_file("one.sql", "mssql")],
            ),
            config(),
            &repo.1,
            None,
        );
        assert!(matches!(
            result,
            Err("corpus manifest commit does not match the pinned commit")
        ));
    }

    #[test]
    fn pinned_checkout_validation_requires_a_nonoverlapping_repository_root() {
        let repo = repo(&[("one.sql", b"SELECT 1;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let (_, verified_commit) =
            verify_pinned_checkout(&repo.0, commit.trim(), &repo.1).expect("pinned repo root");
        assert_eq!(verified_commit, commit.trim());

        let workspace = workspace_root().expect("FlowScope workspace root");
        assert!(matches!(
            verify_pinned_checkout(&repo.0, commit.trim(), &workspace),
            Err("corpus repository must be outside and separate from the workspace")
        ));

        let containing_workspace = repo.0.parent().expect("synthetic test area");
        assert!(matches!(
            verify_pinned_checkout(&repo.0, commit.trim(), containing_workspace),
            Err("corpus repository must be outside and separate from the workspace")
        ));

        let nested_workspace = repo.0.join("nested-workspace");
        fs::create_dir(&nested_workspace).expect("create nested workspace");
        assert!(matches!(
            verify_pinned_checkout(&repo.0, commit.trim(), &nested_workspace),
            Err("corpus repository must be outside and separate from the workspace")
        ));

        let nested_directory = repo.0.join("nested");
        fs::create_dir(&nested_directory).expect("create repository subdirectory");
        assert!(matches!(
            verify_pinned_checkout(&nested_directory, commit.trim(), &repo.1),
            Err("corpus directory must be the repository root")
        ));
    }

    #[test]
    fn classified_run_uses_each_file_dialect_and_counts_input_classes() {
        let repo = repo(&[
            ("sqlserver.sql", b"SELECT TOP (1) 1;"),
            ("postgres.sql", b"SELECT 2::INTEGER;"),
        ]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let mut postgres = manifest_file("postgres.sql", "postgres");
        postgres.input_class = InputClass::StandaloneSql;
        postgres.artifact_class = ArtifactClass::Generated;
        postgres.markers.sqlcmd_variables = MarkerStatus::ReviewedPresent;
        postgres.markers.flyway_placeholders = MarkerStatus::Unreviewed;
        postgres.classification_reason = Some("synthetic marker classification".to_owned());

        let mut sqlserver = manifest_file("sqlserver.sql", "mssql");
        sqlserver.input_class = InputClass::BatchScript;
        sqlserver.artifact_class = ArtifactClass::Unknown;
        sqlserver.markers.jinja_dbt_markers = MarkerStatus::ReviewedPresent;
        sqlserver.batch_context = BatchContext::MssqlGoBatches;
        sqlserver.classification_reason = Some("synthetic context classification".to_owned());

        let (actual_commit, tracked_files, tracked_bytes, summary) = run_pinned_classified_corpus(
            &repo.0,
            commit.trim(),
            manifest(commit.trim(), vec![postgres, sqlserver]),
            config(),
            &repo.1,
            None,
        )
        .expect("classified run");

        assert_eq!(actual_commit, commit.trim());
        assert_eq!(tracked_files, 2);
        assert_eq!(
            tracked_bytes,
            (b"SELECT TOP (1) 1;".len() + b"SELECT 2::INTEGER;".len()) as u64
        );
        assert_eq!(
            (summary.parsed, summary.parser_errors, summary.input_errors),
            (2, 0, 0)
        );
        assert_eq!(summary.dialect_counts.get("mssql"), Some(&1));
        assert_eq!(summary.dialect_counts.get("postgres"), Some(&1));
        assert_eq!(
            (summary.batch_scripts, summary.intentional_fragments),
            (1, 0)
        );
        assert_eq!(
            (
                summary.authored_files,
                summary.generated_files,
                summary.unknown_artifact_files
            ),
            (0, 1, 1)
        );
        assert_eq!(
            (
                summary.sqlcmd_reviewed_present,
                summary.flyway_reviewed_present,
                summary.jinja_reviewed_present
            ),
            (1, 0, 1)
        );
        assert_eq!(summary.unreviewed_marker_files, 1);
        assert_eq!(
            (summary.mssql_go_batches, summary.external_context_required),
            (1, 0)
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_report_refuses_public_workspace_paths_without_creating_a_file() {
        let repo = repo(&[("nested/syntax.sql", b"SELECT FROM;")]);
        let report_path = repo
            .0
            .parent()
            .expect("synthetic test area")
            .join("diagnostics.jsonl");
        let workspace = workspace_root().expect("FlowScope workspace root");
        assert!(matches!(
            validate_private_report_path(&report_path, &workspace, &repo.0),
            Err("private diagnostic report must be separate from the workspace and corpus")
        ));
        assert!(!report_path.exists());

        let public_message =
            "private diagnostic report must be separate from the workspace and corpus";
        assert!(!public_message.contains(&report_path.to_string_lossy().to_string()));
        assert!(!public_message.contains("SELECT FROM"));
    }

    #[cfg(unix)]
    #[test]
    fn private_report_rejects_public_overlapping_and_existing_targets() {
        use std::os::unix::fs::PermissionsExt;

        let repo = repo(&[("one.sql", b"SELECT 1;")]);
        let area = repo.0.parent().expect("synthetic test area");
        let output_dir = area.join("private-output");
        fs::create_dir(&output_dir).expect("create private report directory");
        set_mode(&output_dir, 0o700);
        let report_path = output_dir.join("diagnostics.jsonl");
        let report_dir_mode = fs::metadata(&output_dir)
            .expect("private report directory metadata")
            .permissions()
            .mode()
            & 0o777;

        let separate_path = validate_private_report_path(&report_path, &repo.1, &repo.0);
        if report_dir_mode & 0o077 == 0 {
            assert!(separate_path.is_ok());
        } else {
            assert!(matches!(
                separate_path,
                Err("private diagnostic report directory must be owner-only")
            ));
        }
        assert!(matches!(
            validate_private_report_path(
                &report_path,
                &workspace_root().expect("FlowScope workspace root"),
                &repo.0
            ),
            Err("private diagnostic report must be separate from the workspace and corpus")
        ));
        assert!(matches!(
            validate_private_report_path(Path::new("relative.jsonl"), &repo.1, &repo.0),
            Err("private diagnostic report path must be absolute")
        ));

        assert!(matches!(
            validate_private_report_path(&repo.0.join("inside.jsonl"), &repo.1, &repo.0),
            Err("private diagnostic report must be separate from the workspace and corpus")
        ));
        assert!(matches!(
            validate_private_report_path(&repo.1.join("inside.jsonl"), &repo.1, &repo.0),
            Err("private diagnostic report must be separate from the workspace and corpus")
        ));
        assert!(matches!(
            validate_private_report_path(&area.join("ancestor.jsonl"), &repo.1, &repo.0),
            Err("private diagnostic report must be separate from the workspace and corpus")
        ));

        let public_dir = area.join("public-output");
        fs::create_dir(&public_dir).expect("create public report directory");
        set_mode(&public_dir, 0o755);
        assert!(matches!(
            validate_private_report_path(&public_dir.join("diagnostics.jsonl"), &repo.1, &repo.0),
            Err("private diagnostic report directory must be owner-only")
        ));

        let existing_file = repo.0.join("one.sql");
        let existing_contents = fs::read(&existing_file).expect("read synthetic SQL fixture");
        assert!(matches!(
            create_private_report_file(&existing_file),
            Err("private diagnostic report could not be created")
        ));
        assert_eq!(
            fs::read(&existing_file).expect("existing file remains unchanged"),
            existing_contents
        );

        let link = area.join("existing-report-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&existing_file, &link).expect("create report symlink");
        assert!(matches!(
            create_private_report_file(&link),
            Err("private diagnostic report could not be created")
        ));
        assert_eq!(
            fs::read(&existing_file).expect("symlink target remains unchanged"),
            existing_contents
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_report_disk_write_is_restricted_and_drop_removes_partial_output() {
        use std::os::unix::fs::PermissionsExt;

        let repo = TempRepo::new();
        let area = repo.0.parent().expect("synthetic test area");
        let output_dir = area.join("private-output");
        fs::create_dir(&output_dir).expect("create synthetic private output directory");
        set_mode(&output_dir, 0o700);
        let directory_mode = fs::metadata(&output_dir)
            .expect("private output directory metadata")
            .permissions()
            .mode()
            & 0o777;
        let report_path = output_dir.join("diagnostics.jsonl");

        let report_result = PrivateReportWriter::create(&report_path, &repo.1, &repo.0);
        if directory_mode & 0o077 != 0 {
            assert!(matches!(
                report_result,
                Err("private diagnostic report directory must be owner-only")
            ));
            assert!(!report_path.exists());
            return;
        }

        let mut report = match report_result {
            Ok(report) => report,
            Err("private diagnostic report permissions could not be restricted") => {
                assert!(!report_path.exists());
                return;
            }
            Err(_) => panic!("owner-only synthetic report destination was unexpectedly refused"),
        };
        report
            .write(&private_diagnostic(
                "nested/synthetic.sql",
                "synthetic parser diagnostic",
            ))
            .expect("write synthetic private diagnostic");
        report.finish().expect("finish private diagnostic report");

        assert_eq!(
            fs::metadata(&report_path)
                .expect("private report metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let contents = fs::read_to_string(&report_path).expect("read finished private report");
        assert_eq!(contents.lines().count(), 1);
        let record: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("parse private JSONL record");
        assert_eq!(record["path"], "nested/synthetic.sql");
        assert_eq!(record["dialect"], "mssql");
        assert_eq!(record["kind"], "syntax_error");
        assert_eq!(record["message"], "synthetic parser diagnostic");
        assert_eq!(record["line"], 1);
        assert_eq!(record["column"], 1);

        let partial_path = output_dir.join("unfinished.jsonl");
        let mut partial = PrivateReportWriter::create(&partial_path, &repo.1, &repo.0)
            .expect("create second private report");
        partial
            .write(&private_diagnostic(
                "nested/unfinished.sql",
                "synthetic unfinished diagnostic",
            ))
            .expect("write unfinished synthetic diagnostic");
        assert!(partial_path.exists());
        drop(partial);
        assert!(!partial_path.exists());
    }

    #[test]
    fn private_report_encoder_bounds_messages_and_total_size() {
        let detail = parse_diagnostic(ParseError::new("é".repeat(3_000)));
        assert!(detail.message_truncated);
        assert!(detail.message.len() <= HARD_MAX_PRIVATE_DIAGNOSTIC_MESSAGE_BYTES);

        let diagnostic = private_diagnostic("one.sql", "synthetic parser message");
        let mut output = Vec::new();
        let mut written_bytes = 0;
        write_private_diagnostic(&mut output, &mut written_bytes, &diagnostic)
            .expect("write in-memory diagnostic");
        assert_eq!(written_bytes, output.len() as u64);
        assert_eq!(output.last(), Some(&b'\n'));

        let before = output.clone();
        written_bytes = HARD_MAX_PRIVATE_REPORT_BYTES;
        assert!(matches!(
            write_private_diagnostic(&mut output, &mut written_bytes, &diagnostic),
            Err("private diagnostic report exceeds the supported size")
        ));
        assert_eq!(output, before);
        assert_eq!(written_bytes, HARD_MAX_PRIVATE_REPORT_BYTES);
    }

    #[test]
    fn batch_script_parse_only_mode_uses_go_ranges_without_analysis() {
        let mut classification = default_classification(Dialect::Mssql);
        classification.input_class = InputClass::BatchScript;
        classification.batch_context = BatchContext::MssqlGoBatches;
        let result = parse_classified_sql("SELECT 1;\nGO 2 -- repeat\nSELECT 2;", classification)
            .expect("each batch statement should parse");
        assert_eq!(result.0, 3);
    }

    #[test]
    fn parse_only_mode_uses_mssql_analysis_adapters() {
        let classification = default_classification(Dialect::Mssql);
        let openrowset = concat!(
            "SELECT src.id FROM OPENROWSET(",
            "BULK 'path', FORMAT = 'CSV'",
            ") WITH (id INT 1) AS src"
        );
        let result = parse_classified_sql(openrowset, classification)
            .expect("Synapse OPENROWSET WITH should use the analysis input adapter");
        assert_eq!(result, (1, true));

        let metadata = concat!(
            "CREATE EXTERNAL FILE FORMAT csv WITH (",
            "FORMAT_TYPE = DELIMITEDTEXT, ",
            "FORMAT_OPTIONS (FIELD_TERMINATOR = ','))"
        );
        assert_eq!(
            parse_classified_sql(metadata, classification)
                .expect("valid external metadata DDL should count as a statement"),
            (1, false)
        );
        let mixed = format!("{metadata};\nSELECT 1;");
        assert_eq!(
            parse_classified_sql(&mixed, classification)
                .expect("metadata DDL and ordinary SQL should both parse")
                .0,
            2
        );
        let metadata_after_query = format!("SELECT 1;\n{metadata};");
        assert_eq!(
            parse_classified_sql(&metadata_after_query, classification)
                .expect("metadata DDL after ordinary SQL should both parse")
                .0,
            2
        );
    }

    #[test]
    fn malformed_mssql_adapter_inputs_remain_parser_errors_with_diagnostics() {
        let classification = default_classification(Dialect::Mssql);
        let malformed_openrowset =
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH () AS src";
        assert!(matches!(
            parse_classified_sql_with_diagnostics(malformed_openrowset, classification, true),
            Err(ParseAttemptError::Parser {
                diagnostic: Some(_),
                ..
            })
        ));

        let malformed_metadata = "CREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = CSV)";
        match parse_classified_sql_with_diagnostics(malformed_metadata, classification, true) {
            Err(ParseAttemptError::Parser {
                kind: ParseErrorKind::UnsupportedFeature,
                statements: 0,
                diagnostic: Some(diagnostic),
                ..
            }) => {
                assert!(!diagnostic.message.is_empty());
                assert!(diagnostic.position.is_some());
            }
            _ => panic!("unsupported metadata grammar must retain its parse diagnostic"),
        }

        let malformed_after_query =
            "SELECT 1;\nCREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = CSV);";
        assert!(matches!(
            parse_classified_sql(&malformed_after_query, classification),
            Err(ParseAttemptError::Parser {
                kind: ParseErrorKind::UnsupportedFeature,
                ..
            })
        ));
    }

    #[test]
    fn batch_script_keeps_first_error_and_counts_later_statements() {
        let mut classification = default_classification(Dialect::Mssql);
        classification.input_class = InputClass::BatchScript;
        classification.batch_context = BatchContext::MssqlGoBatches;
        let sql = concat!(
            "SELECT 1;\nGO\n",
            "CREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = CSV);\nGO\n",
            "SELECT 2;\nGO\n",
            "SELECT FROM;"
        );
        match parse_classified_sql_with_diagnostics(sql, classification, true) {
            Err(ParseAttemptError::Parser {
                kind: ParseErrorKind::UnsupportedFeature,
                statements: 2,
                diagnostic: Some(diagnostic),
                ..
            }) => {
                assert!(!diagnostic.message.is_empty());
                assert!(diagnostic.position.is_some());
            }
            _ => panic!("the first metadata error and later statement counts must be retained"),
        }
    }

    #[test]
    fn batch_diagnostic_positions_are_mapped_to_the_original_file() {
        let mut classification = default_classification(Dialect::Mssql);
        classification.input_class = InputClass::BatchScript;
        classification.batch_context = BatchContext::MssqlGoBatches;
        let sql =
            "SELECT 1;\nGO\nCREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = CSV);\nSELECT 2;";
        let token_offset =
            sql.find("FORMAT_TYPE = CSV").expect("format option") + "FORMAT_TYPE = ".len();
        let line_start = sql[..token_offset]
            .rfind('\n')
            .map_or(0, |offset| offset + 1);
        let expected_column = sql[line_start..token_offset].chars().count() + 1;

        match parse_classified_sql_with_diagnostics(sql, classification, true) {
            Err(ParseAttemptError::Parser {
                diagnostic: Some(diagnostic),
                ..
            }) => assert_eq!(
                diagnostic.position,
                Some(Position {
                    line: 3,
                    column: expected_column,
                })
            ),
            _ => panic!("batch parser failure did not retain its source position"),
        }
    }

    #[test]
    fn standalone_and_non_mssql_inputs_do_not_use_mssql_batch_adapters() {
        let sql = "SELECT 1;\nGO 2 -- repeat\nSELECT 2;";
        let standalone = default_classification(Dialect::Mssql);
        assert!(matches!(
            parse_classified_sql(sql, standalone),
            Err(ParseAttemptError::Parser { statements: 0, .. })
        ));

        let mut batch = standalone;
        batch.input_class = InputClass::BatchScript;
        batch.batch_context = BatchContext::MssqlGoBatches;
        assert_eq!(
            parse_classified_sql(sql, batch)
                .expect("MSSQL batch classification should recognize GO")
                .0,
            3
        );

        let mut postgres_batch = default_classification(Dialect::Postgres);
        postgres_batch.input_class = InputClass::BatchScript;
        assert!(matches!(
            parse_classified_sql("SELECT 1;\nGO\nSELECT 2;", postgres_batch),
            Err(ParseAttemptError::Parser { statements: 1, .. })
        ));

        let openrowset =
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH (id INT 1) AS src";
        assert!(matches!(
            parse_classified_sql(openrowset, default_classification(Dialect::Generic)),
            Ok((_, false)) | Err(ParseAttemptError::Parser { .. })
        ));
    }

    #[test]
    fn batch_script_parse_error_keeps_successful_batch_statement_counts() {
        let mut classification = default_classification(Dialect::Mssql);
        classification.input_class = InputClass::BatchScript;
        classification.batch_context = BatchContext::MssqlGoBatches;
        let result =
            parse_classified_sql("SELECT 1;\nGO\nSELECT FROM;\nGO\nSELECT 2;", classification);
        assert!(matches!(
            result,
            Err(ParseAttemptError::Parser { statements: 2, .. })
        ));
    }

    #[test]
    fn standalone_parse_error_counts_independently_valid_statements() {
        let classification = default_classification(Dialect::Mssql);
        let sql = "SELECT 1;\nSELECT FROM;\nSELECT 2;";
        assert!(matches!(
            parse_classified_sql(sql, classification),
            Err(ParseAttemptError::Parser {
                statements: 2,
                fallback_used: false,
                ..
            })
        ));
    }

    #[test]
    fn batch_split_expansion_limits_fail_as_input_errors() {
        let mut classification = default_classification(Dialect::Mssql);
        classification.input_class = InputClass::BatchScript;
        classification.batch_context = BatchContext::MssqlGoBatches;

        assert!(matches!(
            parse_classified_sql("SELECT 1;\nGO 1001\n", classification),
            Err(ParseAttemptError::Input)
        ));

        let repeated_batches = "SELECT 1;\nGO 1000\n".repeat(101);
        assert!(matches!(
            parse_classified_sql(&repeated_batches, classification),
            Err(ParseAttemptError::Input)
        ));
    }

    #[test]
    fn batch_context_must_match_dialect_and_input_class() {
        let repo = repo(&[("sample.sql", b"SELECT 1;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let mut entry = manifest_file("sample.sql", "postgres");
        entry.batch_context = BatchContext::MssqlGoBatches;
        entry.classification_reason = Some("synthetic inconsistent classification".to_owned());
        let result = apply_manifest(
            tracked_sql_files(&repo.0, commit.trim(), config())
                .expect("inventory")
                .0,
            manifest(commit.trim(), vec![entry]),
        );
        assert!(matches!(
            result,
            Err("MSSQL GO batch context requires an MSSQL batch-script classification")
        ));
    }

    #[test]
    fn unknown_and_invalid_utf8_encodings_are_input_errors_not_parse_errors() {
        let repo = repo(&[
            ("invalid.sql", b"SELECT \xff;"),
            ("invalid-bom.sql", b"\xef\xbb\xbfSELECT \xff;"),
            ("unknown.sql", b"SELECT 1;"),
        ]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let mut invalid_utf8 = manifest_file("invalid.sql", "mssql");
        invalid_utf8.encoding = InputEncoding::Utf8;
        let mut unknown = manifest_file("unknown.sql", "postgres");
        unknown.encoding = InputEncoding::Unknown;
        unknown.classification_reason = Some("synthetic unknown-encoding case".to_owned());
        let mut invalid_bom = manifest_file("invalid-bom.sql", "mssql");
        invalid_bom.encoding = InputEncoding::Utf8Bom;
        let (_, _, _, summary) = run_pinned_classified_corpus(
            &repo.0,
            commit.trim(),
            manifest(commit.trim(), vec![invalid_utf8, invalid_bom, unknown]),
            config(),
            &repo.1,
            None,
        )
        .expect("input errors remain measurable");
        assert_eq!(
            (
                summary.completed,
                summary.parsed,
                summary.parser_errors,
                summary.input_errors
            ),
            (3, 0, 0, 3)
        );
        assert_eq!(summary.utf8_bom_files, 1);
    }

    #[test]
    fn utf8_bom_must_be_explicitly_classified_and_is_not_stripped() {
        let repo = repo(&[
            ("bom.sql", b"\xef\xbb\xbfSELECT 1;"),
            ("plain.sql", b"SELECT 2;"),
        ]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let mut bom = manifest_file("bom.sql", "mssql");
        bom.encoding = InputEncoding::Utf8Bom;
        bom.classification_reason = Some("synthetic BOM inventory case".to_owned());
        let mut misclassified = manifest_file("plain.sql", "mssql");
        misclassified.encoding = InputEncoding::Utf8Bom;
        misclassified.classification_reason = Some("synthetic BOM mismatch".to_owned());
        let (_, _, _, summary) = run_pinned_classified_corpus(
            &repo.0,
            commit.trim(),
            manifest(commit.trim(), vec![bom, misclassified]),
            config(),
            &repo.1,
            None,
        )
        .expect("BOM classification should complete");
        assert_eq!(summary.utf8_bom_files, 1);
        assert_eq!(summary.input_errors, 1);
        assert_eq!(summary.completed, 2);
    }

    #[test]
    fn unreviewed_preprocessing_is_rejected_without_transforming_source() {
        let repo = repo(&[("one.sql", b"SELECT 1;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let mut entry = manifest_file("one.sql", "mssql");
        entry.preprocessing.push("replace_placeholders".to_owned());
        let result = apply_manifest(
            tracked_sql_files(&repo.0, commit.trim(), config())
                .expect("inventory")
                .0,
            manifest(&commit, vec![entry]),
        );
        assert!(matches!(
            result,
            Err("corpus manifest requests unsupported preprocessing")
        ));
    }
    #[test]
    fn limits_are_positive_and_hard_capped() {
        assert_eq!(parse_positive_limit("4", 16), Ok(4));
        assert!(parse_positive_limit("17", 16).is_err());
        assert!(parse_positive_limit("0", 16).is_err());
        assert_eq!(parse_byte_limit("1024", 2048), Ok(1024));
        assert!(parse_byte_limit("2049", 2048).is_err());
        assert!(parse_byte_limit("0", 2048).is_err());
    }
    #[test]
    fn inventory_is_exact_sorted_and_excludes_untracked_or_non_sql_files() {
        let repo = repo(&[
            ("z.sql", b"SELECT 2;"),
            ("a/nested.sql", b"SELECT 1;"),
            ("note.txt", b"not SQL"),
        ]);
        fs::write(repo.0.join("untracked.sql"), b"SELECT 3;").expect("write untracked fixture");
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let (files, bytes) =
            tracked_sql_files(&repo.0, commit.trim(), config()).expect("inventory");
        let paths: Vec<_> = files
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths, ["a/nested.sql", "z.sql"]);
        assert_eq!(bytes, (b"SELECT 1;".len() + b"SELECT 2;".len()) as u64);
    }
    #[test]
    fn repeated_pinned_runs_have_equivalent_aggregate_results() {
        let repo = repo(&[
            ("one.sql", b"SELECT 1;"),
            ("nested/two.sql", b"SELECT FROM;"),
            ("note.txt", b"not SQL"),
        ]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let one = run_pinned_corpus(&repo.0, commit.trim(), Dialect::Mssql, config(), &repo.1)
            .expect("first run");
        let two = run_pinned_corpus(&repo.0, commit.trim(), Dialect::Mssql, config(), &repo.1)
            .expect("second run");
        assert_eq!(one.0, two.0);
        assert_eq!(one.1, Dialect::Mssql);
        assert_eq!(one.2, 2);
        assert_eq!(one.3, (b"SELECT 1;".len() + b"SELECT FROM;".len()) as u64);
        assert_eq!(one.4, two.4);
        assert_eq!(
            (one.4.parsed, one.4.parser_errors, one.4.statements),
            (1, 1, 1)
        );
        assert_eq!(
            format_summary(&one.0, one.2, one.3, 17, &one.4),
            format_summary(&two.0, two.2, two.3, 17, &two.4)
        );
    }

    #[test]
    fn pinned_run_ignores_working_tree_edits_and_untracked_sql() {
        let repo = repo(&[("one.sql", b"SELECT 1;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        repo.write("one.sql", b"SELECT FROM;");
        repo.write("untracked.sql", b"SELECT FROM;");

        let (actual_commit, _, tracked_files, tracked_bytes, summary) =
            run_pinned_corpus(&repo.0, commit.trim(), Dialect::Mssql, config(), &repo.1)
                .expect("pinned blob run");
        assert_eq!(actual_commit, commit.trim());
        assert_eq!(tracked_files, 1);
        assert_eq!(tracked_bytes, b"SELECT 1;".len() as u64);
        assert_eq!(
            (summary.parsed, summary.parser_errors, summary.statements),
            (1, 0, 1)
        );
    }
    #[test]
    fn file_count_per_file_and_total_byte_caps_are_enforced() {
        let repo = repo(&[("one.sql", b"SELECT 1;"), ("two.sql", b"SELECT 2;")]);
        let commit = git(&repo.0, &["rev-parse", "HEAD"]);
        let mut cfg = config();
        cfg.max_files = 1;
        assert!(tracked_sql_files(&repo.0, commit.trim(), cfg).is_err());
        cfg.max_files = 10;
        cfg.max_file_bytes = 4;
        assert!(tracked_sql_files(&repo.0, commit.trim(), cfg).is_err());
        cfg.max_file_bytes = 1024;
        cfg.max_total_bytes = 10;
        assert!(tracked_sql_files(&repo.0, commit.trim(), cfg).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn tracked_sql_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let repo = TempRepo::new();
        let target = repo.0.join("target.sql");
        fs::write(&target, b"SELECT 1;").expect("write target");
        symlink(&target, repo.0.join("linked.sql")).expect("create symlink");
        let commit = repo.commit();
        assert!(tracked_sql_files(&repo.0, commit.trim(), config()).is_err());
    }
    #[test]
    fn incorrect_commit_pin_is_rejected() {
        let repo = repo(&[("sample.sql", b"SELECT 1;")]);
        assert!(matches!(
            run_pinned_corpus(
                &repo.0,
                "0123456789abcdef0123456789abcdef01234567",
                Dialect::Mssql,
                config(),
                &repo.1
            ),
            Err("repository commit does not match the pinned commit")
        ));
    }
}
