use crate::error::ParseError;
use crate::linter::document::{LintDocument, LintStatement};
use crate::linter::Linter;
use crate::types::*;
use sqlparser::ast::{CreateView, Statement};
use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;
#[cfg(feature = "tracing")]
use tracing::info_span;

/// Maximum SQL input size (10MB) to prevent memory exhaustion.
/// This matches the TypeScript validation limit.
const MAX_SQL_LENGTH: usize = 10 * 1024 * 1024;

mod complexity;
mod context;
pub(crate) mod cross_statement;
mod ddl;
mod descriptions;
mod diagnostics;
mod expression;
mod external_metadata;
mod functions;
mod global;
pub mod helpers;
mod input;
mod query;
pub(crate) mod schema_registry;
mod select_analyzer;
mod statements;
mod transform;
pub mod visitor;

use context::StatementContext;
use cross_statement::CrossStatementTracker;
use descriptions::DescriptionKey;
use helpers::{
    build_column_schemas_with_constraints, find_identifier_span, find_relation_occurrence_spans,
};
use input::{
    collect_statements, validate_analysis_input_sizes, StatementInput, StatementInputKind,
};
use schema_registry::SchemaRegistry;
use statements::{
    detect_dbt_model_materialization, extract_model_name, DbtMaterializationDetection,
    StatementSource,
};
use std::collections::HashMap;

// Re-export for use in other analyzer modules
pub(crate) use schema_registry::TableResolution;

/// Main entry point for SQL analysis
#[must_use]
pub fn analyze(request: &AnalyzeRequest) -> AnalyzeResult {
    if let Err(issue) = validate_analysis_input_sizes(request) {
        return AnalyzeResult::from_issue(*issue);
    }

    #[cfg(feature = "tracing")]
    let _span =
        info_span!("analyze_request", statement_count = %request.sql.matches(';').count() + 1)
            .entered();
    let mut analyzer = Analyzer::new(request);
    analyzer.analyze()
}

/// Split SQL into statement spans.
#[must_use]
pub fn split_statements(request: &StatementSplitRequest) -> StatementSplitResult {
    // Validate input size to prevent memory exhaustion
    if request.sql.len() > MAX_SQL_LENGTH {
        return StatementSplitResult::from_error(format!(
            "SQL exceeds maximum length of {} bytes ({} bytes provided)",
            MAX_SQL_LENGTH,
            request.sql.len()
        ));
    }

    match input::split_statement_spans_with_dialect(&request.sql, request.dialect) {
        Ok(statements) => StatementSplitResult {
            statements,
            error: None,
        },
        Err(()) => StatementSplitResult::from_error(
            "SQL input exceeds the supported MSSQL batch expansion limit",
        ),
    }
}

/// Parse-only summary returned by [`parse_only_sql_with_dialect_output`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOnlyOutput {
    /// Number of SQL or validated metadata statements parsed.
    pub statement_count: usize,
    /// Whether a dialect-specific parser compatibility adapter was used.
    pub parser_fallback_used: bool,
}

/// Parse SQL with the same input adapters used by analysis, without running analysis or lint.
///
/// Supported MSSQL external metadata statements each contribute one to
/// `statement_count`, even though they do not produce a SQL AST node.
pub fn parse_only_sql_with_dialect_output(
    sql: &str,
    dialect: Dialect,
) -> Result<ParseOnlyOutput, ParseError> {
    if matches!(dialect, Dialect::Mssql) {
        if let Ok(statement_ranges) = input::mssql_statement_ranges_without_go(sql) {
            if input::mssql_ranges_have_optional_separators(sql, &statement_ranges) {
                return parse_only_statement_ranges(sql, statement_ranges, dialect);
            }
        }
    }

    match input::parse_input_statement_with_dialect_output(sql, dialect) {
        Ok(output) => Ok(parse_only_output_summary(output)),
        Err(error) => {
            let primary_error = error.into_parse_error();
            if !matches!(dialect, Dialect::Mssql) {
                return Err(primary_error);
            }

            let Ok(statement_ranges) = input::mssql_statement_ranges_without_go(sql) else {
                return Err(primary_error);
            };
            if !input::statement_ranges_contain_external_metadata(sql, &statement_ranges) {
                return Err(primary_error);
            }

            parse_only_statement_ranges(sql, statement_ranges, dialect)
        }
    }
}

fn parse_only_statement_ranges(
    sql: &str,
    statement_ranges: Vec<std::ops::Range<usize>>,
    dialect: Dialect,
) -> Result<ParseOnlyOutput, ParseError> {
    let mut summary = ParseOnlyOutput {
        statement_count: 0,
        parser_fallback_used: false,
    };
    let mut first_error = None;
    for range in statement_ranges {
        let statement_sql = sql.get(range.clone()).ok_or_else(|| {
            ParseError::new("Could not read MSSQL statement source range")
                .with_dialect(dialect)
                .with_kind(crate::error::ParseErrorKind::SyntaxError)
        })?;
        match input::parse_input_statement_with_dialect_output(statement_sql, dialect) {
            Ok(output) => {
                let next = parse_only_output_summary(output);
                summary.statement_count += next.statement_count;
                summary.parser_fallback_used |= next.parser_fallback_used;
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(map_parse_error_from_statement_range(
                        sql,
                        statement_sql,
                        range.start,
                        error.into_parse_error(),
                    ));
                }
            }
        }
    }

    first_error.map_or(Ok(summary), Err)
}

fn map_parse_error_from_statement_range(
    source_sql: &str,
    statement_sql: &str,
    statement_offset: usize,
    mut error: ParseError,
) -> ParseError {
    if let Some(position) = error.position {
        if let Some(relative_offset) =
            helpers::line_col_to_offset(statement_sql, position.line, position.column)
        {
            if let Some(source_position) =
                input::offset_to_position(source_sql, statement_offset + relative_offset)
            {
                error.position = Some(source_position);
                if let Some(message_position) = error.message.rfind(" at Line:") {
                    error.message.truncate(message_position);
                }
            }
        }
    }
    error
}

fn parse_only_output_summary(output: input::InputParseOutput) -> ParseOnlyOutput {
    match output {
        input::InputParseOutput::ParsedSql(output) => ParseOnlyOutput {
            statement_count: output.statements.len(),
            parser_fallback_used: output.parser_fallback_used,
        },
        input::InputParseOutput::ExternalMetadata(_, parser_fallback_used) => ParseOnlyOutput {
            statement_count: 1,
            parser_fallback_used,
        },
    }
}

/// Internal analyzer state.
///
/// The analyzer is organized into focused components:
/// - `schema`: Manages schema metadata, resolution, and normalization
/// - `tracker`: Tracks cross-statement dependencies and lineage
/// - `issues`: Collects warnings and errors during analysis
/// - `statement_lineages`: Stores per-statement analysis results
pub(crate) struct Analyzer<'a> {
    pub(crate) request: &'a AnalyzeRequest,
    pub(crate) issues: Vec<Issue>,
    pub(crate) statement_lineages: Vec<StatementLineage>,
    /// Schema registry for table/column resolution.
    pub(crate) schema: SchemaRegistry,
    /// Cross-statement dependency tracker.
    pub(crate) tracker: CrossStatementTracker,
    /// Whether column lineage is enabled.
    pub(crate) column_lineage_enabled: bool,
    /// Source slice for the currently analyzed statement (for span lookups).
    current_statement_source: Option<StatementSourceSlice<'a>>,
    /// Statements that already emitted a recursion-depth warning.
    depth_limit_statements: HashSet<usize>,
    /// SQL linter (None if linting is disabled).
    linter: Option<Linter>,
    /// Descriptions harvested from structured SQL comments.
    /// Keyed by canonical table path (plus column for column targets).
    pub(crate) descriptions: HashMap<DescriptionKey, Arc<str>>,
}

impl<'a> Analyzer<'a> {
    fn new(request: &'a AnalyzeRequest) -> Self {
        // Check if column lineage is enabled (default: true)
        let column_lineage_enabled = request
            .options
            .as_ref()
            .and_then(|o| o.enable_column_lineage)
            .unwrap_or(true);

        let (schema, init_issues) = SchemaRegistry::new(request.schema.as_ref(), request.dialect);

        // Initialize linter only when explicitly requested via options.lint
        let linter = request
            .options
            .as_ref()
            .and_then(|o| o.lint.clone())
            .filter(|c| c.enabled)
            .map(Linter::new);

        Self {
            request,
            issues: init_issues,
            statement_lineages: Vec::new(),
            schema,
            tracker: CrossStatementTracker::new(),
            column_lineage_enabled,
            current_statement_source: None,
            depth_limit_statements: HashSet::new(),
            linter,
            descriptions: HashMap::new(),
        }
    }

    /// Returns the current statement SQL slice plus its absolute offset.
    fn current_sql_slice(&self, _caller: &'static str) -> Option<(&str, usize)> {
        if let Some(source) = &self.current_statement_source {
            return match source.sql.get(source.range.start..source.range.end) {
                Some(slice) => Some((slice, source.range.start)),
                None => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        caller = _caller,
                        start = source.range.start,
                        end = source.range.end,
                        sql_len = source.sql.len(),
                        "current statement source range is invalid"
                    );
                    None
                }
            };
        }

        Some((self.request.sql.as_str(), 0))
    }

    /// Finds the span of an identifier in the SQL text.
    ///
    /// This is used to attach source locations to issues for better error reporting.
    pub(crate) fn find_span(&self, identifier: &str) -> Option<Span> {
        let (sql, offset) = self.current_sql_slice("find_span")?;
        find_identifier_span(sql, identifier, 0)
            .map(|span| Span::new(offset + span.start, offset + span.end))
    }

    /// Locates the next identifier span inside the current statement using the
    /// statement-local search cursor stored on `ctx`.
    ///
    /// # Traversal-order contract
    ///
    /// Callers must invoke this in roughly left-to-right lexical order within a
    /// single statement. Each successful call advances `ctx.span_search_cursor`
    /// past the matched span, so a caller that processes AST nodes out of text
    /// order will either skip matches or associate them with the wrong node
    /// instance (notably for self-joins and repeated names). The
    /// `debug_assert!` below catches backward movement in debug builds; it is
    /// intentionally silent in release so a mildly-out-of-order visitor does
    /// not panic in production — but callers should still treat left-to-right
    /// traversal as an invariant.
    pub(crate) fn locate_statement_span<F>(
        &self,
        ctx: &mut StatementContext,
        identifier: &str,
        finder: F,
    ) -> Option<Span>
    where
        F: Fn(&str, &str, usize) -> Option<Span>,
    {
        let search_start = ctx.span_search_cursor;

        let (sql, offset) = self.current_sql_slice("locate_statement_span")?;

        let span = if let Some(span) = finder(sql, identifier, search_start) {
            span
        } else {
            if search_start > 0 {
                if let Some(earlier) = finder(sql, identifier, 0) {
                    if earlier.end <= search_start {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            identifier,
                            search_start,
                            earlier_start = earlier.start,
                            earlier_end = earlier.end,
                            "locate_statement_span exhausted its cursor before matching; traversal may be out of lexical order"
                        );
                    }
                }
            }
            return None;
        };
        debug_assert!(
            span.end >= ctx.span_search_cursor,
            "Span cursor moved backward: {} -> {} (identifier: '{}')",
            ctx.span_search_cursor,
            span.end,
            identifier
        );

        ctx.span_search_cursor = span.end;
        Some(Span::new(offset + span.start, offset + span.end))
    }

    /// Locates the next occurrence of a relation name and narrows the match to
    /// the node label token (the final identifier component).
    ///
    /// For example, `public.users` maps to the span of `users`, not the whole
    /// qualified path. This preserves the existing `nameSpans` semantics while
    /// still assigning occurrences per node instance in lexical order.
    pub(crate) fn locate_relation_name_span(
        &self,
        ctx: &mut StatementContext,
        raw_name: &str,
    ) -> Option<Span> {
        let search_start = *ctx.relation_span_cursor(raw_name);

        let (sql, offset) = self.current_sql_slice("locate_relation_name_span")?;

        let (full_span, name_span) = find_relation_occurrence_spans(sql, raw_name, search_start)?;
        *ctx.relation_span_cursor(raw_name) = full_span.end;
        Some(Span::new(offset + name_span.start, offset + name_span.end))
    }

    /// Returns the correct node ID and type for a relation (view vs table).
    pub(crate) fn relation_identity(&self, canonical: &str) -> (Arc<str>, NodeType) {
        self.tracker.relation_identity(canonical)
    }

    /// Returns the node ID for a relation.
    pub(crate) fn relation_node_id(&self, canonical: &str) -> Arc<str> {
        self.tracker.relation_node_id(canonical)
    }

    /// Check if implied schema capture is allowed (default: true).
    pub(crate) fn allow_implied(&self) -> bool {
        self.schema.allow_implied()
    }

    /// Canonicalizes a table reference using schema resolution.
    pub(crate) fn canonicalize_table_reference(&self, name: &str) -> TableResolution {
        self.schema.canonicalize_table_reference(name)
    }

    /// Normalizes an identifier according to dialect case sensitivity.
    pub(crate) fn normalize_identifier(&self, name: &str) -> String {
        self.schema.normalize_identifier(name)
    }

    /// Normalizes a qualified table name.
    pub(crate) fn normalize_table_name(&self, name: &str) -> String {
        self.schema.normalize_table_name(name)
    }

    /// Emits a warning when expression traversal exceeds the recursion guard.
    pub(crate) fn emit_depth_limit_warning(&mut self, statement_index: usize) {
        if self.depth_limit_statements.insert(statement_index) {
            self.issues.push(
                Issue::warning(
                    issue_codes::APPROXIMATE_LINEAGE,
                    format!(
                        "Expression recursion depth exceeded (>{}). Lineage may be incomplete.",
                        expression::MAX_RECURSION_DEPTH
                    ),
                )
                .with_statement(statement_index),
            );
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(dialect = ?self.request.dialect, stmt_count)))]
    fn analyze(&mut self) -> AnalyzeResult {
        let (all_statements, mut preflight_issues) = collect_statements(self.request);
        self.issues.append(&mut preflight_issues);

        #[cfg(feature = "tracing")]
        tracing::Span::current().record("stmt_count", all_statements.len());

        self.precollect_ddl(&all_statements);

        if all_statements.is_empty() {
            self.run_lint_documents_without_statements();
            return self.build_result();
        }

        self.run_lint_documents(&all_statements);

        // Analyze all statements
        for (
            index,
            StatementInput {
                statement,
                source_name,
                source_sql,
                source_range,
                source_sql_untemplated,
                source_range_untemplated,
                templating_applied,
                ..
            },
        ) in all_statements.into_iter().enumerate()
        {
            #[cfg(feature = "tracing")]
            let _stmt_span = info_span!(
                "analyze_statement",
                index,
                source = source_name.as_deref().map_or("inline", String::as_str),
                stmt_type = ?statement
            )
            .entered();

            // Extract resolved SQL when templating was applied
            let resolved_sql = if templating_applied {
                Some(source_sql[source_range.clone()].to_string())
            } else {
                None
            };
            let original_sql = source_sql_untemplated.as_deref().and_then(|sql| {
                source_range_untemplated
                    .as_ref()
                    .and_then(|range| sql.get(range.clone()).map(str::to_string))
            });

            let statement = match statement {
                StatementInputKind::Parsed(statement) => *statement,
                StatementInputKind::ExternalMetadata(metadata) => {
                    let source_span = source_range_untemplated.as_ref().unwrap_or(&source_range);
                    let span = Span::new(source_span.start, source_span.end);
                    let mut issue = metadata
                        .unsupported_lineage_warning()
                        .with_statement(index)
                        .with_span(span);
                    if let Some(name) = source_name.as_deref() {
                        issue = issue.with_source_name(name.as_str());
                    }
                    self.issues.push(issue);
                    self.statement_lineages.push(StatementLineage {
                        statement_index: index,
                        statement_type: metadata.statement_type().to_string(),
                        source_name: source_name.as_deref().map(ToString::to_string),
                        nodes: Vec::new(),
                        edges: Vec::new(),
                        span: Some(Span::new(source_span.start, source_span.end)),
                        join_count: 0,
                        complexity_score: 1,
                        resolved_sql,
                    });
                    continue;
                }
            };

            self.current_statement_source = Some(StatementSourceSlice {
                sql: source_sql,
                range: source_range.clone(),
            });

            let source_name_owned = source_name.as_deref().map(String::from);
            let result = self.analyze_statement(
                index,
                &statement,
                source_name_owned,
                StatementSource {
                    source_range,
                    original_source_range: source_range_untemplated,
                    original_sql,
                    resolved_sql,
                },
            );
            self.current_statement_source = None;

            match result {
                Ok(lineage) => {
                    self.statement_lineages.push(lineage);
                }
                Err(e) => {
                    self.issues.push(
                        Issue::error(issue_codes::PARSE_ERROR, e.to_string()).with_statement(index),
                    );
                }
            }
        }

        self.build_result()
    }
}

struct StatementSourceSlice<'a> {
    sql: Cow<'a, str>,
    range: Range<usize>,
}

impl<'a> Analyzer<'a> {
    fn run_lint_documents(&mut self, statements: &[StatementInput<'a>]) {
        let Some(linter) = self.linter.as_ref() else {
            return;
        };

        let mut start = 0usize;
        while start < statements.len() {
            let source_name_key = statements[start]
                .source_name
                .as_deref()
                .map(|name| name.as_str());
            let source_sql_key = statements[start].source_sql.as_ref();
            let source_untemplated_sql_key = statements[start].source_sql_untemplated.as_deref();

            let mut end = start + 1;
            while end < statements.len()
                && statements[end]
                    .source_name
                    .as_deref()
                    .map(|name| name.as_str())
                    == source_name_key
                && statements[end].source_sql.as_ref() == source_sql_key
                && statements[end].source_sql_untemplated.as_deref() == source_untemplated_sql_key
            {
                end += 1;
            }

            let mut lint_statements = Vec::with_capacity(end - start);
            let mut source_statement_ranges = Vec::with_capacity(end - start);
            let mut lint_statement_indices = Vec::with_capacity(end - start);
            for (offset, statement_input) in statements[start..end].iter().enumerate() {
                if let StatementInputKind::Parsed(statement) = &statement_input.statement {
                    lint_statements.push(LintStatement {
                        statement: statement.as_ref(),
                        statement_index: lint_statement_indices.len(),
                        statement_range: statement_input.source_range.clone(),
                    });
                    lint_statement_indices.push(offset);
                    source_statement_ranges.push(statement_input.source_range_untemplated.clone());
                }
            }
            if lint_statements.is_empty() {
                start = end;
                continue;
            }

            let parser_fallback_used = statements[start..end]
                .iter()
                .any(|statement_input| statement_input.parser_fallback_used);
            let document = LintDocument::new_with_parser_fallback_and_source(
                source_sql_key,
                source_untemplated_sql_key,
                self.request.dialect,
                lint_statements,
                parser_fallback_used,
                Some(source_statement_ranges),
            );
            let mut lint_issues = linter.check_document(&document);
            for issue in &mut lint_issues {
                if let Some(local_index) = issue.statement_index {
                    issue.statement_index = lint_statement_indices
                        .get(local_index)
                        .map(|offset| start + offset);
                }
                if issue.source_name.is_none() {
                    issue.source_name = source_name_key.map(str::to_owned);
                }
            }
            self.issues.extend(lint_issues);

            start = end;
        }
    }

    fn run_lint_documents_without_statements(&mut self) {
        let Some(linter) = self.linter.as_ref() else {
            return;
        };

        if let Some(files) = &self.request.files {
            if files.is_empty() {
                return;
            }
            for file in files {
                let document = LintDocument::new(&file.content, self.request.dialect, Vec::new());
                let mut lint_issues = linter.check_document(&document);
                for issue in &mut lint_issues {
                    issue.statement_index = None;
                    if issue.source_name.is_none() {
                        issue.source_name = Some(file.name.clone());
                    }
                }
                self.issues.extend(lint_issues);
            }
            return;
        }

        if !self.request.sql.is_empty() {
            let document = LintDocument::new(&self.request.sql, self.request.dialect, Vec::new());
            let mut lint_issues = linter.check_document(&document);
            for issue in &mut lint_issues {
                issue.statement_index = None;
                if issue.source_name.is_none() {
                    issue.source_name = self.request.source_name.clone();
                }
            }
            self.issues.extend(lint_issues);
        }
    }

    /// Pre-registers CREATE TABLE/VIEW targets so earlier statements can resolve them.
    fn precollect_ddl(&mut self, statements: &[StatementInput]) {
        self.descriptions = self.collect_description_map(statements);

        if self.is_dbt_mode() {
            self.precollect_dbt_models(statements);
        }

        for (index, stmt_input) in statements.iter().enumerate() {
            let StatementInputKind::Parsed(statement) = &stmt_input.statement else {
                continue;
            };
            match statement.as_ref() {
                Statement::CreateTable(create) => self.precollect_create_table(create, index),
                Statement::CreateView(CreateView { name, .. }) => {
                    self.precollect_create_view(name);
                }
                _ => {}
            }
        }
    }

    /// Pre-registers dbt model relations so forward `ref(...)` consumers and
    /// later producers share one canonical node identity.
    ///
    /// This pass only **declares type** — it does not record a producer
    /// statement index. Producer indices are set later by the main analysis
    /// pass via `record_view_produced` / `record_produced`. Keeping that
    /// single source of truth for production avoids duplicating producer
    /// state and prevents `declared_views` from drifting out of sync with
    /// `produced_views`.
    ///
    /// Two other responsibilities handled here:
    /// - Detecting duplicate model names across files and surfacing a warning
    ///   so real project configuration errors aren't silently masked. The
    ///   first definition's materialization wins for node identity; later
    ///   producer statements still overwrite the producer index via the
    ///   normal `record_produced` path, so cross-statement edges point at the
    ///   most recently seen producer.
    /// - Surfacing a warning when `materialized=` is present but can't be
    ///   resolved (dynamic Jinja or adapter-specific value), so users know
    ///   we fell back to the default node type.
    fn precollect_dbt_models(&mut self, statements: &[StatementInput]) {
        let mut first_source: HashMap<String, String> = HashMap::new();

        for (index, stmt_input) in statements.iter().enumerate() {
            let StatementInputKind::Parsed(statement) = &stmt_input.statement else {
                continue;
            };
            let Statement::Query(_) = statement.as_ref() else {
                continue;
            };

            let Some(source_name) = stmt_input.source_name.as_deref() else {
                continue;
            };

            let original_sql = stmt_input
                .source_sql_untemplated
                .as_deref()
                .and_then(|sql| {
                    stmt_input
                        .source_range_untemplated
                        .as_ref()
                        .and_then(|range| sql.get(range.clone()))
                });
            let model_name = self.normalize_table_name(extract_model_name(source_name));

            if let Some(existing) = first_source.get(&model_name) {
                self.issues.push(
                    Issue::warning(
                        issue_codes::SCHEMA_CONFLICT,
                        format!(
                            "Duplicate dbt model '{model_name}' defined in both '{existing}' and '{source_name}'. Node identity (table/view/ephemeral) is taken from the first definition ('{existing}'); cross-statement lineage edges still point to the last statement that produces the model."
                        ),
                    )
                    .with_statement(index),
                );
                continue;
            }
            first_source.insert(model_name.clone(), source_name.to_string());

            let detection = original_sql
                .map(detect_dbt_model_materialization)
                .unwrap_or(DbtMaterializationDetection::NotConfigured);

            match detection.node_type() {
                Some(NodeType::View) => self.tracker.declare_view(&model_name),
                Some(NodeType::Cte) => self.tracker.declare_ephemeral(&model_name),
                // Table is the default in `relation_identity`, but we still
                // need to declare it so forward `ref(...)` consumers resolve
                // to a known relation instead of emitting
                // `UNRESOLVED_REFERENCE` before the producer statement runs.
                // `None` (NotConfigured / Unresolved) also defaults to table.
                Some(NodeType::Table) | None => self.tracker.declare_table(&model_name),
                Some(NodeType::Output | NodeType::Column) => {
                    unreachable!("dbt materializations must map to relation-like node types")
                }
            }

            if matches!(detection, DbtMaterializationDetection::Unresolved) {
                self.issues.push(
                    Issue::warning(
                        issue_codes::APPROXIMATE_LINEAGE,
                        format!(
                            "dbt model '{model_name}' has a dynamic or unsupported `materialized` value; defaulting to table"
                        ),
                    )
                    .with_statement(index),
                );
            }
        }
    }

    /// Handles CREATE TABLE statements during DDL pre-collection.
    fn precollect_create_table(
        &mut self,
        create: &sqlparser::ast::CreateTable,
        statement_index: usize,
    ) {
        let canonical = self.normalize_table_name(&create.name.to_string());

        if create.query.is_none() {
            let (column_schemas, table_constraints) =
                build_column_schemas_with_constraints(&create.columns, &create.constraints);

            self.schema.seed_implied_schema_with_constraints(
                &canonical,
                column_schemas,
                table_constraints,
                create.temporary,
                statement_index,
            );
        } else {
            // This is a CTAS (CREATE TABLE ... AS SELECT ...).
            // We mark the table as known to prevent UNRESOLVED_REFERENCE
            // errors, but we don't have column schema yet.
            self.schema.mark_table_known(&canonical);
        }
    }

    /// Handles CREATE VIEW statements during DDL pre-collection.
    fn precollect_create_view(&mut self, name: &sqlparser::ast::ObjectName) {
        let canonical = self.normalize_table_name(&name.to_string());
        self.schema.mark_table_known(&canonical);
    }
}

#[cfg(test)]
mod tests;
