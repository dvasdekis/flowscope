//! Input collection and validation for SQL analysis requests.
//!
//! This module handles the parsing and collection of SQL statements from analysis requests,
//! supporting both file-based and inline SQL inputs.

use super::external_metadata::{parse_external_metadata_statement, ExternalMetadataStatement};
use crate::error::{ParseError, ParseErrorKind, Position};
use crate::limits::{MAX_ANALYSIS_SOURCE_BYTES, MAX_ANALYSIS_TOTAL_BYTES};
use crate::parser::{
    parse_sql_with_dialect_output, parse_sql_with_dialect_tokens_output, ParseSqlOutput,
};
use crate::types::{issue_codes, AnalyzeRequest, Dialect, Issue, Span};
use sqlparser::ast::{
    Ident, SetExpr, Statement, TableAliasColumnDef, TableFactor, VisitMut, VisitorMut,
};
use sqlparser::dialect::MsSqlDialect;
use sqlparser::tokenizer::{Span as TokenSpan, Token, TokenWithSpan, Tokenizer};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::ops::Range;
use std::rc::Rc;
use thiserror::Error;

#[cfg(feature = "templating")]
use crate::templater::{template_sql, TemplateMode};

/// Maximum iterations allowed when merging statement ranges to prevent infinite loops
/// on malformed SQL input.
const MAX_MERGE_ITERATIONS: usize = 10_000;
pub(super) const MAX_MSSQL_EXPANDED_STATEMENT_RANGES: usize = 100_000;
const MAX_MSSQL_GO_SEPARATORS: usize = 100_000;
/// Repeated MSSQL batches are expanded for analysis, but the count is bounded to avoid
/// untrusted `GO n` lines multiplying work without limit.
pub(super) const MAX_MSSQL_GO_REPEAT: usize = 1_000;
const MSSQL_SYNAPSE_OPENROWSET_OPTIONS: &[&str] = &[
    "CODEPAGE",
    "DATA_COMPRESSION",
    "DATA_SOURCE",
    "DATAFILETYPE",
    "ERRORFILE_DATA_SOURCE",
    "ERRORFILE_LOCATION",
    "ESCAPECHAR",
    "FIELDQUOTE",
    "FIELDTERMINATOR",
    "FIRSTROW",
    "FORMAT",
    "HEADER_ROW",
    "MAXERRORS",
    "PARSER_VERSION",
    "ROWSET_OPTIONS",
    "ROWTERMINATOR",
];

#[derive(Clone, Copy)]
enum AnalysisSource<'a> {
    Inline(Option<&'a str>),
    File(&'a str),
}

impl<'a> AnalysisSource<'a> {
    fn name(self) -> Option<&'a str> {
        match self {
            Self::Inline(name) => name,
            Self::File(name) => Some(name),
        }
    }

    fn description(self) -> String {
        match self {
            Self::Inline(Some(name)) | Self::File(name) => format!("SQL source \"{name}\""),
            Self::Inline(None) => "Inline SQL".to_string(),
        }
    }
}

#[derive(Clone, Copy)]
struct AnalysisSourceSize<'a> {
    source: AnalysisSource<'a>,
    bytes: usize,
}

/// Validates raw SQL byte sizes before schema initialization, templating, or parsing.
pub(super) fn validate_analysis_input_sizes(request: &AnalyzeRequest) -> Result<(), Box<Issue>> {
    validate_analysis_input_sizes_with_limits(
        request,
        MAX_ANALYSIS_SOURCE_BYTES,
        MAX_ANALYSIS_TOTAL_BYTES,
    )
}

fn validate_analysis_input_sizes_with_limits(
    request: &AnalyzeRequest,
    max_source_bytes: usize,
    max_total_bytes: usize,
) -> Result<(), Box<Issue>> {
    let inline = std::iter::once(AnalysisSourceSize {
        source: AnalysisSource::Inline(request.source_name.as_deref()),
        bytes: request.sql.len(),
    });
    let files = request
        .files
        .iter()
        .flatten()
        .map(|file| AnalysisSourceSize {
            source: AnalysisSource::File(&file.name),
            bytes: file.content.len(),
        });

    validate_analysis_source_sizes(inline.chain(files), max_source_bytes, max_total_bytes)
}

fn validate_analysis_source_sizes<'a>(
    sources: impl IntoIterator<Item = AnalysisSourceSize<'a>>,
    max_source_bytes: usize,
    max_total_bytes: usize,
) -> Result<(), Box<Issue>> {
    let mut total_bytes = 0usize;

    for source in sources {
        if source.bytes > max_source_bytes {
            let mut issue = Issue::error(
                issue_codes::INVALID_REQUEST,
                format!(
                    "{} exceeds the maximum analysis source size of {} bytes ({} bytes provided)",
                    source.source.description(),
                    max_source_bytes,
                    source.bytes
                ),
            );
            if let Some(name) = source.source.name() {
                issue = issue.with_source_name(name);
            }
            return Err(Box::new(issue));
        }

        total_bytes = match total_bytes.checked_add(source.bytes) {
            Some(total) => total,
            None => {
                return Err(Box::new(Issue::error(
                    issue_codes::INVALID_REQUEST,
                    format!(
                        "Aggregate SQL input exceeds the maximum analysis size of {} bytes",
                        max_total_bytes
                    ),
                )));
            }
        };

        if total_bytes > max_total_bytes {
            return Err(Box::new(Issue::error(
                issue_codes::INVALID_REQUEST,
                format!(
                    "Aggregate SQL input exceeds the maximum analysis size of {} bytes ({} bytes provided)",
                    max_total_bytes, total_bytes
                ),
            )));
        }
    }

    Ok(())
}

/// Creates an issue for a template rendering error.
#[cfg(feature = "templating")]
fn template_error_issue(
    error: &crate::templater::TemplateError,
    source_name: Option<&str>,
) -> Issue {
    let message = match source_name {
        Some(name) => format!("Template error in {name}: {error}"),
        None => format!("Template error: {error}"),
    };
    let mut issue = Issue::error(issue_codes::TEMPLATE_ERROR, message);
    if let Some(name) = source_name {
        issue = issue.with_source_name(name);
    }
    issue
}

/// Applies template preprocessing to SQL if configured.
///
/// Returns the (possibly transformed) SQL and whether templating was applied.
/// The boolean is true when templating was run in non-raw mode, regardless of
/// whether the rendered result differs from the original SQL.
#[cfg(feature = "templating")]
fn apply_template<'a>(
    sql: &'a str,
    config: Option<&crate::templater::TemplateConfig>,
) -> Result<(Cow<'a, str>, bool), crate::templater::TemplateError> {
    match config {
        Some(cfg) if cfg.mode != TemplateMode::Raw => {
            let rendered = template_sql(sql, cfg)?;
            // Templating was applied
            Ok((Cow::Owned(rendered), true))
        }
        _ => Ok((Cow::Borrowed(sql), false)),
    }
}

/// Errors that can occur when aligning statement ranges.
#[derive(Debug, Error)]
enum RangeAlignmentError {
    /// No ranges provided when statements were expected.
    #[error("no ranges provided when {0} statements were expected")]
    NoRanges(usize),
    /// Fewer ranges than statements (cannot split a range).
    #[error("fewer ranges ({0}) than statements ({1}), cannot split ranges")]
    FewerRangesThanStatements(usize, usize),
    /// Failed to merge ranges to match statement count.
    #[error("failed to merge ranges to match statement count")]
    MergeFailed,
    /// Iteration limit exceeded during merge (possible infinite loop).
    #[error("iteration limit ({0}) exceeded during merge, possible infinite loop")]
    IterationLimitExceeded(usize),
    /// A range extends beyond the source SQL bounds.
    #[error("range end ({0}) exceeds source SQL length ({1})")]
    OutOfBounds(usize, usize),
    /// Invalid range where start exceeds end.
    #[error("invalid range: start ({0}) > end ({1})")]
    InvalidRange(usize, usize),
}

/// Context for parsing SQL from a single source.
struct ParseContext<'a> {
    /// The full SQL buffer to parse.
    ///
    /// Uses `Cow` to support both borrowed SQL (from request) and owned SQL
    /// (from template rendering).
    source_sql: Cow<'a, str>,
    /// Optional source file name for error reporting.
    ///
    /// Wrapped in `Rc` so multiple `StatementInput` instances can share
    /// the same name without additional allocations.
    source_name: Option<Rc<String>>,
    /// SQL dialect for parsing.
    dialect: Dialect,
    /// Original SQL before template rendering, when templating is applied.
    untemplated_sql: Option<Cow<'a, str>>,
    /// Whether template processing was applied to produce `source_sql`.
    templating_applied: bool,
}

struct MssqlOpenRowsetSchema {
    openrowset_offset: usize,
    token_range: Range<usize>,
    columns: Vec<TableAliasColumnDef>,
}

struct MssqlOpenRowsetCompatibility {
    tokens: Vec<TokenWithSpan>,
    schemas: Vec<MssqlOpenRowsetSchema>,
}

struct MssqlSynapseOpenRowsetArgumentAdaptation {
    bulk_index: usize,
    equals_indices: Vec<usize>,
}

fn parse_input_sql_with_dialect_output(
    sql: &str,
    dialect: Dialect,
) -> Result<ParseSqlOutput, ParseError> {
    let original = parse_sql_with_dialect_output(sql, dialect);
    if !matches!(dialect, Dialect::Mssql)
        || !mssql_source_contains_ascii_case_insensitive(sql, b"OPENROWSET")
    {
        return original;
    }

    if original.is_ok() {
        if let Some(position) = mssql_parenthesized_bulk_syntax_error(sql) {
            return Err(ParseError::with_position(
                "Malformed or unsupported Synapse OPENROWSET BULK file-list syntax",
                position.line,
                position.column,
            )
            .with_dialect(dialect));
        }
    }

    let Some(compatibility) = mssql_openrowset_compatibility(sql) else {
        return original;
    };

    let mut output = match parse_sql_with_dialect_tokens_output(dialect, compatibility.tokens) {
        Ok(output) => output,
        Err(error) => {
            return if original.is_ok() {
                original
            } else {
                Err(error)
            };
        }
    };
    if !compatibility.schemas.is_empty()
        && !mssql_apply_openrowset_schema_columns(
            sql,
            &mut output.statements,
            compatibility.schemas,
        )
    {
        return original;
    }
    output.parser_fallback_used = true;
    Ok(output)
}

fn mssql_source_contains_ascii_case_insensitive(sql: &str, needle: &[u8]) -> bool {
    sql.as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

pub(crate) enum InputParseOutput {
    ParsedSql(ParseSqlOutput),
    ExternalMetadata(ExternalMetadataStatement, bool),
}

#[derive(Debug)]
pub(crate) enum InputParseError {
    ExternalMetadata(ParseError),
    Parser(ParseError),
}

impl InputParseError {
    pub(crate) fn into_parse_error(self) -> ParseError {
        match self {
            Self::ExternalMetadata(error) | Self::Parser(error) => error,
        }
    }
}

pub(crate) fn parse_input_statement_with_dialect_output(
    sql: &str,
    dialect: Dialect,
) -> Result<InputParseOutput, InputParseError> {
    if matches!(dialect, Dialect::Mssql) {
        match parse_external_metadata_statement(sql) {
            Ok(Some(metadata)) => {
                let parser_fallback_used = match &metadata {
                    ExternalMetadataStatement::Cetas(cetas) => {
                        validate_cetas_query(sql, cetas, dialect)
                            .map_err(InputParseError::ExternalMetadata)?
                    }
                    ExternalMetadataStatement::FileFormat(_)
                    | ExternalMetadataStatement::ConditionalFileFormat(_)
                    | ExternalMetadataStatement::ExternalTable(_) => false,
                };
                return Ok(InputParseOutput::ExternalMetadata(
                    metadata,
                    parser_fallback_used,
                ));
            }
            Err(error) => return Err(InputParseError::ExternalMetadata(error)),
            Ok(None) => {}
        }
    }

    parse_input_sql_with_dialect_output(sql, dialect)
        .map(InputParseOutput::ParsedSql)
        .map_err(InputParseError::Parser)
}

fn validate_cetas_query(
    sql: &str,
    cetas: &super::external_metadata::CetasDefinition,
    dialect: Dialect,
) -> Result<bool, ParseError> {
    let query_sql = sql.get(cetas.query_range.clone()).ok_or_else(|| {
        ParseError::new("Could not read the CETAS SELECT query source range")
            .with_dialect(dialect)
            .with_kind(ParseErrorKind::SyntaxError)
    })?;
    let output = parse_input_sql_with_dialect_output(query_sql, dialect).map_err(|mut error| {
        if let Some(position) = error.position {
            if let Some(relative_offset) = crate::analyzer::helpers::line_col_to_offset(
                query_sql,
                position.line,
                position.column,
            ) {
                if let Some(source_offset) = cetas.query_range.start.checked_add(relative_offset) {
                    if let Some(source_position) = offset_to_position(sql, source_offset) {
                        if let Some(message_position) = error.message.rfind(" at Line:") {
                            error.message.truncate(message_position);
                        }
                        error.position = Some(source_position);
                    }
                }
            }
        }
        error.dialect = Some(dialect);
        error
    })?;

    if matches!(
        output.statements.as_slice(),
        [Statement::Query(query)] if is_select_query_body(query.body.as_ref())
    ) {
        return Ok(output.parser_fallback_used);
    }

    let position =
        offset_to_position(sql, cetas.query_range.start).unwrap_or(Position { line: 1, column: 1 });
    Err(ParseError::with_position(
        "CREATE EXTERNAL TABLE AS SELECT requires exactly one SELECT query",
        position.line,
        position.column,
    )
    .with_dialect(dialect)
    .with_kind(ParseErrorKind::SyntaxError))
}

fn is_select_query_body(body: &SetExpr) -> bool {
    match body {
        SetExpr::Select(_) => true,
        SetExpr::SetOperation { left, right, .. } => {
            is_select_query_body(left) && is_select_query_body(right)
        }
        _ => false,
    }
}

pub(crate) fn offset_to_position(sql: &str, offset: usize) -> Option<Position> {
    let prefix = sql.get(..offset)?;
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let current_line = prefix.rsplit_once('\n').map_or(prefix, |(_, line)| line);
    Some(Position {
        line,
        column: current_line.chars().count() + 1,
    })
}

/// Returns the parser token stream for documented Synapse OPENROWSET arguments.
#[cfg(test)]
fn mssql_openrowset_compatible_tokens(sql: &str) -> Option<Vec<TokenWithSpan>> {
    mssql_openrowset_compatibility(sql).map(|compatibility| compatibility.tokens)
}

fn mssql_parenthesized_bulk_syntax_error(sql: &str) -> Option<Position> {
    let tokens = Tokenizer::new(&MsSqlDialect {}, sql)
        .tokenize_with_location()
        .ok()?;
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() || !word.value.eq_ignore_ascii_case("OPENROWSET") {
            continue;
        }
        if !mssql_openrowset_is_table_factor(&tokens, index) {
            continue;
        }

        let open_paren = mssql_next_significant_token(&tokens, index + 1)?;
        if !matches!(tokens[open_paren].token, Token::LParen) {
            continue;
        }
        let Some(close_paren) = mssql_matching_paren(&tokens, open_paren) else {
            continue;
        };
        let Some(argument_ranges) = mssql_openrowset_arguments(&tokens, open_paren, close_paren)
        else {
            continue;
        };
        let Some(first_argument) = argument_ranges.first() else {
            continue;
        };
        let significant = mssql_significant_token_indices(&tokens, first_argument);
        let Some(bulk_index) = significant.first().copied() else {
            continue;
        };
        let Token::Word(bulk) = &tokens[bulk_index].token else {
            continue;
        };
        if bulk.quote_style.is_some() || !bulk.value.eq_ignore_ascii_case("BULK") {
            continue;
        }
        let Some(list_index) = significant.get(1).copied() else {
            continue;
        };
        if !matches!(tokens[list_index].token, Token::LParen) {
            continue;
        }

        let invalid_arguments = mssql_synapse_openrowset_argument_adaptation(
            &tokens,
            &argument_ranges,
            MSSQL_SYNAPSE_OPENROWSET_OPTIONS,
        )
        .is_none();
        let invalid_schema = mssql_openrowset_schema_after_call(
            sql,
            &tokens,
            close_paren,
            mssql_token_byte_range(sql, token)?.start,
        )
        .is_err();
        if invalid_arguments || invalid_schema {
            let list_offset = mssql_token_byte_range(sql, &tokens[list_index])?.start;
            return offset_to_position(sql, list_offset);
        }
    }
    None
}

fn mssql_openrowset_compatibility(sql: &str) -> Option<MssqlOpenRowsetCompatibility> {
    let tokens = Tokenizer::new(&MsSqlDialect {}, sql)
        .tokenize_with_location()
        .ok()?;
    let mut adaptations = Vec::new();
    let mut schemas = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() || !word.value.eq_ignore_ascii_case("OPENROWSET") {
            continue;
        }
        if !mssql_openrowset_is_table_factor(&tokens, index) {
            continue;
        }

        let Some(open_paren) = mssql_next_significant_token(&tokens, index + 1) else {
            continue;
        };
        if !matches!(tokens[open_paren].token, Token::LParen) {
            continue;
        }
        let Some(close_paren) = mssql_matching_paren(&tokens, open_paren) else {
            continue;
        };
        let Some(argument_ranges) = mssql_openrowset_arguments(&tokens, open_paren, close_paren)
        else {
            continue;
        };
        let Some(argument_adaptation) = mssql_synapse_openrowset_argument_adaptation(
            &tokens,
            &argument_ranges,
            MSSQL_SYNAPSE_OPENROWSET_OPTIONS,
        ) else {
            continue;
        };

        let openrowset_offset = mssql_token_byte_range(sql, token)?.start;
        let schema = match mssql_openrowset_schema_after_call(
            sql,
            &tokens,
            close_paren,
            openrowset_offset,
        ) {
            Ok(schema) => schema,
            Err(()) => continue,
        };
        adaptations.push(argument_adaptation);
        if let Some(schema) = schema {
            schemas.push(schema);
        }
    }

    if adaptations.is_empty() {
        return None;
    }

    let mut removed = vec![false; tokens.len()];
    for schema in &schemas {
        for (index, token) in tokens
            .iter()
            .enumerate()
            .take(schema.token_range.end)
            .skip(schema.token_range.start)
        {
            if !matches!(token.token, Token::Whitespace(_)) {
                removed[index] = true;
            }
        }
    }

    let mut replacements = HashMap::new();
    let mut insertions = Vec::with_capacity(adaptations.len());
    for adaptation in adaptations {
        let point_span = mssql_point_span(tokens[adaptation.bulk_index].span.end)?;
        insertions.push((
            adaptation.bulk_index + 1,
            TokenWithSpan::new(Token::Colon, point_span),
        ));
        for index in adaptation.equals_indices {
            if !matches!(tokens[index].token, Token::Eq) {
                return None;
            }
            replacements.insert(index, TokenWithSpan::new(Token::Colon, tokens[index].span));
        }
    }

    insertions.sort_by_key(|(index, _)| *index);
    let mut compatible_tokens = Vec::with_capacity(tokens.len() + insertions.len());
    let mut insertion_index = 0;
    for index in 0..=tokens.len() {
        while insertions
            .get(insertion_index)
            .is_some_and(|(insertion_at, _)| *insertion_at == index)
        {
            compatible_tokens.push(insertions[insertion_index].1.clone());
            insertion_index += 1;
        }
        if index < tokens.len() && !removed[index] {
            compatible_tokens.push(
                replacements
                    .remove(&index)
                    .unwrap_or_else(|| tokens[index].clone()),
            );
        }
    }
    Some(MssqlOpenRowsetCompatibility {
        tokens: compatible_tokens,
        schemas,
    })
}

fn mssql_openrowset_schema_after_call(
    sql: &str,
    tokens: &[TokenWithSpan],
    call_close_paren: usize,
    openrowset_offset: usize,
) -> Result<Option<MssqlOpenRowsetSchema>, ()> {
    let Some(with_index) = mssql_next_significant_token(tokens, call_close_paren + 1) else {
        return Ok(None);
    };
    let Token::Word(with_keyword) = &tokens[with_index].token else {
        return Ok(None);
    };
    if with_keyword.quote_style.is_some() || !with_keyword.value.eq_ignore_ascii_case("WITH") {
        return Ok(None);
    }

    let open_paren = mssql_next_significant_token(tokens, with_index + 1).ok_or(())?;
    if !matches!(tokens[open_paren].token, Token::LParen) {
        return Err(());
    }
    let close_paren = mssql_matching_paren(tokens, open_paren).ok_or(())?;
    let column_ranges = mssql_openrowset_arguments(tokens, open_paren, close_paren).ok_or(())?;
    let columns = mssql_synapse_openrowset_schema_columns(sql, tokens, &column_ranges).ok_or(())?;
    Ok(Some(MssqlOpenRowsetSchema {
        openrowset_offset,
        token_range: with_index..close_paren + 1,
        columns,
    }))
}

fn mssql_point_span(location: sqlparser::tokenizer::Location) -> Option<TokenSpan> {
    (location.line != 0 && location.column != 0).then_some(TokenSpan::new(location, location))
}

fn mssql_synapse_openrowset_schema_columns(
    sql: &str,
    tokens: &[TokenWithSpan],
    column_ranges: &[Range<usize>],
) -> Option<Vec<TableAliasColumnDef>> {
    let mut definitions = Vec::with_capacity(column_ranges.len());
    for range in column_ranges {
        let significant = mssql_significant_token_indices(tokens, range);
        if significant.len() < 2 {
            return None;
        }

        if !matches!(tokens[*significant.first()?].token, Token::Word(_)) {
            return None;
        }

        let mut definition_tokens = significant;
        let last_index = *definition_tokens.last()?;
        if mssql_token_is_at_top_level(tokens, range, last_index) {
            match &tokens[last_index].token {
                Token::Number(ordinal, _) => {
                    ordinal.parse::<usize>().ok().filter(|value| *value > 0)?;
                    definition_tokens.pop();
                }
                Token::SingleQuotedString(_) | Token::NationalStringLiteral(_) => {
                    definition_tokens.pop();
                }
                _ => {}
            }
        }
        if definition_tokens.len() < 2 {
            return None;
        }

        let start = mssql_token_byte_range(sql, &tokens[*definition_tokens.first()?])?.start;
        let end = mssql_token_byte_range(sql, &tokens[*definition_tokens.last()?])?.end;
        definitions.push(sql.get(start..end)?.to_string());
    }

    let create_sql = format!(
        "CREATE TABLE [__flowscope_openrowset_schema] ({})",
        definitions.join(", ")
    );
    let output = parse_sql_with_dialect_output(&create_sql, Dialect::Mssql).ok()?;
    let mut statements = output.statements.into_iter();
    let Statement::CreateTable(create) = statements.next()? else {
        return None;
    };
    if statements.next().is_some()
        || create.columns.len() != definitions.len()
        || create.columns.iter().any(|column| {
            column
                .options
                .as_slice()
                .iter()
                .any(|option| !matches!(&option.option, sqlparser::ast::ColumnOption::Collation(_)))
        })
    {
        return None;
    }

    Some(
        create
            .columns
            .into_iter()
            .map(|column| TableAliasColumnDef {
                name: column.name,
                data_type: Some(column.data_type),
            })
            .collect(),
    )
}

fn mssql_token_is_at_top_level(
    tokens: &[TokenWithSpan],
    range: &Range<usize>,
    target_index: usize,
) -> bool {
    let mut depth = 0usize;
    for token in &tokens[range.start..target_index] {
        match token.token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth == 0
}

fn mssql_apply_openrowset_schema_columns(
    sql: &str,
    statements: &mut [Statement],
    schemas: Vec<MssqlOpenRowsetSchema>,
) -> bool {
    let schemas: HashMap<_, _> = schemas
        .into_iter()
        .map(|schema| (schema.openrowset_offset, schema.columns))
        .collect();
    let mut visitor = MssqlOpenRowsetSchemaVisitor { sql, schemas };
    for statement in statements {
        if matches!(statement.visit(&mut visitor), ControlFlow::Break(())) {
            return false;
        }
    }
    visitor.schemas.is_empty()
}

struct MssqlOpenRowsetSchemaVisitor<'a> {
    sql: &'a str,
    schemas: HashMap<usize, Vec<TableAliasColumnDef>>,
}

impl VisitorMut for MssqlOpenRowsetSchemaVisitor<'_> {
    type Break = ();

    fn pre_visit_table_factor(
        &mut self,
        table_factor: &mut TableFactor,
    ) -> ControlFlow<Self::Break> {
        if mssql_apply_openrowset_schema_columns_to_table_factor(
            table_factor,
            self.sql,
            &mut self.schemas,
        ) {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    }
}

fn mssql_apply_openrowset_schema_columns_to_table_factor(
    table_factor: &mut TableFactor,
    sql: &str,
    schemas: &mut HashMap<usize, Vec<TableAliasColumnDef>>,
) -> bool {
    match table_factor {
        TableFactor::Table { name, alias, .. } => {
            let Some(first_name) = name.0.first().and_then(|part| part.as_ident()) else {
                return true;
            };
            if !first_name.value.eq_ignore_ascii_case("OPENROWSET") {
                return true;
            }
            let Some(offset) = mssql_ident_byte_offset(sql, first_name) else {
                return false;
            };
            let Some(columns) = schemas.remove(&offset) else {
                return true;
            };
            let Some(alias) = alias else {
                return false;
            };
            if alias.columns.is_empty() {
                alias.columns = columns;
                return true;
            }
            if alias.columns.len() != columns.len()
                || alias
                    .columns
                    .iter()
                    .any(|column| column.data_type.is_some())
            {
                return false;
            }
            for (alias_column, schema_column) in alias.columns.iter_mut().zip(columns) {
                alias_column.data_type = schema_column.data_type;
            }
            true
        }
        _ => true,
    }
}

fn mssql_ident_byte_offset(sql: &str, ident: &Ident) -> Option<usize> {
    let span = ident.span;
    let offset = crate::analyzer::helpers::line_col_to_offset(
        sql,
        span.start.line.try_into().ok()?,
        span.start.column.try_into().ok()?,
    )?;
    (offset <= sql.len() && sql.is_char_boundary(offset)).then_some(offset)
}

fn mssql_openrowset_is_table_factor(tokens: &[TokenWithSpan], index: usize) -> bool {
    let mut previous = index;
    while previous > 0 {
        previous -= 1;
        if matches!(tokens[previous].token, Token::Whitespace(_)) {
            continue;
        }

        if matches!(tokens[previous].token, Token::Period) {
            return false;
        }
        return match &tokens[previous].token {
            Token::Word(word) => ["APPLY", "FROM", "JOIN"]
                .iter()
                .any(|keyword| word.value.eq_ignore_ascii_case(keyword)),
            Token::Comma => mssql_comma_is_in_from_clause(tokens, previous),
            _ => false,
        };
    }
    false
}

fn mssql_comma_is_in_from_clause(tokens: &[TokenWithSpan], comma_index: usize) -> bool {
    let mut nested_depth = 0usize;
    for token in tokens[..comma_index].iter().rev() {
        match &token.token {
            Token::RParen => nested_depth += 1,
            Token::LParen if nested_depth > 0 => nested_depth -= 1,
            Token::LParen => return false,
            Token::Word(word) if nested_depth == 0 => {
                if word.value.eq_ignore_ascii_case("FROM") {
                    return true;
                }
                if [
                    "WHERE",
                    "GROUP",
                    "HAVING",
                    "ORDER",
                    "QUALIFY",
                    "UNION",
                    "EXCEPT",
                    "INTERSECT",
                    "ON",
                    "SET",
                    "VALUES",
                    "RETURNING",
                ]
                .iter()
                .any(|keyword| word.value.eq_ignore_ascii_case(keyword))
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    false
}

fn mssql_next_significant_token(tokens: &[TokenWithSpan], mut index: usize) -> Option<usize> {
    while index < tokens.len() {
        if !matches!(tokens[index].token, Token::Whitespace(_)) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn mssql_matching_paren(tokens: &[TokenWithSpan], open_paren: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open_paren) {
        match token.token {
            Token::LParen => depth += 1,
            Token::RParen => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn mssql_openrowset_arguments(
    tokens: &[TokenWithSpan],
    open_paren: usize,
    close_paren: usize,
) -> Option<Vec<Range<usize>>> {
    let mut arguments = Vec::new();
    let mut argument_start = open_paren + 1;
    let mut depth = 0usize;
    for (index, token) in tokens
        .iter()
        .enumerate()
        .take(close_paren)
        .skip(open_paren + 1)
    {
        match token.token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.checked_sub(1)?,
            Token::Comma if depth == 0 => {
                arguments.push(argument_start..index);
                argument_start = index + 1;
            }
            _ => {}
        }
    }
    arguments.push(argument_start..close_paren);
    (!arguments.iter().any(Range::is_empty)).then_some(arguments)
}

fn mssql_synapse_openrowset_argument_adaptation(
    tokens: &[TokenWithSpan],
    argument_ranges: &[Range<usize>],
    options: &[&str],
) -> Option<MssqlSynapseOpenRowsetArgumentAdaptation> {
    let mut significant = mssql_significant_token_indices(tokens, argument_ranges.first()?);
    let bulk_index = *significant.first()?;
    let Token::Word(bulk) = &tokens[bulk_index].token else {
        return None;
    };
    if bulk.quote_style.is_some() || !bulk.value.eq_ignore_ascii_case("BULK") {
        return None;
    }
    let bulk_value = &significant[1..];
    let path_index = *bulk_value.first()?;
    let path_argument_valid = if bulk_value.len() == 1 {
        mssql_synapse_bulk_path_is_string(&tokens[path_index].token)
    } else if matches!(tokens[path_index].token, Token::LParen)
        && matches!(tokens[*bulk_value.last()?].token, Token::RParen)
    {
        let list = &bulk_value[1..bulk_value.len() - 1];
        if list.is_empty() || list.len() & 1 == 0 {
            false
        } else {
            list.iter().enumerate().all(|(index, token_index)| {
                if index % 2 == 0 {
                    mssql_synapse_bulk_path_is_string(&tokens[*token_index].token)
                } else {
                    matches!(tokens[*token_index].token, Token::Comma)
                }
            })
        }
    } else {
        false
    };
    if !path_argument_valid {
        return None;
    }

    let mut equals_indices = Vec::new();
    let mut seen_options = std::collections::HashSet::new();
    let mut seen_format = false;

    for range in argument_ranges.iter().skip(1) {
        significant = mssql_significant_token_indices(tokens, range);
        if significant.len() != 3 {
            return None;
        }
        let key_index = *significant.first()?;
        let equals_index = *significant.get(1)?;
        let value_index = *significant.get(2)?;
        let Token::Word(key) = &tokens[key_index].token else {
            return None;
        };
        let option = key.value.to_ascii_uppercase();
        if key.quote_style.is_some()
            || !options.iter().any(|allowed| *allowed == option)
            || !seen_options.insert(option.clone())
            || !matches!(tokens[equals_index].token, Token::Eq)
            || !mssql_synapse_openrowset_option_value_is_valid(&option, &tokens[value_index].token)
        {
            return None;
        }
        if option == "FORMAT" {
            seen_format = true;
        } else if option != "DATA_SOURCE" && !seen_format {
            return None;
        }
        equals_indices.push(equals_index);
    }

    seen_format.then_some(MssqlSynapseOpenRowsetArgumentAdaptation {
        bulk_index,
        equals_indices,
    })
}

fn mssql_synapse_bulk_path_is_string(token: &Token) -> bool {
    matches!(
        token,
        Token::SingleQuotedString(_) | Token::NationalStringLiteral(_)
    )
}

fn mssql_significant_token_indices(tokens: &[TokenWithSpan], range: &Range<usize>) -> Vec<usize> {
    range
        .clone()
        .filter(|index| !matches!(tokens[*index].token, Token::Whitespace(_)))
        .collect()
}

fn mssql_synapse_openrowset_option_value_is_valid(option: &str, value: &Token) -> bool {
    match option {
        "FORMAT" => match value {
            Token::SingleQuotedString(format) | Token::NationalStringLiteral(format) => {
                ["CSV", "DELTA", "PARQUET"]
                    .iter()
                    .any(|supported| format.eq_ignore_ascii_case(supported))
            }
            _ => false,
        },
        "HEADER_ROW" => {
            matches!(value, Token::Word(word) if word.quote_style.is_none() && (word.value.eq_ignore_ascii_case("TRUE") || word.value.eq_ignore_ascii_case("FALSE")))
        }
        "FIRSTROW" | "MAXERRORS" => {
            matches!(
                value,
                Token::Number(_, _)
                    | Token::SingleQuotedString(_)
                    | Token::NationalStringLiteral(_)
            )
        }
        "CODEPAGE" => {
            matches!(
                value,
                Token::Number(_, _)
                    | Token::SingleQuotedString(_)
                    | Token::NationalStringLiteral(_)
            )
        }
        _ => matches!(
            value,
            Token::SingleQuotedString(_) | Token::NationalStringLiteral(_)
        ),
    }
}

fn mssql_token_byte_range(sql: &str, token: &TokenWithSpan) -> Option<Range<usize>> {
    let start = crate::analyzer::helpers::line_col_to_offset(
        sql,
        token.span.start.line.try_into().ok()?,
        token.span.start.column.try_into().ok()?,
    )?;
    let end = crate::analyzer::helpers::line_col_to_offset(
        sql,
        token.span.end.line.try_into().ok()?,
        token.span.end.column.try_into().ok()?,
    )?;
    (start <= end && end <= sql.len() && sql.is_char_boundary(start) && sql.is_char_boundary(end))
        .then_some(start..end)
}

/// A parsed SQL statement or explicitly classified metadata-only statement.
#[derive(Debug)]
pub(crate) enum StatementInputKind {
    Parsed(Box<Statement>),
    ExternalMetadata(ExternalMetadataStatement),
}

/// A statement alongside its source metadata.
pub(crate) struct StatementInput<'a> {
    /// The parsed SQL statement or metadata-only classification.
    pub(crate) statement: StatementInputKind,
    /// Optional source file name for error reporting and tracing.
    ///
    /// Uses `Rc<String>` to avoid repeated heap allocations when the same file
    /// contains multiple statements. All statements from a single file share
    /// the same `Rc`, so cloning is just a reference count increment.
    pub(crate) source_name: Option<Rc<String>>,
    /// The full SQL buffer this statement came from.
    ///
    /// Uses `Cow` to support both borrowed SQL (from request) and owned SQL
    /// (from template rendering). When templated, each statement owns its
    /// copy of the rendered SQL; when not templated, all statements from the
    /// same source share a borrowed reference.
    pub(crate) source_sql: Cow<'a, str>,
    /// Byte range of the statement within `source_sql`.
    pub(crate) source_range: Range<usize>,
    /// Original SQL before template rendering, when templating is applied.
    pub(crate) source_sql_untemplated: Option<Cow<'a, str>>,
    /// Byte range of the statement within `source_sql_untemplated`, when available.
    pub(crate) source_range_untemplated: Option<Range<usize>>,
    /// Whether template processing was applied to produce `source_sql`.
    /// When true, `source_sql` contains the resolved/compiled SQL.
    pub(crate) templating_applied: bool,
    /// Whether parser fallback was used while parsing this statement.
    pub(crate) parser_fallback_used: bool,
}

/// Collects and parses SQL statements from the analysis request.
///
/// This function handles both file-based and inline SQL inputs, combining them into
/// a single ordered list of statements for analysis.
///
/// # Input Sources
///
/// The request can provide SQL through two mechanisms:
///
/// 1. **File sources** (`request.files`): A list of named SQL files with content
/// 2. **Inline SQL** (`request.sql`): Direct SQL text in the request body
///
/// Both sources are processed and combined. At least one must contain valid SQL.
///
/// # Processing Order
///
/// When both sources are present, statements are collected in this order:
///
/// 1. File statements (in the order files appear in the array)
/// 2. Inline SQL statements
///
/// This ordering ensures predictable cross-statement dependency detection,
/// where earlier statements can be referenced by later ones.
///
/// # Error Handling
///
/// Parse errors from individual files or inline SQL are collected as issues
/// rather than failing immediately. This allows partial analysis when some
/// inputs are valid.
///
/// # Returns
///
/// A tuple of `(statements, issues)` where:
/// - `statements`: Successfully parsed statements with source attribution
/// - `issues`: Any validation errors or parse failures encountered
pub(crate) fn collect_statements<'a>(
    request: &'a AnalyzeRequest,
) -> (Vec<StatementInput<'a>>, Vec<Issue>) {
    collect_statements_with_mssql_range_limit(request, MAX_MSSQL_EXPANDED_STATEMENT_RANGES)
}

fn collect_statements_with_mssql_range_limit<'a>(
    request: &'a AnalyzeRequest,
    mssql_range_limit: usize,
) -> (Vec<StatementInput<'a>>, Vec<Issue>) {
    let mut issues = Vec::new();
    let mut statements = Vec::new();
    // Share the expanded-range budget across every source so files and inline SQL
    // cannot each consume the full allowance independently.
    let mut remaining_mssql_ranges = mssql_range_limit;

    let has_sql = !request.sql.trim().is_empty();
    let has_files = request
        .files
        .as_ref()
        .map(|files| !files.is_empty())
        .unwrap_or(false);

    if !has_sql && !has_files {
        issues.push(Issue::error(
            issue_codes::INVALID_REQUEST,
            "Provide inline SQL or at least one file to analyze",
        ));
        return (Vec::new(), issues);
    }

    // Parse files first (if present)
    if let Some(files) = &request.files {
        for file in files {
            // Apply templating if configured
            #[cfg(feature = "templating")]
            let (source_sql, templating_applied): (Cow<'_, str>, bool) = {
                match apply_template(&file.content, request.template_config.as_ref()) {
                    Ok((sql, applied)) => (sql, applied),
                    Err(e) => {
                        issues.push(template_error_issue(&e, Some(&file.name)));
                        continue; // Skip this file but continue with others
                    }
                }
            };
            #[cfg(not(feature = "templating"))]
            let (source_sql, templating_applied): (Cow<'_, str>, bool) =
                (Cow::Borrowed(file.content.as_str()), false);

            let ctx = ParseContext {
                source_sql,
                source_name: Some(Rc::new(file.name.clone())),
                dialect: request.dialect,
                untemplated_sql: templating_applied.then_some(Cow::Borrowed(file.content.as_str())),
                templating_applied,
            };
            let (file_stmts, file_issues) =
                parse_statements_individually(&ctx, &mut remaining_mssql_ranges);
            statements.extend(file_stmts);
            issues.extend(file_issues);
        }
    }

    // Parse inline SQL if present (appended after file statements)
    if has_sql {
        // Apply templating if configured
        #[cfg(feature = "templating")]
        let (source_sql, templating_applied): (Cow<'_, str>, bool) = {
            match apply_template(&request.sql, request.template_config.as_ref()) {
                Ok((sql, applied)) => (sql, applied),
                Err(e) => {
                    // Record error and return collected statements (same as file error handling).
                    // Inline SQL is processed last, so returning here is equivalent to continuing.
                    issues.push(template_error_issue(&e, request.source_name.as_deref()));
                    return (statements, issues);
                }
            }
        };
        #[cfg(not(feature = "templating"))]
        let (source_sql, templating_applied): (Cow<'_, str>, bool) =
            (Cow::Borrowed(request.sql.as_str()), false);

        let ctx = ParseContext {
            source_sql,
            source_name: request.source_name.clone().map(Rc::new),
            dialect: request.dialect,
            untemplated_sql: templating_applied.then_some(Cow::Borrowed(request.sql.as_str())),
            templating_applied,
        };
        let (inline_stmts, inline_issues) =
            parse_statements_individually(&ctx, &mut remaining_mssql_ranges);
        statements.extend(inline_stmts);
        issues.extend(inline_issues);
    }

    (statements, issues)
}

/// Parses SQL from a single buffer with best-effort error handling.
///
/// The parser first tries to process the entire buffer so statements containing
/// embedded semicolons (e.g. procedures) remain intact. If that fails, it
/// falls back to parsing semicolon-delimited slices individually so later
/// statements can still be analyzed.
fn parse_statements_individually<'a>(
    ctx: &ParseContext<'a>,
    remaining_mssql_ranges: &mut usize,
) -> (Vec<StatementInput<'a>>, Vec<Issue>) {
    let statement_ranges = match compute_statement_ranges_for_dialect_with_limit(
        &ctx.source_sql,
        ctx.dialect,
        *remaining_mssql_ranges,
    ) {
        Ok(ranges) => ranges,
        Err(()) => {
            let mut issue = Issue::error(
                issue_codes::INVALID_REQUEST,
                "SQL input exceeds the supported MSSQL batch expansion limit",
            );
            if let Some(source_name) = ctx.source_name.as_deref() {
                issue = issue.with_source_name(source_name);
            }
            return (Vec::new(), vec![issue]);
        }
    };
    if matches!(ctx.dialect, Dialect::Mssql) {
        *remaining_mssql_ranges = remaining_mssql_ranges.saturating_sub(statement_ranges.len());
    }

    match parse_full_sql_buffer(ctx, &statement_ranges) {
        Ok(statements) => (statements, Vec::new()),
        Err(fallback_error) => {
            let (statements, mut issues) = if matches!(ctx.dialect, Dialect::Mssql) {
                parse_mssql_ranges_best_effort(ctx, statement_ranges)
            } else {
                parse_statement_ranges_best_effort(ctx, statement_ranges)
            };

            // Surface the fallback reason to users so they understand why
            // best-effort parsing was used
            if let Some(error) = fallback_error {
                let source_info = ctx
                    .source_name
                    .as_deref()
                    .map(|n| format!(" in {n}"))
                    .unwrap_or_default();
                let message = format!(
                    "Full SQL parsing failed{source_info}, using best-effort mode: {error}"
                );
                let mut issue = Issue::warning(issue_codes::PARSE_ERROR, message);
                if let Some(name) = ctx.source_name.as_deref() {
                    issue = issue.with_source_name(name);
                }
                issues.insert(0, issue);
            }

            (statements, issues)
        }
    }
}

/// Attempts full SQL buffer parsing with statement range alignment.
///
/// Returns:
/// - `Ok(statements)` if parsing and range alignment succeeded
/// - `Err(None)` if SQL parsing failed (no specific error to report)
/// - `Err(Some(error))` if range alignment failed (error should be surfaced)
fn parse_full_sql_buffer<'a>(
    ctx: &ParseContext<'a>,
    statement_ranges: &[Range<usize>],
) -> Result<Vec<StatementInput<'a>>, Option<RangeAlignmentError>> {
    if matches!(ctx.dialect, Dialect::Mssql)
        && (statement_ranges_contain_external_metadata(&ctx.source_sql, statement_ranges)
            || mssql_ranges_have_optional_separators(&ctx.source_sql, statement_ranges))
    {
        return Err(None);
    }

    let parsed_output =
        parse_input_sql_with_dialect_output(&ctx.source_sql, ctx.dialect).map_err(|_| None)?;
    let parser_fallback_used = parsed_output.parser_fallback_used;
    let parsed = parsed_output.statements;

    if parsed.is_empty() {
        return Ok(Vec::new());
    }

    let aligned_ranges = match align_statement_ranges(
        &ctx.source_sql,
        statement_ranges,
        ctx.dialect,
        parsed.len(),
    ) {
        Ok(ranges) => ranges,
        Err(e) => {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                source = ?ctx.source_name.as_deref(),
                error = %e,
                "Failed to align statement ranges, falling back to best-effort parsing"
            );
            return Err(Some(e));
        }
    };

    let aligned_untemplated_ranges = ctx.untemplated_sql.as_deref().and_then(|sql| {
        let ranges = compute_statement_ranges_for_dialect(sql, ctx.dialect).ok()?;
        align_statement_ranges(sql, &ranges, ctx.dialect, parsed.len()).ok()
    });

    let mut statements = Vec::with_capacity(parsed.len());
    for (index, (stmt, range)) in parsed.into_iter().zip(aligned_ranges).enumerate() {
        statements.push(StatementInput {
            statement: StatementInputKind::Parsed(Box::new(stmt)),
            source_name: ctx.source_name.clone(),
            source_sql: ctx.source_sql.clone(),
            source_range: range,
            source_sql_untemplated: ctx.untemplated_sql.clone(),
            source_range_untemplated: aligned_untemplated_ranges
                .as_ref()
                .and_then(|ranges| ranges.get(index).cloned()),
            templating_applied: ctx.templating_applied,
            parser_fallback_used,
        });
    }

    Ok(statements)
}

fn align_statement_ranges(
    source_sql: &str,
    statement_ranges: &[Range<usize>],
    dialect: Dialect,
    statement_count: usize,
) -> Result<Vec<Range<usize>>, RangeAlignmentError> {
    if statement_count == 0 {
        return Ok(Vec::new());
    }

    if statement_ranges.is_empty() {
        return Err(RangeAlignmentError::NoRanges(statement_count));
    }

    if statement_ranges.len() == statement_count {
        return Ok(statement_ranges.to_vec());
    }

    if statement_ranges.len() < statement_count {
        return Err(RangeAlignmentError::FewerRangesThanStatements(
            statement_ranges.len(),
            statement_count,
        ));
    }

    merge_statement_ranges(source_sql, statement_ranges, dialect, statement_count)
}

/// Re-aligns semicolon-delimited ranges with the statements parsed by `sqlparser`.
///
/// This is necessary because `sqlparser` may parse a single statement that contains
/// multiple semicolons (e.g., a `CREATE PROCEDURE` block). In such cases, our
/// naive `compute_statement_ranges` will produce more ranges than `sqlparser` produces
/// statements. This function greedily merges consecutive ranges until the resulting
/// SQL snippet successfully parses as a single statement, ensuring each parsed AST
/// node is mapped to its correct, complete source text.
fn merge_statement_ranges(
    source_sql: &str,
    statement_ranges: &[Range<usize>],
    dialect: Dialect,
    statement_count: usize,
) -> Result<Vec<Range<usize>>, RangeAlignmentError> {
    let mut merged = Vec::with_capacity(statement_count);
    let mut range_index = 0usize;

    // Process each expected statement, greedily merging ranges as needed
    for _ in 0..statement_count {
        // Ensure we have ranges left to process
        if range_index >= statement_ranges.len() {
            return Err(RangeAlignmentError::MergeFailed);
        }

        let mut statement_iterations = 0usize;

        // Start with the current range; we'll extend it if needed
        let mut current_range = statement_ranges[range_index].clone();
        range_index += 1;

        // Keep extending the range until we get exactly one parsed statement
        loop {
            statement_iterations += 1;
            if statement_iterations > MAX_MERGE_ITERATIONS {
                return Err(RangeAlignmentError::IterationLimitExceeded(
                    MAX_MERGE_ITERATIONS,
                ));
            }

            // Validate range boundaries
            if current_range.start > current_range.end {
                return Err(RangeAlignmentError::InvalidRange(
                    current_range.start,
                    current_range.end,
                ));
            }
            if current_range.end > source_sql.len() {
                return Err(RangeAlignmentError::OutOfBounds(
                    current_range.end,
                    source_sql.len(),
                ));
            }

            let snippet = &source_sql[current_range.clone()];
            match parse_input_sql_with_dialect_output(snippet, dialect)
                .map(|output| output.statements)
            {
                // Found exactly one statement - this range is complete
                Ok(parsed) if parsed.len() == 1 => {
                    merged.push(current_range);
                    break;
                }
                // Either parsed multiple statements, zero statements, or failed to parse.
                // Extend the range by including the next semicolon-delimited segment and retry.
                _ => {
                    if range_index >= statement_ranges.len() {
                        return Err(RangeAlignmentError::MergeFailed);
                    }
                    // Merge current range with the next range
                    current_range = current_range.start..statement_ranges[range_index].end;
                    range_index += 1;
                }
            }
        }
    }

    // Verify we consumed all ranges - if not, the merge logic is incorrect
    if range_index != statement_ranges.len() {
        return Err(RangeAlignmentError::MergeFailed);
    }

    Ok(merged)
}

/// Parses SQL slices defined by `statement_ranges`, recording parse errors per slice.
fn parse_statement_ranges_best_effort<'a>(
    ctx: &ParseContext<'a>,
    statement_ranges: Vec<Range<usize>>,
) -> (Vec<StatementInput<'a>>, Vec<Issue>) {
    let mut statements = Vec::new();
    let mut issues = Vec::new();

    let source_sql_ref: &str = &ctx.source_sql;
    let aligned_untemplated_ranges = ctx.untemplated_sql.as_deref().and_then(|sql| {
        let ranges = compute_statement_ranges_for_dialect(sql, ctx.dialect).ok()?;
        align_statement_ranges(sql, &ranges, ctx.dialect, statement_ranges.len()).ok()
    });

    for (range_index, range) in statement_ranges.into_iter().enumerate() {
        // Skip invalid ranges
        if range.start > range.end || range.end > source_sql_ref.len() {
            continue;
        }

        let statement_sql = &source_sql_ref[range.clone()];
        let original_range = aligned_untemplated_ranges
            .as_ref()
            .and_then(|ranges| ranges.get(range_index).cloned());

        match parse_input_statement_with_dialect_output(statement_sql, ctx.dialect) {
            Ok(InputParseOutput::ExternalMetadata(metadata, parser_fallback_used)) => {
                statements.push(StatementInput {
                    statement: StatementInputKind::ExternalMetadata(metadata),
                    source_name: ctx.source_name.clone(),
                    source_sql: ctx.source_sql.clone(),
                    source_range: range.clone(),
                    source_sql_untemplated: ctx.untemplated_sql.clone(),
                    source_range_untemplated: original_range.clone(),
                    templating_applied: ctx.templating_applied,
                    parser_fallback_used,
                });
            }
            Ok(InputParseOutput::ParsedSql(parsed_output)) => {
                let parser_fallback_used = parsed_output.parser_fallback_used;

                // Typically one statement per range, but handle multiple if present
                for stmt in parsed_output.statements {
                    statements.push(StatementInput {
                        statement: StatementInputKind::Parsed(Box::new(stmt)),
                        source_name: ctx.source_name.clone(),
                        source_sql: ctx.source_sql.clone(),
                        source_range: range.clone(),
                        source_sql_untemplated: ctx.untemplated_sql.clone(),
                        source_range_untemplated: None,
                        templating_applied: ctx.templating_applied,
                        parser_fallback_used,
                    });
                }
            }
            Err(InputParseError::ExternalMetadata(error)) => {
                let message = match ctx.source_name.as_deref() {
                    Some(name) => format!("Parse error in {name}: {error}"),
                    None => format!("Parse error: {error}"),
                };
                let issue_range = original_range.as_ref().unwrap_or(&range);
                let mut issue = Issue::error(issue_codes::PARSE_ERROR, message)
                    .with_span(Span::new(issue_range.start, issue_range.end));
                if let Some(name) = ctx.source_name.as_deref() {
                    issue = issue.with_source_name(name);
                }
                issues.push(issue);
            }
            Err(InputParseError::Parser(error)) => {
                // Record the parse error but continue with remaining statements
                let message = match ctx.source_name.as_deref() {
                    Some(name) => format!("Parse error in {name}: {error}"),
                    None => format!("Parse error: {error}"),
                };

                let mut issue = Issue::error(issue_codes::PARSE_ERROR, message)
                    .with_span(Span::new(range.start, range.end));
                if let Some(name) = ctx.source_name.as_deref() {
                    issue = issue.with_source_name(name);
                }
                issues.push(issue);
            }
        }
    }

    (statements, issues)
}

/// Parse MSSQL input by preserving complete `BEGIN`/`END` blocks during recovery.
///
/// The general statement splitter is intentionally dialect-neutral and splits at
/// semicolons. That is useful for ordinary statements, but after a failed
/// whole-buffer parse it can tear a T-SQL procedure or control-flow block into
/// invalid fragments. Merge those fragments back into balanced blocks before
/// retrying them individually; never suppress a real parser error.
fn parse_mssql_ranges_best_effort<'a>(
    ctx: &ParseContext<'a>,
    statement_ranges: Vec<Range<usize>>,
) -> (Vec<StatementInput<'a>>, Vec<Issue>) {
    parse_statement_ranges_best_effort(ctx, statement_ranges)
}

fn merge_mssql_block_ranges(
    sql: &str,
    ranges: Vec<Range<usize>>,
    go_ranges: &[Range<usize>],
) -> Vec<Range<usize>> {
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    let mut block_depth = 0usize;
    let mut batch_index = 0usize;
    let mut go_index = 0usize;
    let mut current_range_has_block = false;

    for range in ranges {
        while go_index < go_ranges.len() && go_ranges[go_index].end <= range.start {
            go_index += 1;
        }
        let next_batch_index = go_index;
        if next_batch_index != batch_index {
            block_depth = 0;
            batch_index = next_batch_index;
            current_range_has_block = false;
        }

        let text = &sql[range.clone()];
        let block_depth_before = block_depth;
        let next_block_depth = mssql_update_block_depth(text, block_depth);
        let begins_block = next_block_depth > block_depth_before;

        if let Some(current) = merged.last_mut() {
            if block_depth > 0 && current_range_has_block && batch_index == next_batch_index {
                current.end = range.end;
                current_range_has_block |= begins_block;
            } else {
                merged.push(range);
                current_range_has_block = begins_block;
            }
        } else {
            merged.push(range);
            current_range_has_block = begins_block;
        }

        block_depth = next_block_depth;
    }

    merged
}

fn mssql_update_block_depth(sql: &str, mut block_depth: usize) -> usize {
    let mut tokenizer = Tokenizer::new(&MsSqlDialect {}, sql);
    let Ok(tokens) = tokenizer.tokenize_with_location() else {
        return block_depth;
    };

    let mut case_depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() {
            continue;
        }
        if word.value.eq_ignore_ascii_case("CASE") {
            case_depth += 1;
        } else if word.value.eq_ignore_ascii_case("END") {
            if case_depth > 0 {
                case_depth -= 1;
            } else if !mssql_word_follows(&tokens, index, "CONVERSATION") {
                block_depth = block_depth.saturating_sub(1);
            }
        } else if word.value.eq_ignore_ascii_case("BEGIN")
            && !mssql_word_follows_any(
                &tokens,
                index,
                &[
                    "TRAN",
                    "TRANSACTION",
                    "DIALOG",
                    "DISTRIBUTED",
                    "CONVERSATION",
                ],
            )
        {
            block_depth += 1;
        }
    }
    block_depth
}

fn mssql_word_follows(
    tokens: &[sqlparser::tokenizer::TokenWithSpan],
    index: usize,
    expected: &str,
) -> bool {
    mssql_word_follows_any(tokens, index, &[expected])
}

fn mssql_word_follows_any(
    tokens: &[sqlparser::tokenizer::TokenWithSpan],
    index: usize,
    expected: &[&str],
) -> bool {
    tokens[index + 1..]
        .iter()
        .find_map(|token| match &token.token {
            Token::Whitespace(_) => None,
            Token::Word(word) if word.quote_style.is_none() => Some(word.value.as_str()),
            Token::Word(_) => Some(""),
            _ => Some(""),
        })
        .is_some_and(|next| expected.iter().any(|word| next.eq_ignore_ascii_case(word)))
}

pub(crate) fn split_statement_spans_with_dialect(
    sql: &str,
    dialect: Dialect,
) -> Result<Vec<Span>, ()> {
    compute_statement_ranges_for_dialect(sql, dialect).map(|ranges| {
        ranges
            .into_iter()
            .map(|range| Span::new(range.start, range.end))
            .collect()
    })
}

fn compute_statement_ranges_for_dialect(
    sql: &str,
    dialect: Dialect,
) -> Result<Vec<Range<usize>>, ()> {
    compute_statement_ranges_for_dialect_with_limit(
        sql,
        dialect,
        MAX_MSSQL_EXPANDED_STATEMENT_RANGES,
    )
}

pub(crate) fn mssql_statement_ranges_without_go(sql: &str) -> Result<Vec<Range<usize>>, ()> {
    let ranges = compute_statement_ranges_mssql(sql, 0, 0, MAX_MSSQL_EXPANDED_STATEMENT_RANGES)?;
    let block_ranges = merge_mssql_block_ranges(sql, ranges, &[]);
    split_mssql_optional_statement_ranges(sql, block_ranges, MAX_MSSQL_EXPANDED_STATEMENT_RANGES)
}

pub(crate) fn statement_ranges_contain_external_metadata(
    sql: &str,
    statement_ranges: &[Range<usize>],
) -> bool {
    statement_ranges.iter().any(|range| {
        sql.get(range.clone()).is_some_and(|statement_sql| {
            !matches!(parse_external_metadata_statement(statement_sql), Ok(None))
        })
    })
}

fn compute_statement_ranges_for_dialect_with_limit(
    sql: &str,
    dialect: Dialect,
    max_ranges: usize,
) -> Result<Vec<Range<usize>>, ()> {
    if !matches!(dialect, Dialect::Mssql) {
        return Ok(compute_statement_ranges(sql));
    }
    let separators = mssql_go_separators(sql)?;
    let go_ranges: Vec<_> = separators
        .iter()
        .map(|separator| separator.range.clone())
        .collect();
    let batch_ranges = if separators.is_empty() {
        compute_statement_ranges_mssql(sql, 0, 0, max_ranges)?
    } else {
        split_ranges_on_mssql_go_separators(sql, &separators, max_ranges)?
    };
    let block_ranges = merge_mssql_block_ranges(sql, batch_ranges, &go_ranges);
    split_mssql_optional_statement_ranges(sql, block_ranges, max_ranges)
}

fn split_mssql_optional_statement_ranges(
    sql: &str,
    ranges: Vec<Range<usize>>,
    max_ranges: usize,
) -> Result<Vec<Range<usize>>, ()> {
    let mut split_ranges = Vec::with_capacity(ranges.len());
    for range in ranges {
        let statement_sql = sql.get(range.clone()).ok_or(())?;
        let Ok(tokens) = Tokenizer::new(&MsSqlDialect {}, statement_sql).tokenize_with_location()
        else {
            push_statement_range(&mut split_ranges, sql, range.start, range.end);
            continue;
        };

        let mut current_start = 0usize;
        let mut previous_significant = None;
        let mut block_depth = 0usize;
        let mut case_depth = 0usize;
        let mut parenthesis_depth = 0usize;
        for (index, token) in tokens.iter().enumerate() {
            if matches!(token.token, Token::LParen) {
                parenthesis_depth += 1;
                previous_significant = Some(index);
                continue;
            }
            if matches!(token.token, Token::RParen) {
                parenthesis_depth = parenthesis_depth.saturating_sub(1);
                previous_significant = Some(index);
                continue;
            }
            let Token::Word(word) = &token.token else {
                if !matches!(token.token, Token::Whitespace(_)) {
                    previous_significant = Some(index);
                }
                continue;
            };
            if word.quote_style.is_some() {
                previous_significant = Some(index);
                continue;
            }

            if block_depth == 0
                && parenthesis_depth == 0
                && is_mssql_optional_statement_start(&word.value)
                && previous_significant.is_some_and(|previous| {
                    token.span.start.line > tokens[previous].span.end.line
                        && mssql_token_can_end_statement(&tokens[previous].token)
                })
            {
                if let Some(local_range) = mssql_token_byte_range(statement_sql, token) {
                    let prefix = statement_sql
                        .get(current_start..local_range.start)
                        .ok_or(())?;
                    if mssql_fragment_is_one_statement(prefix) {
                        push_statement_range(
                            &mut split_ranges,
                            sql,
                            range.start + current_start,
                            range.start + local_range.start,
                        );
                        current_start = local_range.start;
                        if split_ranges.len() > max_ranges {
                            return Err(());
                        }
                    }
                }
            }

            if word.value.eq_ignore_ascii_case("CASE") {
                case_depth += 1;
            } else if word.value.eq_ignore_ascii_case("END") {
                if case_depth > 0 {
                    case_depth -= 1;
                } else if !mssql_word_follows(&tokens, index, "CONVERSATION") {
                    block_depth = block_depth.saturating_sub(1);
                }
            } else if word.value.eq_ignore_ascii_case("BEGIN")
                && !mssql_word_follows_any(
                    &tokens,
                    index,
                    &[
                        "TRAN",
                        "TRANSACTION",
                        "DIALOG",
                        "DISTRIBUTED",
                        "CONVERSATION",
                    ],
                )
            {
                block_depth += 1;
            }
            previous_significant = Some(index);
        }
        push_statement_range(
            &mut split_ranges,
            sql,
            range.start + current_start,
            range.end,
        );
        if split_ranges.len() > max_ranges {
            return Err(());
        }
    }
    Ok(split_ranges)
}

fn mssql_token_can_end_statement(token: &Token) -> bool {
    match token {
        Token::Word(word) if word.quote_style.is_none() => ![
            "AND",
            "AS",
            "BETWEEN",
            "BY",
            "CASE",
            "ELSE",
            "EXCEPT",
            "FROM",
            "GROUP",
            "HAVING",
            "IN",
            "INTERSECT",
            "IS",
            "JOIN",
            "LIKE",
            "NOT",
            "ON",
            "OR",
            "ORDER",
            "SELECT",
            "THEN",
            "UNION",
            "VALUES",
            "WHEN",
            "WHERE",
            "WITH",
        ]
        .iter()
        .any(|keyword| word.value.eq_ignore_ascii_case(keyword)),
        Token::Word(_)
        | Token::Number(_, _)
        | Token::SingleQuotedString(_)
        | Token::NationalStringLiteral(_)
        | Token::RParen
        | Token::SemiColon => true,
        _ => false,
    }
}

fn is_mssql_optional_statement_start(word: &str) -> bool {
    [
        "ALTER",
        "BACKUP",
        "BEGIN",
        "CREATE",
        "DECLARE",
        "DELETE",
        "DROP",
        "EXEC",
        "EXECUTE",
        "GRANT",
        "IF",
        "INSERT",
        "MERGE",
        "PRINT",
        "RAISERROR",
        "RESTORE",
        "RETURN",
        "REVOKE",
        "SELECT",
        "SET",
        "THROW",
        "TRUNCATE",
        "UPDATE",
        "USE",
        "WHILE",
    ]
    .iter()
    .any(|keyword| word.eq_ignore_ascii_case(keyword))
}

fn mssql_fragment_is_one_statement(sql: &str) -> bool {
    match parse_input_statement_with_dialect_output(sql, Dialect::Mssql) {
        Ok(InputParseOutput::ParsedSql(output)) => output.statements.len() == 1,
        Ok(InputParseOutput::ExternalMetadata(_, _)) => true,
        Err(_) => false,
    }
}

pub(crate) fn mssql_ranges_have_optional_separators(sql: &str, ranges: &[Range<usize>]) -> bool {
    ranges.windows(2).any(|pair| {
        let Some(gap) = sql.get(pair[0].end..pair[1].start) else {
            return false;
        };
        if !gap.contains(['\n', '\r']) {
            return false;
        }
        Tokenizer::new(&MsSqlDialect {}, gap)
            .tokenize_with_location()
            .is_ok_and(|tokens| {
                tokens
                    .iter()
                    .all(|token| matches!(token.token, Token::Whitespace(_)))
            })
    })
}

#[derive(Clone, Debug)]
struct MssqlGoSeparator {
    range: Range<usize>,
    repeat_count: usize,
    comment_depth_after_line: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MssqlLexState {
    Normal,
    SingleQuote,
    DoubleQuote,
    BracketIdentifier,
    LineComment,
    BlockComment(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MssqlGoLine {
    Separator(usize),
    OverLimit,
    Invalid,
}

fn split_ranges_on_mssql_go_separators(
    sql: &str,
    separators: &[MssqlGoSeparator],
    max_ranges: usize,
) -> Result<Vec<Range<usize>>, ()> {
    let mut out = Vec::new();
    let mut batch_start = 0usize;
    let mut comment_depth = 0usize;
    for separator in separators {
        let batch_end = separator.range.start;
        let batch = sql.get(batch_start..batch_end).unwrap_or_default();
        let remaining = max_ranges.saturating_sub(out.len());
        let batch_ranges =
            compute_statement_ranges_mssql(batch, batch_start, comment_depth, remaining)?;
        let expanded_count = batch_ranges
            .len()
            .checked_mul(separator.repeat_count)
            .and_then(|count| out.len().checked_add(count));
        if expanded_count.is_none_or(|count| count > max_ranges) {
            return Err(());
        }
        for _ in 0..separator.repeat_count {
            out.extend(batch_ranges.iter().cloned());
        }
        batch_start = separator.range.end;
        comment_depth = separator.comment_depth_after_line;
    }

    let batch = sql.get(batch_start..).unwrap_or_default();
    let trailing_ranges = compute_statement_ranges_mssql(
        batch,
        batch_start,
        comment_depth,
        max_ranges.saturating_sub(out.len()),
    )?;
    if out
        .len()
        .checked_add(trailing_ranges.len())
        .is_none_or(|count| count > max_ranges)
    {
        return Err(());
    }
    out.extend(trailing_ranges);

    Ok(out)
}

fn compute_statement_ranges_mssql(
    sql: &str,
    offset: usize,
    initial_block_comment_depth: usize,
    max_ranges: usize,
) -> Result<Vec<Range<usize>>, ()> {
    let mut ranges =
        compute_statement_ranges_with_mssql_comment_depth(sql, initial_block_comment_depth);
    if ranges.len() > max_ranges {
        return Err(());
    }
    for range in &mut ranges {
        range.start += offset;
        range.end += offset;
    }
    Ok(ranges)
}

fn mssql_go_separators(sql: &str) -> Result<Vec<MssqlGoSeparator>, ()> {
    let bytes = sql.as_bytes();
    let mut separators = Vec::new();
    let mut state = MssqlLexState::Normal;
    let mut line_start = 0usize;

    while line_start < bytes.len() {
        let newline = bytes[line_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| line_start + offset);
        let line_end = newline.unwrap_or(bytes.len());
        let line_range_end = newline.map_or(bytes.len(), |index| index + 1);
        let line = sql.get(line_start..line_end).unwrap_or_default();

        let separator_repeat_count = if state == MssqlLexState::Normal {
            match parse_mssql_go_line(line) {
                MssqlGoLine::Separator(repeat_count) => Some(repeat_count),
                MssqlGoLine::OverLimit => return Err(()),
                MssqlGoLine::Invalid => None,
            }
        } else {
            None
        };

        scan_mssql_lex_state(bytes, line_start, line_end, &mut state);
        if newline.is_some() && state == MssqlLexState::LineComment {
            state = MssqlLexState::Normal;
        }
        if let Some(repeat_count) = separator_repeat_count {
            let comment_depth_after_line = match state {
                MssqlLexState::BlockComment(depth) => depth,
                _ => 0,
            };
            separators.push(MssqlGoSeparator {
                range: line_start..line_range_end,
                repeat_count,
                comment_depth_after_line,
            });
            if separators.len() > MAX_MSSQL_GO_SEPARATORS {
                return Err(());
            }
        }
        line_start = line_range_end;
    }

    Ok(separators)
}

fn parse_mssql_go_line(line: &str) -> MssqlGoLine {
    let line = line
        .trim_end_matches('\r')
        .trim_start_matches(char::is_whitespace);
    let bytes = line.as_bytes();
    if bytes.len() < 2 || !bytes[..2].eq_ignore_ascii_case(b"GO") {
        return MssqlGoLine::Invalid;
    }
    let mut index = 2usize;
    if index < bytes.len()
        && !bytes[index].is_ascii_whitespace()
        && bytes[index] != b'-'
        && bytes[index] != b'/'
    {
        return MssqlGoLine::Invalid;
    }
    skip_ascii_space(bytes, &mut index);

    let count_start = index;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    let mut over_limit = false;
    let repeat_count = if index > count_start {
        let count = match std::str::from_utf8(&bytes[count_start..index])
            .unwrap_or_default()
            .parse::<usize>()
        {
            Ok(count) => count,
            Err(_) => {
                over_limit = true;
                1
            }
        };
        if !over_limit && count == 0 {
            return MssqlGoLine::Invalid;
        }
        if count > MAX_MSSQL_GO_REPEAT {
            over_limit = true;
        }
        if over_limit {
            1
        } else {
            count
        }
    } else {
        1
    };

    skip_ascii_space(bytes, &mut index);
    while index < bytes.len() {
        if bytes[index..].starts_with(b"--") {
            return if over_limit {
                MssqlGoLine::OverLimit
            } else {
                MssqlGoLine::Separator(repeat_count)
            };
        }
        if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1usize;
            while index < bytes.len() && depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth = depth.saturating_add(1);
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            if depth > 0 {
                // A block comment may continue on subsequent lines. The GO line
                // remains valid, and the lexical scanner carries that comment state.
                return if over_limit {
                    MssqlGoLine::OverLimit
                } else {
                    MssqlGoLine::Separator(repeat_count)
                };
            }
            skip_ascii_space(bytes, &mut index);
            continue;
        }
        return MssqlGoLine::Invalid;
    }
    if over_limit {
        MssqlGoLine::OverLimit
    } else {
        MssqlGoLine::Separator(repeat_count)
    }
}

fn skip_ascii_space(bytes: &[u8], index: &mut usize) {
    while bytes.get(*index).is_some_and(u8::is_ascii_whitespace) {
        *index += 1;
    }
}

fn scan_mssql_lex_state(bytes: &[u8], start: usize, end: usize, state: &mut MssqlLexState) {
    let mut index = start;
    while index < end {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match *state {
            MssqlLexState::Normal => match (byte, next) {
                (b'-', Some(b'-')) => {
                    *state = MssqlLexState::LineComment;
                    index += 2;
                }
                (b'/', Some(b'*')) => {
                    *state = MssqlLexState::BlockComment(1);
                    index += 2;
                }
                (b'\'', _) => {
                    *state = MssqlLexState::SingleQuote;
                    index += 1;
                }
                (b'"', _) => {
                    *state = MssqlLexState::DoubleQuote;
                    index += 1;
                }
                (b'[', _) => {
                    *state = MssqlLexState::BracketIdentifier;
                    index += 1;
                }
                _ => index += 1,
            },
            MssqlLexState::SingleQuote => {
                if byte == b'\'' && next == Some(b'\'') {
                    index += 2;
                } else {
                    if byte == b'\'' {
                        *state = MssqlLexState::Normal;
                    }
                    index += 1;
                }
            }
            MssqlLexState::DoubleQuote => {
                if byte == b'"' && next == Some(b'"') {
                    index += 2;
                } else {
                    if byte == b'"' {
                        *state = MssqlLexState::Normal;
                    }
                    index += 1;
                }
            }
            MssqlLexState::BracketIdentifier => {
                if byte == b']' && next == Some(b']') {
                    index += 2;
                } else {
                    if byte == b']' {
                        *state = MssqlLexState::Normal;
                    }
                    index += 1;
                }
            }
            MssqlLexState::LineComment => break,
            MssqlLexState::BlockComment(depth) => match (byte, next) {
                (b'/', Some(b'*')) => {
                    *state = MssqlLexState::BlockComment(depth.saturating_add(1));
                    index += 2;
                }
                (b'*', Some(b'/')) => {
                    *state = if depth == 1 {
                        MssqlLexState::Normal
                    } else {
                        MssqlLexState::BlockComment(depth - 1)
                    };
                    index += 2;
                }
                _ => index += 1,
            },
        }
    }
}

/// Split SQL text into statement ranges by finding semicolons outside of strings/comments.
///
/// # Design Decision: Character-Level State Machine
///
/// This function intentionally uses a character-by-character state machine rather than
/// leveraging sqlparser's tokenizer. This is necessary for several reasons:
///
/// 1. **Pre-tokenization requirement**: Statement splitting must happen *before* parsing
///    because some analysis modes need statement boundaries before the dialect is
///    determined. This is a chicken-and-egg problem where we can't tokenize without
///    knowing the dialect, but we may need statement boundaries to help determine context.
///
/// 2. **Error tolerance**: The parser/tokenizer may fail on incomplete or invalid SQL,
///    but we still need to identify statement boundaries for partial analysis, error
///    recovery, and editor features like completions that work with incomplete input.
///
/// 3. **Multi-dialect support**: The state machine handles quoting styles from multiple
///    dialects simultaneously (double quotes, single quotes, backticks, brackets),
///    allowing statement splitting to work regardless of dialect.
///
/// 4. **Dollar-quoted strings**: PostgreSQL's `$tag$...$tag$` strings require special
///    handling that's simpler to implement in a dedicated state machine.
///
/// # Note on Alternatives
///
/// While it might seem cleaner to use sqlparser's tokenizer (which properly handles
/// all these cases), the tokenizer is designed to work on single statements and may
/// fail on multi-statement input with syntax errors. This function is specifically
/// designed to be resilient to partial/invalid SQL.
///
/// A future improvement could use error-recovering tokenization when available in
/// sqlparser, but for now this manual approach provides the most reliable results
/// for the analysis use cases.
fn compute_statement_ranges(sql: &str) -> Vec<Range<usize>> {
    compute_statement_ranges_with_mssql_comment_depth(sql, 0)
}

fn compute_statement_ranges_with_mssql_comment_depth(
    sql: &str,
    initial_block_comment_depth: usize,
) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    if sql.is_empty() {
        return ranges;
    }

    let mut start = if initial_block_comment_depth > 0 {
        None
    } else {
        Some(0usize)
    };
    let mut i = 0usize;
    let len = sql.len();

    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_backtick = false;
    let mut in_bracket = false;
    let mut in_line_comment = false;
    let mut block_comment_depth = initial_block_comment_depth;
    let mut dollar_delimiter: Option<String> = None;

    while i < len {
        if let Some(delim) = &dollar_delimiter {
            if sql[i..].starts_with(delim) {
                i += delim.len();
                dollar_delimiter = None;
            } else {
                let (_, advance) = next_char(sql, i);
                i += advance;
            }
            continue;
        }

        if in_line_comment {
            let (ch, advance) = next_char(sql, i);
            i += advance;
            if ch == '\n' || ch == '\r' {
                in_line_comment = false;
            }
            continue;
        }

        if block_comment_depth > 0 {
            if starts_with_at(sql, i, "/*") {
                i += 2;
                block_comment_depth = block_comment_depth.saturating_add(1);
            } else if starts_with_at(sql, i, "*/") {
                i += 2;
                block_comment_depth -= 1;
                if block_comment_depth == 0 && start.is_none() {
                    start = Some(i);
                }
            } else {
                let (_, advance) = next_char(sql, i);
                i += advance;
            }
            continue;
        }

        if in_single_quote {
            let (ch, advance) = next_char(sql, i);
            i += advance;
            if ch == '\'' {
                if let Some((next, next_len)) = char_at(sql, i) {
                    if next == '\'' {
                        i += next_len;
                    } else {
                        in_single_quote = false;
                    }
                } else {
                    in_single_quote = false;
                }
            }
            continue;
        }

        if in_double_quote {
            let (ch, advance) = next_char(sql, i);
            i += advance;
            if ch == '"' {
                if let Some((next, next_len)) = char_at(sql, i) {
                    if next == '"' {
                        i += next_len;
                    } else {
                        in_double_quote = false;
                    }
                } else {
                    in_double_quote = false;
                }
            }
            continue;
        }

        if in_backtick {
            let (ch, advance) = next_char(sql, i);
            i += advance;
            if ch == '`' {
                if let Some((next, next_len)) = char_at(sql, i) {
                    if next == '`' {
                        i += next_len;
                    } else {
                        in_backtick = false;
                    }
                } else {
                    in_backtick = false;
                }
            }
            continue;
        }

        if in_bracket {
            let (ch, advance) = next_char(sql, i);
            i += advance;
            if ch == ']' {
                if let Some((next, next_len)) = char_at(sql, i) {
                    if next == ']' {
                        i += next_len;
                    } else {
                        in_bracket = false;
                    }
                } else {
                    in_bracket = false;
                }
            }
            continue;
        }

        let (ch, advance) = next_char(sql, i);
        match ch {
            '\'' => {
                in_single_quote = true;
                i += advance;
                continue;
            }
            '"' => {
                in_double_quote = true;
                i += advance;
                continue;
            }
            '`' => {
                in_backtick = true;
                i += advance;
                continue;
            }
            '[' => {
                in_bracket = true;
                i += advance;
                continue;
            }
            '-' if starts_with_at(sql, i + advance, "-") => {
                in_line_comment = true;
                i += advance + 1;
                continue;
            }
            '#' => {
                in_line_comment = true;
                i += advance;
                continue;
            }
            '/' if starts_with_at(sql, i + advance, "*") => {
                block_comment_depth = 1;
                i += advance + 1;
                continue;
            }
            '$' => {
                if let Some((delim, end_idx)) = detect_dollar_quote(sql, i) {
                    dollar_delimiter = Some(delim);
                    i = end_idx;
                    continue;
                }
            }
            ';' => {
                if let Some(statement_start) = start {
                    push_statement_range(&mut ranges, sql, statement_start, i);
                }
                start = Some(i + advance);
            }
            _ => {}
        }

        i += advance;
    }

    if let Some(statement_start) = start {
        push_statement_range(&mut ranges, sql, statement_start, len);
    }
    ranges
}

fn detect_dollar_quote(sql: &str, start: usize) -> Option<(String, usize)> {
    let len = sql.len();
    if start + 1 >= len {
        return None;
    }

    let mut idx = start + 1;
    while idx < len {
        let (ch, advance) = next_char(sql, idx);
        idx += advance;
        if ch == '$' {
            let delimiter = sql[start..idx].to_string();
            return Some((delimiter, idx));
        }
        if !(ch == '_' || ch.is_ascii_alphanumeric()) {
            return None;
        }
    }

    None
}

fn starts_with_at(sql: &str, index: usize, pattern: &str) -> bool {
    if index >= sql.len() {
        return false;
    }
    if !sql.is_char_boundary(index) {
        return false;
    }
    sql[index..].starts_with(pattern)
}

fn next_char(sql: &str, index: usize) -> (char, usize) {
    debug_assert!(sql.is_char_boundary(index));
    let mut iter = sql[index..].char_indices();
    let (_, ch) = iter.next().expect("index should point to a char boundary");
    let advance = ch.len_utf8();
    (ch, advance)
}

fn char_at(sql: &str, index: usize) -> Option<(char, usize)> {
    if index >= sql.len() {
        return None;
    }
    if !sql.is_char_boundary(index) {
        return None;
    }
    let mut iter = sql[index..].char_indices();
    let (_, ch) = iter.next().expect("index should point to a char boundary");
    let advance = ch.len_utf8();
    Some((ch, advance))
}

fn push_statement_range(ranges: &mut Vec<Range<usize>>, sql: &str, start: usize, end: usize) {
    if let Some(range) = trim_statement_range(sql, start, end) {
        ranges.push(range);
    }
}

fn trim_statement_range(sql: &str, start: usize, end: usize) -> Option<Range<usize>> {
    if start >= end {
        return None;
    }

    let mut s = start;
    let mut e = end;

    let bytes = sql.as_bytes();

    while s < e {
        if s + 1 < e {
            let first = bytes[s];
            let second = bytes[s + 1];
            if first == b'-' && second == b'-' {
                s = skip_line_comment(bytes, s + 2, e);
                continue;
            }
            if first == b'/' && second == b'*' {
                s = skip_block_comment(bytes, s + 2, e);
                continue;
            }
        }

        let b = bytes[s];
        match b {
            b'#' => {
                s = skip_line_comment(bytes, s + 1, e);
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                s += 1;
            }
            _ => break,
        }
    }

    while s < e {
        let b = bytes[e - 1];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => {
                e -= 1;
            }
            _ => break,
        }
    }

    if s >= e {
        return None;
    }

    Some(s..e)
}

fn skip_line_comment(bytes: &[u8], mut index: usize, end: usize) -> usize {
    while index < end {
        let byte = bytes[index];
        index += 1;
        if byte == b'\n' || byte == b'\r' {
            break;
        }
    }
    index
}

fn skip_block_comment(bytes: &[u8], mut index: usize, end: usize) -> usize {
    while index < end {
        if index + 1 < end && bytes[index] == b'*' && bytes[index + 1] == b'/' {
            return index + 2;
        }
        index += 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Dialect, FileSource};
    use sqlparser::ast::{SetExpr, TableFactor};

    fn base_request() -> AnalyzeRequest {
        AnalyzeRequest {
            sql: String::new(),
            files: None,
            dialect: Dialect::Generic,
            source_name: None,
            options: None,
            schema: None,
            #[cfg(feature = "templating")]
            template_config: None,
        }
    }

    fn openrowset_schema_types(statement: &Statement) -> Vec<Vec<(String, Option<String>)>> {
        #[derive(Default)]
        struct SchemaCollector {
            schemas: Vec<Vec<(String, Option<String>)>>,
        }

        impl VisitorMut for SchemaCollector {
            type Break = ();

            fn pre_visit_table_factor(
                &mut self,
                table_factor: &mut TableFactor,
            ) -> ControlFlow<Self::Break> {
                if let TableFactor::Table {
                    name,
                    alias: Some(alias),
                    ..
                } = table_factor
                {
                    if name
                        .0
                        .first()
                        .and_then(|part| part.as_ident())
                        .is_some_and(|ident| ident.value.eq_ignore_ascii_case("OPENROWSET"))
                    {
                        self.schemas.push(
                            alias
                                .columns
                                .iter()
                                .map(|column| {
                                    (
                                        column.name.value.clone(),
                                        column.data_type.as_ref().map(ToString::to_string),
                                    )
                                })
                                .collect(),
                        );
                    }
                }
                ControlFlow::Continue(())
            }
        }

        let mut statement = statement.clone();
        let mut collector = SchemaCollector::default();
        let _ = statement.visit(&mut collector);
        collector.schemas
    }

    #[test]
    fn mssql_synapse_openrowset_parsing_preserves_ast_and_source_offsets() {
        let sql = concat!(
            "-- café\r\n",
            "SELECT file.id FROM OPENROWSET(",
            "BULK 'https://storage.example/container/*.parquet', ",
            "DATA_SOURCE = 'lake', FORMAT = 'PARQUET'",
            ") AS [file]"
        );
        assert!(
            parse_sql_with_dialect_output(sql, Dialect::Mssql).is_err(),
            "the upstream MSSQL parser currently rejects Synapse's OPENROWSET option syntax"
        );

        let _compatible_tokens =
            mssql_openrowset_compatible_tokens(sql).expect("recognized Synapse OPENROWSET syntax");

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse with bounded Synapse syntax adaptation");
        assert!(output.parser_fallback_used);
        assert_eq!(output.statements.len(), 1);
        let Statement::Query(query) = &output.statements[0] else {
            panic!("expected SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        let TableFactor::Table {
            name,
            args: Some(args),
            alias: Some(alias),
            ..
        } = &select.from[0].relation
        else {
            panic!("expected OPENROWSET table-valued function");
        };
        assert_eq!(name.to_string(), "OPENROWSET");
        assert_eq!(alias.name.value, "file");
        assert_eq!(
            args.args
                .iter()
                .map(|argument| match argument {
                    sqlparser::ast::FunctionArg::ExprNamed {
                        name: sqlparser::ast::Expr::Identifier(name),
                        operator: sqlparser::ast::FunctionArgOperator::Colon,
                        ..
                    } => name.value.to_ascii_uppercase(),
                    other => panic!("expected preserved named argument, got {other:?}"),
                })
                .collect::<Vec<_>>(),
            vec![
                "BULK".to_string(),
                "DATA_SOURCE".to_string(),
                "FORMAT".to_string(),
            ]
        );

        let csv_sql = concat!(
            "SELECT csv_row.id FROM OPENROWSET(",
            "BULK 'https://storage.example/container/*.csv', ",
            "FORMAT = 'CSV', PARSER_VERSION = '2.0', HEADER_ROW = TRUE, ",
            "FIELDTERMINATOR = '|'",
            ") AS csv_row"
        );
        let csv_output = parse_input_sql_with_dialect_output(csv_sql, Dialect::Mssql)
            .expect("parse canonical Synapse CSV OPENROWSET");
        assert_eq!(csv_output.statements.len(), 1);
        assert!(csv_output.parser_fallback_used);
    }

    #[test]
    fn mssql_synapse_openrowset_accepts_data_source_after_format() {
        let sql = concat!(
            "-- café\r\n",
            "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', ",
            "DATA_SOURCE = 'lake') AS r"
        );
        let _compatible_tokens =
            mssql_openrowset_compatible_tokens(sql).expect("recognized Synapse option ordering");

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse FORMAT-before-DATA_SOURCE Synapse syntax");
        assert!(output.parser_fallback_used);
        assert_eq!(output.statements.len(), 1);
        let Statement::Query(query) = &output.statements[0] else {
            panic!("expected SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        let TableFactor::Table {
            args: Some(args), ..
        } = &select.from[0].relation
        else {
            panic!("expected OPENROWSET table-valued function");
        };
        let argument_names: Vec<_> = args
            .args
            .iter()
            .map(|argument| match argument {
                sqlparser::ast::FunctionArg::ExprNamed {
                    name: sqlparser::ast::Expr::Identifier(name),
                    operator: sqlparser::ast::FunctionArgOperator::Colon,
                    ..
                } => name.value.to_ascii_uppercase(),
                other => panic!("expected preserved named argument, got {other:?}"),
            })
            .collect();
        assert_eq!(argument_names, ["BULK", "FORMAT", "DATA_SOURCE"]);

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_string();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(analysis.statements.len(), 1);
        assert_eq!(
            analysis.statements[0].span,
            Some(Span::new(
                sql.find("SELECT").expect("query start"),
                sql.len()
            ))
        );
        assert!(
            !analysis
                .issues
                .iter()
                .any(|issue| issue.code == issue_codes::PARSE_ERROR),
            "accepted option ordering must preserve analysis source spans: {:?}",
            analysis.issues
        );

        for malformed in [
            "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', DATA_SOURCE = 'lake') AS r",
            "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', DATA_SOURCE = 'lake', DATA_SOURCE = 'lake2') AS r",
            "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', DATA_SOURCE = 'lake', FORMAT = 'CSV') AS r",
            "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', DATA_SOURCE = 'lake', FORMAT = 'PARQUET', DATA_SOURCE = 'lake2') AS r",
            "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', DATA_SOURCE = 1) AS r",
            "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', DATA_SOURCE = 'lake', UNKNOWN = 'x') AS r",
        ] {
            assert!(
                mssql_openrowset_compatible_tokens(malformed).is_none(),
                "malformed options must not use the compatibility adapter: {malformed}"
            );
            assert!(
                parse_input_sql_with_dialect_output(malformed, Dialect::Mssql).is_err(),
                "malformed options must remain parser errors: {malformed}"
            );
        }
        let malformed = "SELECT r.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', DATA_SOURCE = 1) AS r";
        let error = parse_input_sql_with_dialect_output(malformed, Dialect::Mssql)
            .err()
            .expect("invalid DATA_SOURCE value must remain an error");
        assert!(error.position.is_some());

        assert_eq!(
            parse_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            parse_input_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            "the MSSQL adapter must not change generic-dialect parsing"
        );
    }

    #[test]
    fn mssql_synapse_openrowset_preserves_observed_csv_options() {
        let sql = concat!(
            "-- café\r\n",
            "SELECT records.record_id FROM OPENROWSET(\r\n",
            "  BULK N'https://example.invalid/records/*.csv',\r\n",
            "  FORMAT = 'CSV', PARSER_VERSION = '2.0', FIRSTROW = 2,\r\n",
            "  FIELDQUOTE = '\"', ROWTERMINATOR = '0x0A',\r\n",
            "  ROWSET_OPTIONS = '{\"READ_OPTIONS\":[\"ALLOW_INCONSISTENT_READS\"]}'\r\n",
            ") AS records"
        );
        let _compatible_tokens =
            mssql_openrowset_compatible_tokens(sql).expect("recognized Synapse CSV options");

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse CSV rowset options");
        assert!(output.parser_fallback_used);
        let Statement::Query(query) = &output.statements[0] else {
            panic!("expected SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        let TableFactor::Table {
            args: Some(args), ..
        } = &select.from[0].relation
        else {
            panic!("expected OPENROWSET table factor");
        };
        let argument_names: Vec<_> = args
            .args
            .iter()
            .map(|argument| match argument {
                sqlparser::ast::FunctionArg::ExprNamed {
                    name: sqlparser::ast::Expr::Identifier(name),
                    operator: sqlparser::ast::FunctionArgOperator::Colon,
                    ..
                } => name.value.to_ascii_uppercase(),
                other => panic!("expected preserved named argument, got {other:?}"),
            })
            .collect();
        assert_eq!(
            argument_names,
            [
                "BULK",
                "FORMAT",
                "PARSER_VERSION",
                "FIRSTROW",
                "FIELDQUOTE",
                "ROWTERMINATOR",
                "ROWSET_OPTIONS",
            ]
        );

        let malformed =
            "SELECT r.id FROM OPENROWSET(BULK 'data.csv', FORMAT = 'CSV', ROWSET_OPTIONS = TRUE) AS r";
        assert!(mssql_openrowset_compatible_tokens(malformed).is_none());
        let error = parse_input_sql_with_dialect_output(malformed, Dialect::Mssql)
            .err()
            .expect("non-string ROWSET_OPTIONS must remain invalid");
        assert!(error.position.is_some());

        assert_eq!(
            parse_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            parse_input_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            "the MSSQL-only adapter must not change generic-dialect parsing"
        );
    }

    #[test]
    fn mssql_synapse_openrowset_supports_multiple_sources_and_delta_format() {
        let sql = concat!(
            "SELECT csv_row.item_id, delta_row.item_id FROM OPENROWSET(",
            "BULK 'https://example.invalid/csv/*.csv', FORMAT = 'CSV'",
            ") WITH (item_id INT 1) AS csv_row ",
            "JOIN OPENROWSET(",
            "BULK 'https://example.invalid/delta/*.parquet', FORMAT = 'DELTA'",
            ") WITH (item_id BIGINT 1) AS delta_row ",
            "ON csv_row.item_id = delta_row.item_id"
        );
        let _compatible_tokens =
            mssql_openrowset_compatible_tokens(sql).expect("adapt both external rowsets");

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse multiple CSV and Delta rowsets");
        let Statement::Query(query) = &output.statements[0] else {
            panic!("expected SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        let TableFactor::Table {
            alias: Some(csv_alias),
            ..
        } = &select.from[0].relation
        else {
            panic!("expected first OPENROWSET factor");
        };
        assert_eq!(csv_alias.name.value, "csv_row");
        assert_eq!(
            csv_alias.columns[0]
                .data_type
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("INT")
        );

        let TableFactor::Table {
            alias: Some(delta_alias),
            ..
        } = &select.from[0].joins[0].relation
        else {
            panic!("expected joined OPENROWSET factor");
        };
        assert_eq!(delta_alias.name.value, "delta_row");
        assert_eq!(
            delta_alias.columns[0]
                .data_type
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("BIGINT")
        );
    }

    #[test]
    fn mssql_openrowset_schema_collation_preserves_the_declared_type_and_source_range() {
        let sql = concat!(
            "-- café\r\n",
            "SELECT src.c FROM OPENROWSET(",
            "BULK ('data/a.csv'), FORMAT = 'CSV', DATA_SOURCE = 'lake'",
            ") WITH (c VARCHAR(20) COLLATE Latin1_General_100_BIN2_UTF8) AS src"
        );
        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("documented schema collation should be accepted");
        assert!(output.parser_fallback_used);
        let Statement::Query(query) = &output.statements[0] else {
            panic!("expected SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        let TableFactor::Table {
            alias: Some(alias), ..
        } = &select.from[0].relation
        else {
            panic!("expected OPENROWSET table factor");
        };
        assert_eq!(alias.columns.len(), 1);
        assert_eq!(alias.columns[0].name.value, "c");
        assert_eq!(
            alias.columns[0]
                .data_type
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("VARCHAR(20)"),
            "the declared data type must survive the collation adapter"
        );

        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql)
            .expect("valid MSSQL source ranges");
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            &sql[ranges[0].clone()],
            sql.trim_start_matches("-- café\r\n")
        );

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(analysis.statements.len(), 1);
        assert_eq!(
            analysis.statements[0].span,
            Some(Span::new(
                sql.find("SELECT").expect("query start"),
                sql.len()
            )),
            "schema adaptation must retain original UTF-8 source spans"
        );
        assert!(
            !analysis.issues.iter().any(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            }),
            "valid collation syntax must not report a parse error: {:?}",
            analysis.issues
        );

        let malformed = concat!(
            "SELECT src.c FROM OPENROWSET(BULK 'data/a.csv', FORMAT = 'CSV') ",
            "WITH (c VARCHAR(20) COLLATE) AS src"
        );
        assert!(
            parse_input_sql_with_dialect_output(malformed, Dialect::Mssql).is_err(),
            "a missing collation name must remain invalid"
        );
        assert_eq!(
            parse_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            parse_input_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            "the collation adapter must remain MSSQL-only"
        );
    }

    #[test]
    fn mssql_synapse_openrowset_supports_parenthesized_bulk_file_lists() {
        let sql = concat!(
            "-- café\r\n",
            "SELECT src.id FROM OPENROWSET(\r\n",
            "  BULK (\r\n",
            "    N'data/a.parquet', /* preserve list comments */ 'data/b.parquet'\r\n",
            "  ), FORMAT = 'PARQUET'\r\n",
            ") AS src"
        );
        assert!(
            parse_sql_with_dialect_output(sql, Dialect::Mssql).is_ok(),
            "the upstream parser accepts this shape as a BULK function call rather than a Synapse argument"
        );

        let _compatible_tokens =
            mssql_openrowset_compatible_tokens(sql).expect("recognize a Synapse BULK file list");

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse parenthesized Synapse BULK file list");
        assert!(output.parser_fallback_used);
        let Statement::Query(query) = &output.statements[0] else {
            panic!("expected SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        let TableFactor::Table {
            args: Some(args), ..
        } = &select.from[0].relation
        else {
            panic!("expected OPENROWSET table-valued function");
        };
        let Some(sqlparser::ast::FunctionArg::ExprNamed {
            name: sqlparser::ast::Expr::Identifier(name),
            operator: sqlparser::ast::FunctionArgOperator::Colon,
            ..
        }) = args.args.first()
        else {
            panic!("expected adapted BULK argument");
        };
        assert_eq!(name.value, "BULK");
        let bulk_argument = format!("{:?}", args.args[0]);
        assert!(bulk_argument.contains("data/a.parquet"));
        assert!(bulk_argument.contains("data/b.parquet"));

        let single_sql =
            "SELECT src.id FROM OPENROWSET(BULK ('data/single.parquet'), FORMAT = 'PARQUET') AS src";
        let single_output = parse_input_sql_with_dialect_output(single_sql, Dialect::Mssql)
            .expect("parse a one-item parenthesized Synapse BULK list");
        assert!(single_output.parser_fallback_used);
        assert_eq!(single_output.statements.len(), 1);

        let generic = parse_input_sql_with_dialect_output(sql, Dialect::Generic);
        assert_eq!(
            parse_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            generic.is_ok(),
            "parenthesized BULK adaptation must remain MSSQL-only"
        );
        if let Ok(output) = generic {
            assert!(!output.parser_fallback_used);
        }
    }

    #[test]
    fn mssql_openrowset_bulk_lists_accept_newline_adjacent_and_comment_separators() {
        let sql = concat!(
            "-- café\r\n",
            "SELECT a.id, b.id, c.id, d.id, e.id, f.id FROM OPENROWSET(",
            "BULK\n('demo/a.parquet', 'demo/b.parquet'), FORMAT='PARQUET'",
            ") WITH (id BIGINT) AS a ",
            "JOIN OPENROWSET(BULK('demo/c.parquet', 'demo/d.parquet'), ",
            "FORMAT = 'PARQUET') WITH (id INT) AS b ON a.id = b.id ",
            "JOIN OPENROWSET(BULK/* λ */\r\n('demo/e.parquet', 'demo/f.parquet'), ",
            "FORMAT='PARQUET') WITH (id SMALLINT) AS c ON b.id = c.id ",
            "JOIN OPENROWSET(BULK/*comment only*/('demo/g.parquet', 'demo/h.parquet'), ",
            "FORMAT='PARQUET') WITH (id TINYINT) AS d ON c.id = d.id ",
            "JOIN OPENROWSET(BULK'demo/i.parquet', FORMAT='PARQUET') ",
            "WITH (id INTEGER) AS e ON d.id = e.id ",
            "JOIN OPENROWSET(BULK\n'demo/j.parquet', FORMAT='PARQUET') ",
            "WITH (id DECIMAL(10, 2)) AS f ON e.id = f.id"
        );
        let compatible_tokens = mssql_openrowset_compatible_tokens(sql)
            .expect("recognize newline, adjacent, and comment-separated BULK lists");
        let original_tokens = Tokenizer::new(&MsSqlDialect {}, sql)
            .tokenize_with_location()
            .expect("tokenize original source");
        let bulk_token = original_tokens
            .iter()
            .find(|token| matches!(&token.token, Token::Word(word) if word.value.eq_ignore_ascii_case("BULK")))
            .expect("original BULK token");
        let inserted_colon = compatible_tokens
            .iter()
            .find(|token| {
                matches!(token.token, Token::Colon)
                    && token.span.start == bulk_token.span.end
                    && token.span.end == bulk_token.span.end
            })
            .expect("zero-width named-argument punctuation at the original token boundary");
        assert_eq!(inserted_colon.span.start, bulk_token.span.end);

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse all documented file-list separator forms");
        assert!(output.parser_fallback_used);
        assert_eq!(output.statements.len(), 1);
        assert_eq!(
            openrowset_schema_types(&output.statements[0]),
            vec![
                vec![("id".to_string(), Some("BIGINT".to_string()))],
                vec![("id".to_string(), Some("INT".to_string()))],
                vec![("id".to_string(), Some("SMALLINT".to_string()))],
                vec![("id".to_string(), Some("TINYINT".to_string()))],
                vec![("id".to_string(), Some("INTEGER".to_string()))],
                vec![("id".to_string(), Some("DECIMAL(10,2)".to_string()))],
            ]
        );

        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql)
            .expect("compute ranges against unchanged source");
        assert_eq!(ranges, vec![sql.find("SELECT").unwrap()..sql.len()]);

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(
            analysis.statements[0].span,
            Some(Span::new(sql.find("SELECT").unwrap(), sql.len())),
            "synthetic punctuation must not shift UTF-8 source spans"
        );
        assert!(
            !analysis.issues.iter().any(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            }),
            "all separator forms should analyze without parser errors: {:?}",
            analysis.issues
        );

        let generic = parse_input_sql_with_dialect_output(sql, Dialect::Generic);
        assert_eq!(
            parse_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            generic.is_ok(),
            "OPENROWSET token adaptation must remain MSSQL-only"
        );
        if let Ok(output) = generic {
            assert!(!output.parser_fallback_used);
        }
    }

    #[test]
    fn mssql_openrowset_fallback_composes_with_trailing_comma_before_from_sanitizer() {
        let sql = concat!(
            "SELECT src.id,\n",
            "FROM OPENROWSET(BULK\n",
            "('demo/a.parquet', 'demo/b.parquet'), FORMAT = 'PARQUET') ",
            "WITH (id BIGINT) AS src"
        );
        assert!(
            parse_sql_with_dialect_output(sql, Dialect::Mssql).is_err(),
            "the primary parser cannot consume this combined compatibility shape"
        );

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("compose the source-preserving token fallbacks");
        assert!(output.parser_fallback_used);
        let [Statement::Query(query)] = output.statements.as_slice() else {
            panic!("expected one SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        assert_eq!(select.projection.len(), 1, "the trailing comma is removed");
        assert_eq!(
            openrowset_schema_types(&output.statements[0]),
            vec![vec![("id".to_string(), Some("BIGINT".to_string()))]]
        );

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(
            analysis.statements[0].span,
            Some(Span::new(sql.find("SELECT").unwrap(), sql.len())),
            "token fallback composition must retain original statement offsets"
        );
        assert!(
            !analysis.issues.iter().any(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            }),
            "the combined fallback should not emit a parse error: {:?}",
            analysis.issues
        );
    }

    #[test]
    fn mssql_synapse_openrowset_schema_is_preserved_as_alias_columns() {
        let sql = concat!(
            "-- café\r\n",
            "SELECT src.order_id, src.customer_name FROM OPENROWSET(",
            "BULK N'https://storage.example/container/*.csv', ",
            "FORMAT = 'CSV', HEADER_ROW = TRUE",
            ") /* keep comments outside the schema */ WITH (\r\n",
            "  -- CSV ordinal and JSON path are source metadata.\n",
            "  [order_id] BIGINT 1,\n",
            "  [customer_name] VARCHAR(128) '$.customerName'\n",
            ") AS [src]"
        );
        let _compatible_tokens =
            mssql_openrowset_compatible_tokens(sql).expect("recognized schema-bearing OPENROWSET");

        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse schema-bearing Synapse OPENROWSET");
        assert!(output.parser_fallback_used);
        let Statement::Query(query) = &output.statements[0] else {
            panic!("expected SELECT query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected SELECT body");
        };
        let TableFactor::Table {
            alias: Some(alias), ..
        } = &select.from[0].relation
        else {
            panic!("expected OPENROWSET table factor with alias");
        };
        assert_eq!(alias.name.value, "src");
        assert_eq!(
            alias
                .columns
                .iter()
                .map(|column| column.name.value.as_str())
                .collect::<Vec<_>>(),
            vec!["order_id", "customer_name"]
        );
        assert_eq!(
            alias.columns[0]
                .data_type
                .as_ref()
                .expect("declared type")
                .to_string(),
            "BIGINT"
        );
        assert_eq!(
            alias.columns[1]
                .data_type
                .as_ref()
                .expect("declared type")
                .to_string(),
            "VARCHAR(128)"
        );
    }

    #[test]
    fn mssql_openrowset_schema_attaches_inside_nested_procedure_blocks() {
        let sql = concat!(
            "CREATE OR ALTER PROCEDURE dbo.demo AS BEGIN\n",
            "  IF 1 = 1 BEGIN\n",
            "    SELECT r.id FROM OPENROWSET(BULK 'demo/procedure.parquet', ",
            "FORMAT = 'PARQUET') WITH (id INT) AS r;\n",
            "  END;\n",
            "END"
        );
        let output = parse_input_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse schema-bearing OPENROWSET within nested procedure blocks");
        assert!(output.parser_fallback_used);
        let Statement::CreateProcedure { body, .. } = &output.statements[0] else {
            panic!("expected CREATE PROCEDURE");
        };
        let [Statement::If(if_statement)] = body.statements().as_slice() else {
            panic!("expected nested IF block in procedure body");
        };
        assert!(matches!(
            if_statement.if_block.statements().as_slice(),
            [Statement::Query(_)]
        ));
        assert_eq!(
            openrowset_schema_types(&output.statements[0]),
            vec![vec![("id".to_string(), Some("INT".to_string()))]]
        );

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(analysis.statements.len(), 1);
        assert_eq!(
            analysis.statements[0].span,
            Some(Span::new(0, sql.len())),
            "nested procedure blocks must keep original source offsets"
        );
        assert!(
            !analysis.issues.iter().any(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            }),
            "schema attachment inside nested blocks must not fail analysis: {:?}",
            analysis.issues
        );
    }

    #[test]
    fn mssql_openrowset_schema_attaches_in_cte_tvfs_and_trigger_blocks() {
        let function_sql = concat!(
            "CREATE OR ALTER FUNCTION dbo.demo_rows() RETURNS TABLE AS RETURN ",
            "WITH source_rows AS (SELECT f.id FROM OPENROWSET(",
            "BULK 'demo/function.parquet', FORMAT='PARQUET') ",
            "WITH (id SMALLINT) AS f) SELECT id FROM source_rows"
        );
        let function_output = parse_input_sql_with_dialect_output(function_sql, Dialect::Mssql)
            .expect("parse CTE-backed table-valued function");
        assert!(matches!(
            function_output.statements.as_slice(),
            [Statement::CreateFunction(_)]
        ));
        assert_eq!(
            openrowset_schema_types(&function_output.statements[0]),
            vec![vec![("id".to_string(), Some("SMALLINT".to_string()))]]
        );

        let trigger_sql = concat!(
            "CREATE TRIGGER dbo.demo_trigger ON dbo.source AFTER INSERT AS BEGIN\n",
            "  SELECT t.id FROM OPENROWSET(BULK 'demo/trigger.parquet', ",
            "FORMAT='PARQUET') WITH (id BIGINT) AS t;\n",
            "END"
        );
        let trigger_output = parse_input_sql_with_dialect_output(trigger_sql, Dialect::Mssql)
            .expect("parse schema-bearing OPENROWSET within a trigger block");
        assert!(matches!(
            trigger_output.statements.as_slice(),
            [Statement::CreateTrigger(_)]
        ));
        assert_eq!(
            openrowset_schema_types(&trigger_output.statements[0]),
            vec![vec![("id".to_string(), Some("BIGINT".to_string()))]]
        );
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = trigger_sql.to_owned();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(
            analysis.statements[0].span,
            Some(Span::new(0, trigger_sql.len())),
            "trigger statements must retain original source offsets"
        );
    }

    #[test]
    fn mssql_openrowset_malformed_schema_inside_procedure_remains_a_parse_error() {
        let malformed = concat!(
            "CREATE PROCEDURE dbo.demo AS BEGIN ",
            "SELECT r.id FROM OPENROWSET(BULK 'demo/data.parquet', ",
            "FORMAT='PARQUET') WITH (id) AS r; END"
        );
        assert!(
            parse_input_sql_with_dialect_output(malformed, Dialect::Mssql).is_err(),
            "malformed schema declarations in procedural containers must remain errors"
        );
    }

    #[test]
    fn mssql_openrowset_adapter_does_not_accept_unrecognized_or_malformed_forms() {
        let unknown_option = "SELECT * FROM OPENROWSET(BULK 'path', UNKNOWN_OPTION = 'x') AS file";
        assert!(
            mssql_openrowset_compatible_tokens(unknown_option).is_none(),
            "unknown options must not be rewritten into parser-supported arguments"
        );

        for sql in [
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'TEXT') AS file",
            unknown_option,
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'PARQUET', FORMAT = 'CSV') AS file",
            "SELECT * FROM OPENROWSET(BULK 'path' + 'other', FORMAT = 'PARQUET') AS file",
            "SELECT OPENROWSET(BULK 'path', FORMAT = 'PARQUET')",
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = ) AS file",
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH () AS file",
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH (id) AS file",
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH (id INT DEFAULT 1) AS file",
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH (id INT 0) AS file",
            "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH (id INT,) AS file",
            "SELECT * FROM OPENROWSET(BULK (), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK ('path',), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK('path',), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK (, 'path'), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK ('path' 'other'), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK/*only*/('path', 1), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK\n('path', 1), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK (('path'), 'other'), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK ('path', 1), FORMAT = 'PARQUET') AS file",
            "SELECT * FROM OPENROWSET(BULK ('path', 'other',), FORMAT = 'PARQUET') AS file",
        ] {
            assert!(
                parse_input_sql_with_dialect_output(sql, Dialect::Mssql).is_err(),
                "unsupported or malformed syntax must remain a parser error: {sql}"
            );
            assert!(
                mssql_openrowset_compatible_tokens(sql).is_none(),
                "malformed schema syntax must not be rewritten: {sql}"
            );
        }

        let non_target_parse_error =
            "SELECT FROM OPENROWSET(BULK 'path', FORMAT = 'PARQUET') AS file";
        assert!(
            mssql_openrowset_compatible_tokens(non_target_parse_error).is_some(),
            "the documented OPENROWSET arguments should still be recognized"
        );
        assert!(
            parse_input_sql_with_dialect_output(non_target_parse_error, Dialect::Mssql).is_err(),
            "rewriting OPENROWSET must not hide unrelated SQL parse errors"
        );
        let parse_error_without_openrowset = "SELECT FROM dbo.source";
        assert!(mssql_openrowset_compatible_tokens(parse_error_without_openrowset).is_none());
        assert!(
            parse_input_sql_with_dialect_output(parse_error_without_openrowset, Dialect::Mssql)
                .is_err(),
            "non-target MSSQL syntax must remain a parser error"
        );

        let embedded_keyword_sql = concat!(
            "SELECT 'OPENROWSET(BULK ''path'', FORMAT = ''CSV'') WITH (id INT)' AS sql_text ",
            "/* OPENROWSET(BULK 'path', FORMAT = 'CSV') WITH (id INT) */"
        );
        assert!(mssql_openrowset_compatible_tokens(embedded_keyword_sql).is_none());
        let embedded_keyword_output =
            parse_input_sql_with_dialect_output(embedded_keyword_sql, Dialect::Mssql)
                .expect("keywords in strings/comments must remain ordinary SQL text");
        assert!(!embedded_keyword_output.parser_fallback_used);

        let provider_sql = concat!(
            "SELECT rowset.id FROM OPENROWSET(",
            "'MSOLEDBSQL', 'Server=server;Trusted_Connection=yes;', ",
            "'SELECT id FROM dbo.source'",
            ") AS rowset"
        );
        assert!(mssql_openrowset_compatible_tokens(provider_sql).is_none());
        let provider_parse = parse_sql_with_dialect_output(provider_sql, Dialect::Mssql);
        let provider_adaptation = parse_input_sql_with_dialect_output(provider_sql, Dialect::Mssql);
        assert_eq!(provider_parse.is_ok(), provider_adaptation.is_ok());
        if let Ok(output) = provider_adaptation {
            assert!(!output.parser_fallback_used);
        }
    }

    #[test]
    fn synapse_cetas_parses_with_an_explicit_unsupported_lineage_warning() {
        let sql = concat!(
            "CREATE EXTERNAL TABLE [analytics].[daily_rollup] ",
            "WITH (LOCATION = 'output/daily/', DATA_SOURCE = lake_source, ",
            "FILE_FORMAT = parquet_format) AS ",
            "SELECT item_id, 'café' AS label FROM OPENROWSET(",
            "BULK 'source.parquet', DATA_SOURCE = 'lake', ",
            "FORMAT = 'PARQUET') AS source_items"
        );
        let parsed = parse_input_statement_with_dialect_output(sql, Dialect::Mssql)
            .expect("documented CETAS syntax should be recognized");
        assert!(matches!(
            parsed,
            InputParseOutput::ExternalMetadata(ExternalMetadataStatement::Cetas(_), true)
        ));

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();
        let result = crate::analyzer::analyze(&request);
        assert_eq!(result.statements.len(), 1);
        assert_eq!(
            result.statements[0].statement_type,
            "CREATE_EXTERNAL_TABLE_AS_SELECT"
        );
        assert_eq!(
            result.statements[0].span,
            Some(Span::new(0, sql.len())),
            "the metadata-only statement span must use original UTF-8 byte offsets"
        );
        assert!(result.nodes.is_empty());
        assert!(result.edges.is_empty());
        let warning = result
            .issues
            .iter()
            .find(|issue| issue.code == issue_codes::UNSUPPORTED_SYNTAX)
            .expect("explicit external-lineage warning");
        assert_eq!(warning.severity, crate::types::Severity::Warning);
        assert_eq!(warning.span, Some(Span::new(0, sql.len())));
        assert!(warning.message.contains("file-write lineage"));
        assert!(
            result
                .issues
                .iter()
                .all(|issue| issue.code != issue_codes::PARSE_ERROR),
            "recognized CETAS should not be reported as a parser error"
        );

        let parse_only = crate::analyzer::parse_only_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse-only CETAS");
        assert_eq!(parse_only.statement_count, 1);
        assert!(
            parse_only.parser_fallback_used,
            "nested OPENROWSET adaptation is included in parse-only fallback accounting"
        );

        let malformed_options = concat!(
            "CREATE EXTERNAL TABLE target WITH (LOCATION = 'out/', ",
            "DATA_SOURCE = lake_source, FILE_FORMAT = ) AS SELECT 1"
        );
        let error = parse_input_statement_with_dialect_output(malformed_options, Dialect::Mssql)
            .err()
            .expect("malformed CETAS metadata must remain a parser error")
            .into_parse_error();
        assert!(error.position.is_some());
        assert_eq!(error.dialect, Some(Dialect::Mssql));

        let reordered_options = concat!(
            "CREATE EXTERNAL TABLE target WITH (DATA_SOURCE = lake_source, ",
            "LOCATION = 'out/', FILE_FORMAT = parquet_format) AS SELECT 1"
        );
        assert!(
            parse_input_statement_with_dialect_output(reordered_options, Dialect::Mssql).is_err(),
            "CETAS options must follow the documented LOCATION/DATA_SOURCE/FILE_FORMAT order"
        );

        let malformed_query = concat!(
            "CREATE EXTERNAL TABLE target WITH (LOCATION = 'out/', ",
            "DATA_SOURCE = lake_source, FILE_FORMAT = parquet_format) ",
            "AS SELECT 'café' AS label FROM )"
        );
        let query_error =
            parse_input_statement_with_dialect_output(malformed_query, Dialect::Mssql)
                .err()
                .expect("malformed CETAS must remain a parser error")
                .into_parse_error();
        let query_error_position = query_error.position.expect("original query position");
        assert_eq!(query_error.dialect, Some(Dialect::Mssql));
        assert!(
            query_error_position.column > malformed_query.find(" AS SELECT").expect("CETAS query"),
            "query diagnostics must include the original CETAS prefix offset"
        );
        assert!(
            !query_error.message.contains(" at Line:"),
            "query diagnostics must not retain query-fragment coordinates"
        );
        let query_sql = "SELECT 'café' AS label FROM )";
        let fragment_error = parse_input_sql_with_dialect_output(query_sql, Dialect::Mssql)
            .err()
            .expect("the SELECT fragment is malformed");
        let fragment_position = fragment_error.position.expect("fragment error position");
        let fragment_offset = crate::analyzer::helpers::line_col_to_offset(
            query_sql,
            fragment_position.line,
            fragment_position.column,
        )
        .expect("fragment error offset");
        let query_offset = malformed_query.find(query_sql).expect("query offset");
        assert_eq!(
            Some(offset_to_position(&malformed_query, query_offset + fragment_offset).unwrap()),
            Some(query_error_position),
            "query diagnostic location must map to the original UTF-8 source"
        );

        let extra_query = concat!(
            "CREATE EXTERNAL TABLE target WITH (LOCATION = 'out/', ",
            "DATA_SOURCE = lake_source, FILE_FORMAT = parquet_format) ",
            "AS SELECT 1; SELECT 2"
        );
        assert!(
            parse_input_statement_with_dialect_output(extra_query, Dialect::Mssql).is_err(),
            "CETAS accepts exactly one SELECT statement after AS"
        );
        let non_select_query = concat!(
            "CREATE EXTERNAL TABLE target WITH (LOCATION = 'out/', ",
            "DATA_SOURCE = lake_source, FILE_FORMAT = parquet_format) AS VALUES (1)"
        );
        assert!(
            parse_input_statement_with_dialect_output(non_select_query, Dialect::Mssql).is_err(),
            "CETAS requires a SELECT query, not a VALUES expression"
        );

        assert_eq!(
            parse_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            parse_input_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
            "CETAS recognition must remain MSSQL-only"
        );
    }

    #[test]
    fn synapse_cetas_optional_output_columns_use_parse_only_validation() {
        let sql = concat!(
            "/* café */ CREATE EXTERNAL TABLE [analytics].[daily_rollup] ",
            "/* output names */ ([SELECT], [output label], source_id) /* options */ ",
            "WITH (LOCATION = 'output/daily/', DATA_SOURCE = lake_source, ",
            "FILE_FORMAT = parquet_format) AS SELECT 1"
        );
        assert!(matches!(
            parse_input_statement_with_dialect_output(sql, Dialect::Mssql),
            Ok(InputParseOutput::ExternalMetadata(
                ExternalMetadataStatement::Cetas(_),
                false
            ))
        ));

        let parse_only = crate::analyzer::parse_only_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect("parse-only CETAS with optional output names");
        assert_eq!(parse_only.statement_count, 1);
        assert!(!parse_only.parser_fallback_used);

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(analysis.statements.len(), 1);
        assert!(analysis.nodes.is_empty());
        assert!(analysis.edges.is_empty());
        assert!(analysis
            .issues
            .iter()
            .any(|issue| issue.code == issue_codes::UNSUPPORTED_SYNTAX));

        let generic = parse_input_statement_with_dialect_output(sql, Dialect::Generic);
        assert!(
            !matches!(generic, Ok(InputParseOutput::ExternalMetadata(_, _))),
            "the Synapse CETAS adapter must remain MSSQL-only"
        );

        let malformed_columns = concat!(
            "/* café */ CREATE EXTERNAL TABLE target (id, ) WITH ",
            "(LOCATION = 'out/', DATA_SOURCE = source, FILE_FORMAT = format) AS SELECT 1"
        );
        let column_error =
            parse_input_statement_with_dialect_output(malformed_columns, Dialect::Mssql)
                .err()
                .expect("a trailing output-column comma must be rejected")
                .into_parse_error();
        let column_error_position = column_error.position.expect("column-list source position");
        assert_eq!(column_error.dialect, Some(Dialect::Mssql));
        let column_error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_columns,
            column_error_position.line,
            column_error_position.column,
        )
        .expect("column-list error source offset");
        assert_eq!(
            column_error_offset,
            malformed_columns
                .find("id, )")
                .expect("malformed column list")
                + 4,
            "the error must point at the trailing list delimiter in the original SQL"
        );

        let query_fragment = "SELECT 'café' AS label FROM )";
        let malformed_query = format!(
            "/* café */ CREATE EXTERNAL TABLE target ([label], [source id]) \
             WITH (LOCATION = 'out/', DATA_SOURCE = source, FILE_FORMAT = format) AS \
             {query_fragment}"
        );
        let query_error =
            parse_input_statement_with_dialect_output(&malformed_query, Dialect::Mssql)
                .err()
                .expect("malformed SELECT after optional output names must fail")
                .into_parse_error();
        let query_error_position = query_error.position.expect("query source position");
        let fragment_error = parse_input_sql_with_dialect_output(query_fragment, Dialect::Mssql)
            .err()
            .expect("the SELECT fragment is malformed");
        let fragment_position = fragment_error.position.expect("fragment source position");
        let fragment_offset = crate::analyzer::helpers::line_col_to_offset(
            query_fragment,
            fragment_position.line,
            fragment_position.column,
        )
        .expect("fragment error offset");
        let expected_query_error_offset = malformed_query
            .find(query_fragment)
            .expect("query source range")
            + fragment_offset;
        assert_eq!(
            offset_to_position(&malformed_query, expected_query_error_offset),
            Some(query_error_position),
            "query error coordinates must map through the optional output-column prefix"
        );
    }

    #[test]
    fn analysis_source_size_limit_uses_utf8_bytes_and_is_inclusive() {
        let mut request = base_request();
        request.sql = "é".repeat(5);
        assert_eq!(request.sql.chars().count(), 5);
        assert_eq!(request.sql.len(), 10);
        assert!(validate_analysis_input_sizes_with_limits(&request, 10, 100).is_ok());

        request.sql.push('x');
        let issue =
            validate_analysis_input_sizes_with_limits(&request, 10, 100).expect_err("oversized");
        assert_eq!(issue.code, issue_codes::INVALID_REQUEST);
        assert!(issue.message.contains("11 bytes provided"));
    }

    #[test]
    fn aggregate_limit_includes_inline_and_multibyte_multi_file_sources() {
        let mut request = base_request();
        request.sql = "é".repeat(2);
        request.files = Some(vec![
            crate::types::FileSource {
                name: "first.sql".to_string(),
                content: "日".repeat(2),
            },
            crate::types::FileSource {
                name: "second.sql".to_string(),
                content: "SELECT 1".to_string(),
            },
        ]);
        assert_eq!(request.sql.len(), 4);
        assert_eq!(request.files.as_ref().unwrap()[0].content.len(), 6);
        assert_eq!(request.files.as_ref().unwrap()[1].content.len(), 8);
        assert!(validate_analysis_input_sizes_with_limits(&request, 10, 18).is_ok());

        request.files.as_mut().unwrap()[1].content.push('é');
        let issue =
            validate_analysis_input_sizes_with_limits(&request, 10, 18).expect_err("oversized");
        assert_eq!(issue.code, issue_codes::INVALID_REQUEST);
        assert!(issue.message.contains("Aggregate SQL input"));
        assert!(issue.message.contains("20 bytes provided"));
    }

    #[test]
    fn collects_file_and_inline_statements() {
        let mut request = base_request();
        request.sql = "SELECT 2".to_string();
        request.source_name = Some("inline.sql".to_string());
        request.files = Some(vec![FileSource {
            name: "file.sql".to_string(),
            content: "SELECT 1".to_string(),
        }]);

        let (statements, issues) = collect_statements(&request);
        assert!(issues.is_empty());
        assert_eq!(statements.len(), 2);
        assert_eq!(
            statements[0].source_name.as_deref().map(String::as_str),
            Some("file.sql")
        );
        assert_eq!(
            statements[0].source_sql[statements[0].source_range.clone()].trim(),
            "SELECT 1"
        );
        assert_eq!(
            statements[1].source_name.as_deref().map(String::as_str),
            Some("inline.sql")
        );
        assert_eq!(
            statements[1].source_sql[statements[1].source_range.clone()].trim(),
            "SELECT 2"
        );
    }

    #[test]
    fn mssql_expansion_budget_is_shared_across_sources_and_attributed() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.files = Some(vec![
            FileSource {
                name: "first.sql".to_string(),
                content: "SELECT 1;\nSELECT 2;".to_string(),
            },
            FileSource {
                name: "second.sql".to_string(),
                content: "SELECT 3;".to_string(),
            },
        ]);
        request.sql = "SELECT 4;\nSELECT 5;".to_string();
        request.source_name = Some("inline.sql".to_string());

        let (statements, issues) = collect_statements_with_mssql_range_limit(&request, 5);
        assert!(
            issues.is_empty(),
            "exactly reaching the shared range limit should succeed: {issues:?}"
        );
        assert_eq!(statements.len(), 5);

        let (statements, issues) = collect_statements_with_mssql_range_limit(&request, 4);
        assert_eq!(statements.len(), 3);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::INVALID_REQUEST);
        assert_eq!(issues[0].source_name.as_deref(), Some("inline.sql"));
    }

    #[test]
    fn mssql_accepts_more_than_one_thousand_ordinary_statements_across_files() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        let first_file_count = 600;
        let second_file_count = 600;
        request.files = Some(vec![
            FileSource {
                name: "first.sql".to_string(),
                content: (0..first_file_count)
                    .map(|index| format!("SELECT {index};\n"))
                    .collect(),
            },
            FileSource {
                name: "second.sql".to_string(),
                content: (first_file_count..first_file_count + second_file_count)
                    .map(|index| format!("SELECT {index};\n"))
                    .collect(),
            },
        ]);

        let (statements, issues) = collect_statements(&request);
        assert!(
            issues.is_empty(),
            "ordinary MSSQL statements should fit within the expanded-range limit: {issues:?}"
        );
        assert_eq!(statements.len(), first_file_count + second_file_count);
        for (index, statement) in statements.iter().enumerate() {
            let expected_source = if index < first_file_count {
                "first.sql"
            } else {
                "second.sql"
            };
            assert_eq!(
                statement.source_name.as_deref().map(String::as_str),
                Some(expected_source)
            );
            assert_eq!(
                &statement.source_sql[statement.source_range.clone()],
                format!("SELECT {index}")
            );
        }
    }

    #[test]
    fn mssql_go_1000_followed_by_ordinary_sql_fits_expanded_range_limit() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.files = Some(vec![
            FileSource {
                name: "repeated.sql".to_string(),
                content: "SELECT 1;\nGO 1000\n".to_string(),
            },
            FileSource {
                name: "following.sql".to_string(),
                content: "SELECT 2;".to_string(),
            },
        ]);

        let (statements, issues) = collect_statements(&request);
        assert!(
            issues.is_empty(),
            "GO 1000 plus a following statement should fit the range budget: {issues:?}"
        );
        assert_eq!(statements.len(), MAX_MSSQL_GO_REPEAT + 1);
        assert!(statements[..MAX_MSSQL_GO_REPEAT].iter().all(|statement| {
            statement.source_name.as_deref().map(String::as_str) == Some("repeated.sql")
        }));
        let final_statement = statements.last().expect("following statement");
        assert_eq!(
            final_statement.source_name.as_deref().map(String::as_str),
            Some("following.sql")
        );
        assert_eq!(
            &final_statement.source_sql[final_statement.source_range.clone()],
            "SELECT 2"
        );
    }

    #[test]
    fn reports_invalid_request_without_inputs() {
        let request = base_request();
        let (_statements, issues) = collect_statements(&request);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::INVALID_REQUEST);
    }

    #[test]
    fn statement_ranges_respect_strings() {
        let sql = "SELECT ';' as value;SELECT 2;";
        let ranges = compute_statement_ranges(sql);
        assert_eq!(ranges.len(), 2);
        assert_eq!(&sql[ranges[0].clone()], "SELECT ';' as value");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
    }

    #[test]
    fn statement_ranges_skip_comments() {
        let sql = "SELECT 1; -- comment; still comment\nSELECT 2; /* block; comment */ SELECT 3;";
        let ranges = compute_statement_ranges(sql);
        assert_eq!(ranges.len(), 3);
        assert_eq!(&sql[ranges[0].clone()], "SELECT 1");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
        assert_eq!(&sql[ranges[2].clone()], "SELECT 3");
        assert!(ranges
            .iter()
            .all(|range| !sql[range.clone()].contains("comment")));
    }

    #[test]
    fn statement_ranges_handle_dollar_quoting() {
        let sql = "DO $$ BEGIN RAISE NOTICE ';'; END $$; SELECT 1;";
        let ranges = compute_statement_ranges(sql);
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            &sql[ranges[0].clone()],
            "DO $$ BEGIN RAISE NOTICE ';'; END $$"
        );
        assert_eq!(&sql[ranges[1].clone()], "SELECT 1");
    }

    #[test]
    fn mssql_statement_ranges_split_go_batch_separators() {
        let sql = "CREATE SCHEMA staging;\nGO\nCREATE TABLE test (id INT)\n";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(&sql[ranges[0].clone()], "CREATE SCHEMA staging");
        assert_eq!(&sql[ranges[1].clone()], "CREATE TABLE test (id INT)");
    }

    #[test]
    fn mssql_statement_ranges_split_trailing_go_batch_separators() {
        for sql in [
            "SELECT 1;\nGO\nSELECT 2;\nGO\n",
            "SELECT 1;\r\n  go  \r\nSELECT 2;\r\nGO\r\n",
            "SELECT 1\nGO\nGO\nSELECT 2\nGO\n",
        ] {
            let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
            assert_eq!(ranges.len(), 2, "unexpected ranges for {sql:?}");
            assert_eq!(&sql[ranges[0].clone()], "SELECT 1");
            assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
        }
    }

    #[test]
    fn mssql_statement_ranges_support_go_comments_and_repeat_counts() {
        let sql = "SELECT 1;\nGO -- batch separator\nSELECT 2;\nGO 2\nSELECT 3;";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();

        assert_eq!(ranges.len(), 4);
        assert_eq!(&sql[ranges[0].clone()], "SELECT 1");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
        assert_eq!(&sql[ranges[2].clone()], "SELECT 2");
        assert_eq!(&sql[ranges[3].clone()], "SELECT 3");
        assert_eq!(
            ranges[1], ranges[2],
            "repeated batch spans point to original source bytes"
        );
    }

    #[test]
    fn mssql_go_separator_accepts_trailing_block_comments() {
        let sql = "SELECT 1;\r\n  GO 2 /* repeat twice */  \r\nSELECT 2;\r\nGO /* next batch */\r\nSELECT 3;";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
        assert_eq!(ranges.len(), 4);
        assert_eq!(&sql[ranges[0].clone()], "SELECT 1");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 1");
        assert_eq!(ranges[0], ranges[1]);
        assert_eq!(&sql[ranges[2].clone()], "SELECT 2");
        assert_eq!(&sql[ranges[3].clone()], "SELECT 3");
    }

    #[test]
    fn mssql_go_separator_preserves_multiline_trailing_comment_state() {
        let sql = "SELECT 1;\nGO /* comment starts\n; GO\n/* nested */ still comment */\nSELECT 2;\nGO\nSELECT 3;";
        let separators = mssql_go_separators(sql).unwrap();
        assert_eq!(separators.len(), 2);
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
        assert_eq!(ranges.len(), 3);
        assert_eq!(&sql[ranges[0].clone()], "SELECT 1");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
        assert_eq!(&sql[ranges[2].clone()], "SELECT 3");
    }

    #[test]
    fn mssql_statement_ranges_ignore_semicolons_in_nested_block_comments() {
        for sql in [
            "SELECT 1 /* outer /* inner; */ outer; */; SELECT 2;",
            "SELECT 1;\nGO\nSELECT 2 /* outer /* inner; */ outer; */;\nGO\nSELECT 3;",
        ] {
            let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
            let statements: Vec<_> = ranges
                .iter()
                .map(|range| sql[range.clone()].trim())
                .collect();
            assert_eq!(statements.len(), if sql.contains("GO") { 3 } else { 2 });
            assert!(statements.iter().all(|statement| !statement.is_empty()));
        }
    }

    #[test]
    fn mssql_go_only_and_consecutive_empty_batches_produce_no_statements() {
        for sql in ["GO\n", "\nGO\nGO\n", "GO 2 -- repeat empty batch\r\nGO\r\n"] {
            assert!(
                compute_statement_ranges_for_dialect(sql, Dialect::Mssql)
                    .unwrap()
                    .is_empty(),
                "empty batch should not become a statement: {sql:?}"
            );
        }
        let sql = "GO\nSELECT 1;\nGO\nGO\nSELECT 2;\nGO\n";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(&sql[ranges[0].clone()], "SELECT 1");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
    }

    #[test]
    fn mssql_go_rejects_malformed_and_unbounded_repeat_suffixes() {
        for suffix in ["0", "-1", "abc", "2 extra"] {
            let sql = format!("SELECT 1;\nGO {suffix}\nSELECT 2;");
            let ranges = compute_statement_ranges_for_dialect(&sql, Dialect::Mssql).unwrap();
            assert_eq!(ranges.len(), 2, "invalid GO suffix split a batch: {suffix}");
            assert!(sql[ranges[1].clone()].contains("GO"));
        }
        for suffix in ["18446744073709551616"] {
            let sql = format!("SELECT 1;\nGO {suffix}\nSELECT 2;");
            assert!(compute_statement_ranges_for_dialect(&sql, Dialect::Mssql).is_err());
        }
    }

    #[test]
    fn mssql_go_repeat_above_per_separator_limit_is_rejected() {
        let sql = format!("SELECT 1;\nGO {}\nSELECT 2;", MAX_MSSQL_GO_REPEAT + 1);
        assert!(compute_statement_ranges_for_dialect(&sql, Dialect::Mssql).is_err());
    }

    #[test]
    fn mssql_go_scanner_recovers_after_lexically_invalid_prior_batch() {
        let sql = "SELECT \0;\nGO\nSELECT 2;\nGO\nSELECT 3;";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
        assert_eq!(ranges.len(), 3);
        assert!(sql[ranges[0].clone()].contains('\0'));
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
        assert_eq!(&sql[ranges[2].clone()], "SELECT 3");
    }

    #[test]
    fn mssql_go_scanner_ignores_multiline_comments_and_preserves_utf8_byte_ranges() {
        let sql = "-- café\r\n/* outer\r\nGO\r\n*/\r\nSELECT 1;\r\nGO 2 -- repeat\r\nSELECT FROM;";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
        assert_eq!(ranges.len(), 3);
        assert!(sql[ranges[0].clone()].ends_with("SELECT 1"));
        assert_eq!(ranges[0], ranges[1]);
        assert_eq!(&sql[ranges[2].clone()], "SELECT FROM");

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();
        let (_, issues) = collect_statements(&request);
        let parse_issue = issues
            .iter()
            .find(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            })
            .expect("malformed later batch should retain its parse issue");
        let span = parse_issue.span.expect("parse issue span");
        assert_eq!(
            &request.sql[span.start..span.end],
            "SELECT FROM",
            "unexpected issue span: {parse_issue:?}"
        );
    }

    #[test]
    fn mssql_statement_ranges_do_not_treat_invalid_go_suffix_as_separator() {
        let sql = "SELECT 1;\nGO 0\nSELECT 2;\nGO abc\nSELECT 3;";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();

        assert_eq!(ranges.len(), 3);
        assert!(ranges
            .iter()
            .any(|range| sql[range.clone()].contains("GO 0")));
        assert!(ranges
            .iter()
            .any(|range| sql[range.clone()].contains("GO abc")));
        assert!(sql[ranges[2].clone()].contains("SELECT 3"));
    }

    #[test]
    fn mssql_statement_ranges_ignore_go_inside_strings_comments_and_identifiers() {
        let sql = "SELECT 'GO' AS literal;\nSELECT [GO] FROM [source];\n-- GO\n/* GO */\nGO\nSELECT 'inside\nGO\nstring' AS literal;";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();

        assert_eq!(ranges.len(), 3);
        assert_eq!(&sql[ranges[0].clone()], "SELECT 'GO' AS literal");
        assert_eq!(&sql[ranges[1].clone()], "SELECT [GO] FROM [source]");
        assert!(sql[ranges[2].clone()].contains("inside\nGO\nstring"));
    }

    #[test]
    fn non_mssql_statement_splitting_is_unchanged_for_go_lines() {
        let sql = "SELECT 1;\nGO\nSELECT 2;";
        let generic = compute_statement_ranges_for_dialect(sql, Dialect::Generic).unwrap();
        assert_eq!(generic.len(), 2);
        assert!(generic
            .iter()
            .any(|range| sql[range.clone()].contains("GO")));
    }

    #[test]
    fn mssql_statement_ranges_recognize_optional_newline_separators() {
        let sql = "-- café\r\nEXEC dbo.demo_proc\r\nDROP VIEW dbo.demo_view";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql)
            .expect("bounded MSSQL ranges");
        assert_eq!(ranges.len(), 2);
        assert_eq!(&sql[ranges[0].clone()], "EXEC dbo.demo_proc");
        assert_eq!(&sql[ranges[1].clone()], "DROP VIEW dbo.demo_view");

        let block = "BEGIN SELECT 1; END\nSET NOCOUNT ON";
        let ranges = compute_statement_ranges_for_dialect(block, Dialect::Mssql)
            .expect("bounded MSSQL block ranges");
        assert_eq!(ranges.len(), 2);
        assert_eq!(&block[ranges[0].clone()], "BEGIN SELECT 1; END");
        assert_eq!(&block[ranges[1].clone()], "SET NOCOUNT ON");

        let comments_and_strings = concat!(
            "EXEC dbo.demo_proc @value = N'DROP VIEW fake_view'\n",
            "-- DROP VIEW in a comment\n",
            "DROP VIEW dbo.demo_view"
        );
        let ranges = compute_statement_ranges_for_dialect(comments_and_strings, Dialect::Mssql)
            .expect("comments and string contents must not become boundaries");
        assert_eq!(ranges.len(), 2);
        assert!(comments_and_strings[ranges[0].clone()].contains("N'DROP VIEW fake_view'"));
        assert_eq!(
            &comments_and_strings[ranges[1].clone()],
            "DROP VIEW dbo.demo_view"
        );

        let continuation = "SELECT 1\nFROM dbo.demo_table";
        assert_eq!(
            compute_statement_ranges_for_dialect(continuation, Dialect::Mssql)
                .expect("SELECT continuation")
                .len(),
            1,
            "a clause continuation must not be split as a new statement"
        );
        for query in [
            "SELECT 1\nUNION\nSELECT 2",
            "SELECT * FROM (\nSELECT 1\n) AS nested_query",
        ] {
            assert_eq!(
                compute_statement_ranges_for_dialect(query, Dialect::Mssql)
                    .expect("query continuation")
                    .len(),
                1,
                "query clauses and nested queries must not be split: {query}"
            );
        }
        assert_eq!(
            compute_statement_ranges_for_dialect(sql, Dialect::Generic)
                .expect("generic dialect keeps its existing splitting")
                .len(),
            1,
            "optional T-SQL separators must not affect other dialects"
        );
    }

    #[test]
    fn mssql_optional_statement_recovery_does_not_hide_malformed_fragments() {
        let sql = "EXEC dbo.demo_proc\nDROP VIEW dbo.demo_view EXTRA";
        let parse_error = crate::analyzer::parse_only_sql_with_dialect_output(sql, Dialect::Mssql)
            .expect_err("parse-only must not recover malformed newline-separated fragments");
        assert_eq!(
            parse_error.position.map(|position| position.line),
            Some(2),
            "parse-only diagnostics must map back to the original source line"
        );

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_owned();

        let (statements, issues) = collect_statements(&request);
        assert_eq!(statements.len(), 1);
        assert_eq!(
            &sql[statements[0].source_range.clone()],
            "EXEC dbo.demo_proc"
        );
        let parse_error = issues
            .iter()
            .find(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            })
            .expect("malformed DROP fragment must remain a parse error");
        let error_span = parse_error.span.expect("malformed fragment span");
        assert_eq!(
            &sql[error_span.start..error_span.end],
            "DROP VIEW dbo.demo_view EXTRA"
        );
    }

    #[test]
    fn mssql_optional_separator_batches_parse_each_statement_with_original_ranges() {
        for sql in [
            "-- café\r\nEXEC dbo.demo_proc\r\nDROP VIEW dbo.demo_view",
            "SELECT 1\nSET NOCOUNT ON",
            "BEGIN SELECT 1; END\nSET NOCOUNT ON",
            "WHILE 1 = 0 BEGIN SELECT 1; END\nSET NOCOUNT ON",
        ] {
            let parse_only =
                crate::analyzer::parse_only_sql_with_dialect_output(sql, Dialect::Mssql)
                    .expect("parse-only semicolon-optional batch");
            assert_eq!(
                parse_only.statement_count, 2,
                "parse-only statement count must follow T-SQL boundaries"
            );

            let mut request = base_request();
            request.dialect = Dialect::Mssql;
            request.sql = sql.to_owned();

            let (statements, issues) = collect_statements(&request);
            assert_eq!(statements.len(), 2, "unexpected statements: {issues:?}");
            assert!(
                !issues.iter().any(|issue| {
                    issue.code == issue_codes::PARSE_ERROR
                        && issue.severity == crate::types::Severity::Error
                }),
                "valid semicolon-optional statements must parse: {issues:?}"
            );
            let expected: Vec<_> = compute_statement_ranges_for_dialect(sql, Dialect::Mssql)
                .expect("validated MSSQL source ranges")
                .into_iter()
                .map(|range| sql[range].to_owned())
                .collect();
            let actual: Vec<_> = statements
                .iter()
                .map(|statement| statement.source_sql[statement.source_range.clone()].to_owned())
                .collect();
            assert_eq!(actual, expected, "statement order and byte spans changed");
        }
    }

    #[test]
    fn mssql_repeat_expansion_has_a_global_range_budget() {
        let mut sql = String::new();
        for _ in 0..=MAX_MSSQL_EXPANDED_STATEMENT_RANGES / MAX_MSSQL_GO_REPEAT {
            sql.push_str("SELECT 1;\nGO 1000\n");
        }
        assert!(compute_statement_ranges_for_dialect(&sql, Dialect::Mssql).is_err());
    }

    #[test]
    fn collect_statements_mssql_go_batch_without_final_semicolon_parses_statements() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "CREATE SCHEMA staging;\nGO\nCREATE TABLE test (id INT)\n".to_string();

        let (statements, issues) = collect_statements(&request);
        assert!(
            issues.is_empty(),
            "MSSQL GO separators should not produce parse errors: {issues:?}"
        );
        assert_eq!(statements.len(), 2);
    }

    #[test]
    fn collect_statements_mssql_go_batch_with_trailing_separator_has_no_parse_error() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "SELECT 1;\nGO\nSELECT 2;\nGO\n".to_string();

        let (statements, issues) = collect_statements(&request);

        assert_eq!(statements.len(), 2);
        assert!(
            issues.is_empty(),
            "MSSQL trailing GO should not produce parse errors: {issues:?}"
        );
    }

    #[test]
    fn collect_statements_mssql_recovers_complete_begin_end_block() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "CREATE OR ALTER PROCEDURE dbo.p AS BEGIN DECLARE @value INT; SET @value = 1; SELECT @value; END; SELECT FROM;\nGO\nSELECT 2;".to_string();

        let (statements, issues) = collect_statements(&request);
        let parse_errors: Vec<_> = issues
            .iter()
            .filter(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            })
            .collect();

        assert_eq!(
            statements.len(),
            2,
            "procedure block and following batch should remain separate"
        );
        assert_eq!(parse_errors.len(), 1, "unexpected parse errors: {issues:?}");
        assert!(request.sql[statements[0].source_range.clone()]
            .contains("CREATE OR ALTER PROCEDURE dbo.p"));
        assert!(request.sql[statements[0].source_range.clone()].contains("SELECT @value"));
        assert_eq!(&request.sql[statements[1].source_range.clone()], "SELECT 2");
    }

    #[test]
    fn collect_statements_mssql_recovers_nested_if_and_case_blocks() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "-- café\nCREATE OR ALTER PROCEDURE dbo.p AS BEGIN IF 1 = 1 BEGIN DECLARE @value INT; SET @value = CASE WHEN 1 = 1 THEN 10 ELSE 20 END; BEGIN SET @value = @value + 1; END; END ELSE BEGIN SET @value = 0; END; END; SELECT FROM; SELECT 9;".to_owned();

        let (statements, issues) = collect_statements(&request);
        let parse_errors: Vec<_> = issues
            .iter()
            .filter(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            })
            .collect();

        assert_eq!(
            statements.len(),
            2,
            "unexpected recovered statements: {issues:?}"
        );
        assert_eq!(
            parse_errors.len(),
            1,
            "expected only the independent malformed statement"
        );
        let procedure = &request.sql[statements[0].source_range.clone()];
        assert!(procedure.starts_with("CREATE OR ALTER PROCEDURE"));
        assert!(procedure.ends_with("END"));
        assert!(procedure.contains("IF 1 = 1"));
        assert_eq!(&request.sql[statements[1].source_range.clone()], "SELECT 9");
        let error_span = parse_errors[0].span.expect("parse error span");
        assert_eq!(
            &request.sql[error_span.start..error_span.end],
            "SELECT FROM"
        );
    }

    #[test]
    fn collect_statements_mssql_keeps_bad_block_error_local_and_recovers_later_statement() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql =
            "CREATE PROCEDURE dbo.p AS BEGIN SELECT 1; SELECT FROM; END; SELECT 2;".to_owned();

        let (statements, issues) = collect_statements(&request);
        let parse_errors: Vec<_> = issues
            .iter()
            .filter(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            })
            .collect();

        assert_eq!(
            statements.len(),
            1,
            "only the valid later statement should survive"
        );
        assert_eq!(&request.sql[statements[0].source_range.clone()], "SELECT 2");
        assert_eq!(
            parse_errors.len(),
            1,
            "malformed procedure must remain an error"
        );
        let span = parse_errors[0].span.expect("procedure error span");
        assert_eq!(
            &request.sql[span.start..span.end],
            "CREATE PROCEDURE dbo.p AS BEGIN SELECT 1; SELECT FROM; END"
        );
    }

    #[test]
    fn mssql_block_scanner_ignores_quoted_keyword_identifiers() {
        assert_eq!(mssql_update_block_depth("SELECT [BEGIN]", 0), 0);
        assert_eq!(mssql_update_block_depth("SELECT [END]", 1), 1);
        assert_eq!(mssql_update_block_depth("SELECT [CASE]; END", 1), 0);
        assert_eq!(mssql_update_block_depth("BEGIN [TRAN]", 0), 1);
        assert_eq!(mssql_update_block_depth("END [CONVERSATION]", 1), 0);
    }

    #[test]
    fn collect_statements_mssql_quoted_begin_does_not_swallow_neighboring_statements() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "SELECT [BEGIN] FROM t; SELECT FROM; SELECT 3;".to_owned();

        let (statements, issues) = collect_statements(&request);
        let parse_errors: Vec<_> = issues
            .iter()
            .filter(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            })
            .collect();

        assert_eq!(
            statements.len(),
            2,
            "unexpected recovered statements: {issues:?}"
        );
        assert_eq!(
            &request.sql[statements[0].source_range.clone()],
            "SELECT [BEGIN] FROM t"
        );
        assert_eq!(&request.sql[statements[1].source_range.clone()], "SELECT 3");
        assert_eq!(
            parse_errors.len(),
            1,
            "the malformed statement must remain an error"
        );
        let span = parse_errors[0].span.expect("parse error span");
        assert_eq!(&request.sql[span.start..span.end], "SELECT FROM");
    }

    #[test]
    fn collect_statements_mssql_does_not_count_dynamic_sql_keywords_as_blocks() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "CREATE PROCEDURE dbo.p AS BEGIN DECLARE @sql NVARCHAR(MAX); SET @sql = N'BEGIN; END'; EXEC @sql; SELECT 1; END; SELECT 2;".to_owned();

        let (statements, issues) = collect_statements(&request);
        assert!(
            !issues.iter().any(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            }),
            "dynamic SQL string contents must remain opaque: {issues:?}"
        );
        assert_eq!(statements.len(), 2);
        assert!(request.sql[statements[0].source_range.clone()].contains("EXEC @sql"));
        assert_eq!(&request.sql[statements[1].source_range.clone()], "SELECT 2");
    }

    #[test]
    fn mssql_try_catch_blocks_balance_without_absorbing_following_statements() {
        let sql = "BEGIN TRY SELECT 1; END TRY BEGIN CATCH SELECT 2; END CATCH; SELECT 3;";
        let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
        assert_eq!(ranges.len(), 2);
        assert!(sql[ranges[0].clone()].starts_with("BEGIN TRY"));
        assert!(sql[ranges[0].clone()].contains("END CATCH"));
        assert_eq!(&sql[ranges[1].clone()], "SELECT 3");
    }

    #[test]
    fn mssql_non_block_begin_forms_do_not_absorb_later_statements() {
        for sql in [
            "BEGIN TRANSACTION; SELECT 1;",
            "BEGIN DIALOG CONVERSATION @handle FROM SERVICE [source] TO SERVICE 'target' ON CONTRACT [contract]; SELECT 1;",
            "BEGIN CONVERSATION TIMER (@handle) TIMEOUT = 1000; SELECT 1;",
        ] {
            let ranges = compute_statement_ranges_for_dialect(sql, Dialect::Mssql).unwrap();
            assert_eq!(ranges.len(), 2, "non-block BEGIN expanded a block: {sql}");
            assert_eq!(&sql[ranges[1].clone()], "SELECT 1");
        }
    }

    #[test]
    fn collect_statements_mssql_keeps_error_for_unbalanced_begin_end_block() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "IF 1 = 1 BEGIN SELECT 1;\nGO\nSELECT 2;".to_string();

        let (statements, issues) = collect_statements(&request);
        let parse_errors: Vec<_> = issues
            .iter()
            .filter(|issue| {
                issue.code == issue_codes::PARSE_ERROR
                    && issue.severity == crate::types::Severity::Error
            })
            .collect();

        assert_eq!(statements.len(), 1);
        assert_eq!(
            parse_errors.len(),
            1,
            "unbalanced block should remain visible: {issues:?}"
        );
        assert!(parse_errors.iter().all(|issue| issue.span.is_some()));
        assert_eq!(&request.sql[statements[0].source_range.clone()], "SELECT 2");
    }

    #[test]
    fn collect_statements_mssql_case_end_is_not_treated_as_block_end() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "CREATE PROCEDURE dbo.p AS BEGIN SELECT CASE WHEN 1 = 1 THEN 2 ELSE 3 END; SELECT 4; END; SELECT 5;".to_string();

        let (_statements, issues) = collect_statements(&request);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == issue_codes::PARSE_ERROR),
            "CASE END must not close the procedure block: {issues:?}"
        );
    }

    #[test]
    fn collects_external_file_format_as_metadata_only_input() {
        let sql = concat!(
            "CREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = DELIMITEDTEXT, ",
            "FORMAT_OPTIONS (FIELD_TERMINATOR = ','));\n",
            "SELECT 1"
        );
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_string();

        let (statements, issues) = collect_statements(&request);

        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == issue_codes::PARSE_ERROR),
            "valid external metadata should not emit a parse error: {issues:?}"
        );
        assert_eq!(statements.len(), 2);
        assert!(matches!(
            statements[0].statement,
            StatementInputKind::ExternalMetadata(_)
        ));
        assert!(matches!(
            statements[1].statement,
            StatementInputKind::Parsed(_)
        ));
        let StatementInputKind::Parsed(parsed_query) = &statements[1].statement else {
            panic!("expected parsed query");
        };
        assert!(matches!(parsed_query.as_ref(), Statement::Query(_)));
        assert_eq!(statements[0].source_sql.as_ref(), sql);
        assert!(statements[0].source_sql[statements[0].source_range.clone()]
            .contains("FIELD_TERMINATOR"));
    }

    #[test]
    fn collects_external_table_and_guarded_file_format_as_metadata_only_inputs() {
        let table_sql = concat!(
            "-- café\r\n",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT, label VARCHAR(20)) ",
            "WITH (LOCATION = 'data/', DATA_SOURCE = demo_storage, ",
            "FILE_FORMAT = demo_parquet)\r\n",
            "SELECT 1"
        );
        let parse_only = crate::analyzer::parse_only_sql_with_dialect_output(
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT, label VARCHAR(20)) \
             WITH (LOCATION = 'data/', DATA_SOURCE = demo_storage, \
             FILE_FORMAT = demo_parquet)",
            Dialect::Mssql,
        )
        .expect("parse-only external table");
        assert_eq!(parse_only.statement_count, 1);

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = table_sql.to_owned();
        let (statements, issues) = collect_statements(&request);
        assert_eq!(statements.len(), 2, "{issues:?}");
        assert!(matches!(
            statements[0].statement,
            StatementInputKind::ExternalMetadata(ExternalMetadataStatement::ExternalTable(_))
        ));
        assert_eq!(
            &table_sql[statements[0].source_range.clone()],
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT, label VARCHAR(20)) \
             WITH (LOCATION = 'data/', DATA_SOURCE = demo_storage, \
             FILE_FORMAT = demo_parquet)"
        );
        assert_eq!(&table_sql[statements[1].source_range.clone()], "SELECT 1");
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == issue_codes::PARSE_ERROR),
            "valid external-table DDL must not report a parse error: {issues:?}"
        );

        let conditional_sql = concat!(
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
            "WHERE name = 'demo_format') BEGIN ",
            "CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); ",
            "END"
        );
        let parse_only =
            crate::analyzer::parse_only_sql_with_dialect_output(conditional_sql, Dialect::Mssql)
                .expect("parse-only guarded external file format");
        assert_eq!(parse_only.statement_count, 1);

        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = conditional_sql.to_owned();
        let analysis = crate::analyzer::analyze(&request);
        assert_eq!(analysis.statements.len(), 1);
        assert_eq!(
            analysis.statements[0].statement_type,
            "CREATE_EXTERNAL_FILE_FORMAT"
        );
        assert_eq!(
            analysis.statements[0].span,
            Some(Span::new(0, conditional_sql.len()))
        );
        assert!(analysis.nodes.is_empty());
        assert!(analysis.edges.is_empty());
        assert!(analysis.issues.iter().any(|issue| {
            issue.code == issue_codes::UNSUPPORTED_SYNTAX
                && issue
                    .message
                    .contains("external-file lineage is not modeled")
                && issue.span == Some(Span::new(0, conditional_sql.len()))
        }));
        assert!(
            !analysis
                .issues
                .iter()
                .any(|issue| issue.code == issue_codes::PARSE_ERROR),
            "the complete conditional must be parsed, not skipped: {:?}",
            analysis.issues
        );

        for sql in [table_sql, conditional_sql] {
            assert_eq!(
                parse_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
                parse_input_sql_with_dialect_output(sql, Dialect::Generic).is_ok(),
                "external metadata recognition must remain MSSQL-only"
            );
        }
    }

    #[test]
    fn collects_single_statement_guarded_file_formats_without_begin_end() {
        let sql_cases = [
            concat!(
                "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
                "WHERE name = 'demo_parquet') CREATE EXTERNAL FILE FORMAT ",
                "demo_parquet WITH (FORMAT_TYPE = PARQUET)"
            ),
            concat!(
                "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
                "WHERE name = 'demo_text') CREATE EXTERNAL FILE FORMAT ",
                "demo_text WITH (FORMAT_TYPE = DELIMITEDTEXT, ",
                "FORMAT_OPTIONS (FIELD_TERMINATOR = ','));"
            ),
        ];

        for sql in sql_cases {
            let parse_only =
                crate::analyzer::parse_only_sql_with_dialect_output(sql, Dialect::Mssql)
                    .expect("parse-only single-statement guarded file format");
            assert_eq!(parse_only.statement_count, 1);

            let mut request = base_request();
            request.dialect = Dialect::Mssql;
            request.sql = sql.to_string();
            let analysis = crate::analyzer::analyze(&request);
            let statement_end = sql.strip_suffix(';').map_or(sql.len(), str::len);
            let expected_span = Span::new(0, statement_end);

            assert_eq!(analysis.statements.len(), 1);
            assert_eq!(
                analysis.statements[0].statement_type,
                "CREATE_EXTERNAL_FILE_FORMAT"
            );
            assert_eq!(analysis.statements[0].span, Some(expected_span));
            assert!(analysis.nodes.is_empty());
            assert!(analysis.edges.is_empty());
            assert!(analysis.issues.iter().any(|issue| {
                issue.code == issue_codes::UNSUPPORTED_SYNTAX
                    && issue
                        .message
                        .contains("external-file lineage is not modeled")
                    && issue.span == Some(expected_span)
            }));
            assert!(
                !analysis
                    .issues
                    .iter()
                    .any(|issue| issue.code == issue_codes::PARSE_ERROR),
                "valid guarded metadata must parse as one full-span statement: {:?}",
                analysis.issues
            );
        }
    }

    #[test]
    fn guarded_file_format_else_is_not_swallowed_as_metadata() {
        let sql = concat!(
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
            "WHERE name = 'demo_format') CREATE EXTERNAL FILE FORMAT demo_format ",
            "WITH (FORMAT_TYPE = PARQUET); ELSE SELECT 1"
        );
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = sql.to_string();

        let (statements, issues) = collect_statements(&request);
        assert_eq!(statements.len(), 1);
        assert!(matches!(
            statements[0].statement,
            StatementInputKind::ExternalMetadata(ExternalMetadataStatement::ConditionalFileFormat(
                _
            ))
        ));
        assert!(
            !sql[statements[0].source_range.clone()].contains("ELSE"),
            "the unsupported ELSE branch must not be included in metadata"
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == issue_codes::PARSE_ERROR),
            "an ELSE branch must remain visible as an error instead of being swallowed: {issues:?}"
        );
    }

    #[test]
    fn unsupported_external_file_format_remains_a_parse_error() {
        let mut request = base_request();
        request.dialect = Dialect::Mssql;
        request.sql = "CREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = CSV)".to_string();

        let (statements, issues) = collect_statements(&request);

        assert!(statements.is_empty());
        let parse_issue = issues
            .iter()
            .find(|issue| issue.code == issue_codes::PARSE_ERROR)
            .expect("unsupported file format must report a parse error");
        assert_eq!(parse_issue.severity, crate::types::Severity::Error);
        assert!(parse_issue.span.is_some());
    }

    #[test]
    fn parses_procedure_with_inner_semicolons() {
        let mut request = base_request();
        request.dialect = Dialect::Snowflake;
        request.sql = r#"
            CREATE PROCEDURE demo()
            LANGUAGE SQL
            AS
            BEGIN
                SELECT 'a';
                SELECT 'b';
                RETURN 'done';
            END;
            SELECT 1;
        "#
        .to_string();

        let (statements, issues) = collect_statements(&request);
        assert!(issues.is_empty(), "Expected no issues, got {issues:?}");
        assert_eq!(
            statements.len(),
            2,
            "Expected procedure and trailing select"
        );
        assert!(matches!(
            statements[0].statement,
            StatementInputKind::Parsed(_)
        ));
        let StatementInputKind::Parsed(procedure) = &statements[0].statement else {
            panic!("expected parsed procedure");
        };
        assert!(matches!(
            procedure.as_ref(),
            Statement::CreateProcedure { .. }
        ));
        let procedure_source = &statements[0].source_sql[statements[0].source_range.clone()];
        assert!(
            procedure_source.contains("SELECT 'b';") && procedure_source.contains("RETURN 'done';"),
            "Procedure source should include entire body: {procedure_source:?}"
        );
        assert!(matches!(
            statements[1].statement,
            StatementInputKind::Parsed(_)
        ));
        let StatementInputKind::Parsed(parsed_query) = &statements[1].statement else {
            panic!("expected parsed query");
        };
        assert!(matches!(parsed_query.as_ref(), Statement::Query(_)));
    }

    #[test]
    fn best_effort_parsing_continues_after_error() {
        // SQL with valid statement, invalid statement, then valid statement
        let mut request = base_request();
        request.sql = r#"
            SELECT 1 FROM users;
            SELECT FROM;
            SELECT 2 FROM orders;
        "#
        .to_string();

        let (statements, issues) = collect_statements(&request);

        // Should have parsed 2 valid statements
        assert_eq!(statements.len(), 2, "Expected 2 valid statements");

        // Should have 1 parse error for the invalid statement
        assert_eq!(issues.len(), 1, "Expected 1 parse error");
        assert_eq!(issues[0].code, issue_codes::PARSE_ERROR);

        // The error should have a span pointing to the invalid statement
        assert!(issues[0].span.is_some(), "Error should have span info");
    }

    #[test]
    fn best_effort_parsing_with_file_source() {
        let mut request = base_request();
        request.files = Some(vec![FileSource {
            name: "test.sql".to_string(),
            content: r#"
                SELECT a FROM t1;
                INVALID SYNTAX HERE;
                SELECT b FROM t2;
            "#
            .to_string(),
        }]);

        let (statements, issues) = collect_statements(&request);

        assert_eq!(statements.len(), 2, "Expected 2 valid statements");
        assert_eq!(issues.len(), 1, "Expected 1 parse error");

        // Error message should include file name
        assert!(
            issues[0].message.contains("test.sql"),
            "Error should mention file name"
        );

        // Issue should have source_name set
        assert_eq!(
            issues[0].source_name.as_deref(),
            Some("test.sql"),
            "Issue should have source_name set"
        );
    }

    #[test]
    fn best_effort_parsing_multiple_errors() {
        let mut request = base_request();
        request.sql = r#"
            SELECT 1;
            BROKEN STATEMENT 1;
            SELECT 2;
            BROKEN STATEMENT 2;
            SELECT 3;
        "#
        .to_string();

        let (statements, issues) = collect_statements(&request);

        assert_eq!(statements.len(), 3, "Expected 3 valid statements");
        assert_eq!(issues.len(), 2, "Expected 2 parse errors");
    }

    #[test]
    fn empty_sql_returns_no_statements() {
        let sql = "";
        let ranges = compute_statement_ranges(sql);
        assert!(ranges.is_empty(), "Empty SQL should produce no ranges");
    }

    #[test]
    fn whitespace_only_sql_returns_no_statements() {
        let sql = "   \n\t\r\n   ";
        let ranges = compute_statement_ranges(sql);
        assert!(
            ranges.is_empty(),
            "Whitespace-only SQL should produce no ranges"
        );
    }

    #[test]
    fn comments_only_sql_returns_no_statements() {
        let sql = "-- just a comment\n/* another comment */";
        let ranges = compute_statement_ranges(sql);
        assert!(
            ranges.is_empty(),
            "Comments-only SQL should produce no ranges"
        );
    }

    #[test]
    fn empty_inline_sql_with_valid_file() {
        let mut request = base_request();
        request.sql = "   ".to_string(); // whitespace only
        request.files = Some(vec![FileSource {
            name: "file.sql".to_string(),
            content: "SELECT 1".to_string(),
        }]);

        let (statements, issues) = collect_statements(&request);
        assert!(issues.is_empty());
        assert_eq!(statements.len(), 1);
        assert_eq!(
            statements[0].source_name.as_deref().map(String::as_str),
            Some("file.sql")
        );
    }

    #[test]
    fn statement_ranges_handle_unicode_identifiers() {
        // Test with multi-byte Unicode characters (Japanese, emoji, etc.)
        let sql = "SELECT '日本語' AS 名前; SELECT '🎉' AS emoji;";
        let ranges = compute_statement_ranges(sql);
        assert_eq!(ranges.len(), 2);
        assert_eq!(&sql[ranges[0].clone()], "SELECT '日本語' AS 名前");
        assert_eq!(&sql[ranges[1].clone()], "SELECT '🎉' AS emoji");
    }

    #[test]
    fn statement_ranges_handle_unicode_in_strings() {
        // Ensure semicolons inside Unicode strings are not treated as delimiters
        let sql = "SELECT '你好;世界' AS greeting; SELECT 2;";
        let ranges = compute_statement_ranges(sql);
        assert_eq!(ranges.len(), 2);
        assert_eq!(&sql[ranges[0].clone()], "SELECT '你好;世界' AS greeting");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");
    }

    #[test]
    fn statement_ranges_handle_mixed_ascii_unicode() {
        // Mix of ASCII and various Unicode scripts
        let sql = "SELECT 'café' AS drink; SELECT 'naïve' AS word; SELECT 'Müller' AS name;";
        let ranges = compute_statement_ranges(sql);
        assert_eq!(ranges.len(), 3);
        assert_eq!(&sql[ranges[0].clone()], "SELECT 'café' AS drink");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 'naïve' AS word");
        assert_eq!(&sql[ranges[2].clone()], "SELECT 'Müller' AS name");
    }

    #[test]
    fn unicode_sql_parses_correctly() {
        // End-to-end test: ensure Unicode SQL parses and produces correct ranges
        let mut request = base_request();
        request.sql = "SELECT '日本' AS country; SELECT 'émoji: 🚀' AS test;".to_string();

        let (statements, issues) = collect_statements(&request);
        assert!(issues.is_empty(), "Expected no issues, got {issues:?}");
        assert_eq!(statements.len(), 2);

        // Verify the source ranges correctly capture the Unicode content
        let first_sql = &statements[0].source_sql[statements[0].source_range.clone()];
        let second_sql = &statements[1].source_sql[statements[1].source_range.clone()];
        assert!(
            first_sql.contains("日本"),
            "First statement should contain Japanese: {first_sql}"
        );
        assert!(
            second_sql.contains("🚀"),
            "Second statement should contain rocket emoji: {second_sql}"
        );
    }
}
