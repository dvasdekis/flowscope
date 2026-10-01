//! Parsing and classification for metadata-only external SQL objects.
//!
//! The supported statements are intentionally kept separate from relational
//! analysis: external objects do not become graph nodes, and external-file and
//! CETAS write lineage are not modeled.

use crate::error::{ParseError, ParseErrorKind};
use crate::parser::parse_sql_with_dialect_output;
use crate::types::{issue_codes, Dialect, Issue};
use sqlparser::ast::{Expr, FunctionArguments, SetExpr, Statement};
use sqlparser::dialect::MsSqlDialect;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer};
use std::collections::HashSet;
use std::ops::Range;

const UNSUPPORTED_LINEAGE_MESSAGE: &str =
    "CREATE EXTERNAL FILE FORMAT is metadata only; external-file lineage is not modeled.";
const EXTERNAL_TABLE_UNSUPPORTED_LINEAGE_MESSAGE: &str =
    "CREATE EXTERNAL TABLE is parsed, but external-file lineage is not modeled.";
const CETAS_UNSUPPORTED_LINEAGE_MESSAGE: &str =
    "CREATE EXTERNAL TABLE AS SELECT is parsed, but external-table and file-write lineage are not modeled.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExternalMetadataStatement {
    FileFormat(ExternalFileFormatDefinition),
    ConditionalFileFormat(ExternalFileFormatDefinition),
    ExternalTable(ExternalTableDefinition),
    Cetas(CetasDefinition),
}

impl ExternalMetadataStatement {
    pub(crate) fn statement_type(&self) -> &'static str {
        match self {
            Self::FileFormat(_) | Self::ConditionalFileFormat(_) => "CREATE_EXTERNAL_FILE_FORMAT",
            Self::ExternalTable(_) => "CREATE_EXTERNAL_TABLE",
            Self::Cetas(_) => "CREATE_EXTERNAL_TABLE_AS_SELECT",
        }
    }

    pub(crate) fn unsupported_lineage_warning(&self) -> Issue {
        match self {
            Self::FileFormat(_) | Self::ConditionalFileFormat(_) => {
                Issue::warning(issue_codes::UNSUPPORTED_SYNTAX, UNSUPPORTED_LINEAGE_MESSAGE)
            }
            Self::ExternalTable(_) => Issue::warning(
                issue_codes::UNSUPPORTED_SYNTAX,
                EXTERNAL_TABLE_UNSUPPORTED_LINEAGE_MESSAGE,
            ),
            Self::Cetas(_) => Issue::warning(
                issue_codes::UNSUPPORTED_SYNTAX,
                CETAS_UNSUPPORTED_LINEAGE_MESSAGE,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CetasDefinition {
    pub(crate) query_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalTableDefinition {
    pub(crate) name: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalFileFormatDefinition {
    pub(crate) name: Vec<String>,
    pub(crate) format: ExternalFileFormatType,
    pub(crate) format_options: Vec<DelimitedTextFormatOption>,
    pub(crate) data_compression: Option<ExternalDataCompression>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalFileFormatType {
    DelimitedText,
    Parquet,
    Delta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DelimitedTextFormatOption {
    FieldTerminator(String),
    StringDelimiter(String),
    FirstRow(u8),
    DateFormat(String),
    UseTypeDefault(bool),
    Encoding(DelimitedTextEncoding),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelimitedTextEncoding {
    Utf8,
    Utf16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalDataCompression {
    Gzip,
    Snappy,
}

/// Validates supported external metadata subsets. External-table column
/// definitions are checked through the MSSQL `CREATE TABLE` parser; other
/// statement kinds return `Ok(None)`.
pub(crate) fn parse_external_metadata_statement(
    sql: &str,
) -> Result<Option<ExternalMetadataStatement>, ParseError> {
    let Ok(tokens) = Tokenizer::new(&MsSqlDialect {}, sql).tokenize_with_location() else {
        return Ok(None);
    };

    let mut parser = ExternalMetadataParser::new(sql, &tokens);
    if parser
        .peek()
        .is_some_and(|token| is_keyword(&token.token, "IF"))
    {
        return parser.parse_conditional_external_metadata();
    }
    if !parser.consume_keyword("CREATE") || !parser.consume_keyword("EXTERNAL") {
        return Ok(None);
    }

    if parser.consume_keyword("FILE") && parser.consume_keyword("FORMAT") {
        return parser.parse_file_format().map(Some);
    }
    if parser.consume_keyword("TABLE") {
        return parser.parse_cetas();
    }
    Ok(None)
}

fn validate_external_table_columns(
    source_sql: &str,
    column_range: Range<usize>,
) -> Result<(), ParseError> {
    let columns_sql = source_sql.get(column_range.clone()).ok_or_else(|| {
        ParseError::new("Could not read external table column definitions")
            .with_dialect(Dialect::Mssql)
            .with_kind(ParseErrorKind::SyntaxError)
    })?;
    let prefix = "CREATE TABLE [__flowscope_external_table] ";
    let adapted_sql = format!("{prefix}{columns_sql}");
    let output = parse_sql_with_dialect_output(&adapted_sql, Dialect::Mssql).map_err(|error| {
        map_adapted_columns_error(
            source_sql,
            &adapted_sql,
            prefix.len(),
            column_range.start,
            error,
        )
    })?;
    let [Statement::CreateTable(create)] = output.statements.as_slice() else {
        return Err(
            ParseError::new("Expected external table column definitions")
                .with_dialect(Dialect::Mssql)
                .with_kind(ParseErrorKind::SyntaxError),
        );
    };
    if create.columns.is_empty() || create.query.is_some() {
        return Err(ParseError::new(
            "External table requires one or more typed column definitions",
        )
        .with_dialect(Dialect::Mssql)
        .with_kind(ParseErrorKind::SyntaxError));
    }
    if !create.constraints.is_empty()
        || create
            .columns
            .iter()
            .any(|column| !column.options.is_empty())
    {
        let mut error = ParseError::new(
            "The supported external table subset requires typed columns without column or table constraints",
        )
        .with_dialect(Dialect::Mssql)
        .with_kind(ParseErrorKind::UnsupportedFeature);
        if let Some(position) = position_at_offset(source_sql, column_range.start) {
            error.position = Some(position);
        }
        return Err(error);
    }
    Ok(())
}

fn token_byte_range(source_sql: &str, token: &TokenWithSpan) -> Option<Range<usize>> {
    let start = crate::analyzer::helpers::line_col_to_offset(
        source_sql,
        token.span.start.line.try_into().ok()?,
        token.span.start.column.try_into().ok()?,
    )?;
    let end = crate::analyzer::helpers::line_col_to_offset(
        source_sql,
        token.span.end.line.try_into().ok()?,
        token.span.end.column.try_into().ok()?,
    )?;
    (start <= end
        && end <= source_sql.len()
        && source_sql.is_char_boundary(start)
        && source_sql.is_char_boundary(end))
    .then_some(start..end)
}

fn map_fragment_error(
    source_sql: &str,
    fragment_sql: &str,
    fragment_offset: usize,
    mut error: ParseError,
) -> ParseError {
    if let Some(position) = error.position {
        if let Some(relative_offset) = crate::analyzer::helpers::line_col_to_offset(
            fragment_sql,
            position.line,
            position.column,
        ) {
            if let Some(source_position) =
                position_at_offset(source_sql, fragment_offset.saturating_add(relative_offset))
            {
                error.position = Some(source_position);
                if let Some(message_position) = error.message.rfind(" at Line:") {
                    error.message.truncate(message_position);
                }
            }
        }
    }
    error.dialect = Some(Dialect::Mssql);
    error
}

fn map_adapted_columns_error(
    source_sql: &str,
    adapted_sql: &str,
    prefix_len: usize,
    source_column_offset: usize,
    mut error: ParseError,
) -> ParseError {
    if let Some(position) = error.position {
        if let Some(adapted_offset) = crate::analyzer::helpers::line_col_to_offset(
            adapted_sql,
            position.line,
            position.column,
        ) {
            let column_offset = adapted_offset.saturating_sub(prefix_len);
            if let Some(source_position) = position_at_offset(
                source_sql,
                source_column_offset.saturating_add(column_offset),
            ) {
                error.position = Some(source_position);
                if let Some(message_position) = error.message.rfind(" at Line:") {
                    error.message.truncate(message_position);
                }
            }
        }
    }
    error.dialect = Some(Dialect::Mssql);
    error
}

fn position_at_offset(source_sql: &str, offset: usize) -> Option<crate::error::Position> {
    let prefix = source_sql.get(..offset)?;
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let current_line = prefix.rsplit_once('\n').map_or(prefix, |(_, line)| line);
    Some(crate::error::Position {
        line,
        column: current_line.chars().count() + 1,
    })
}

struct ExternalMetadataParser<'a> {
    source_sql: &'a str,
    tokens: Vec<&'a TokenWithSpan>,
    position: usize,
    statement_name: &'static str,
    object_name: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConditionalExternalMetadataGuard {
    NotExists,
    Exists,
    ObjectId,
}

impl<'a> ExternalMetadataParser<'a> {
    fn new(source_sql: &'a str, tokens: &'a [TokenWithSpan]) -> Self {
        Self {
            source_sql,
            tokens: tokens
                .iter()
                .filter(|token| !matches!(&token.token, Token::Whitespace(_)))
                .collect(),
            position: 0,
            statement_name: "external metadata statement",
            object_name: "external object",
        }
    }

    fn parse_file_format(&mut self) -> Result<ExternalMetadataStatement, ParseError> {
        self.statement_name = "CREATE EXTERNAL FILE FORMAT";
        self.object_name = "file format";
        let name = self.parse_object_name(2)?;
        self.expect_keyword("WITH")?;
        self.expect_token(
            |token| matches!(token, Token::LParen),
            "opening parenthesis after WITH",
        )?;
        self.expect_keyword("FORMAT_TYPE")?;
        self.expect_token(|token| matches!(token, Token::Eq), "'=' after FORMAT_TYPE")?;

        let format = self.parse_format_type()?;
        let mut format_options = Vec::new();
        let mut data_compression = None;

        if self.consume_token(|token| matches!(token, Token::Comma)) {
            if self.consume_keyword("FORMAT_OPTIONS") {
                if format != ExternalFileFormatType::DelimitedText {
                    return Err(self.error(
                        "FORMAT_OPTIONS is supported only for DELIMITEDTEXT external file formats",
                        ParseErrorKind::UnsupportedFeature,
                    ));
                }
                format_options = self.parse_format_options()?;
                if self.consume_token(|token| matches!(token, Token::Comma)) {
                    data_compression = Some(self.parse_data_compression(format)?);
                }
            } else {
                data_compression = Some(self.parse_data_compression(format)?);
            }
        }

        self.expect_token(
            |token| matches!(token, Token::RParen),
            "closing parenthesis after external file format options",
        )?;
        self.consume_token(|token| matches!(token, Token::SemiColon));
        if self.peek().is_some() {
            return Err(self.error(
                "Unexpected token after CREATE EXTERNAL FILE FORMAT statement",
                ParseErrorKind::SyntaxError,
            ));
        }

        Ok(ExternalMetadataStatement::FileFormat(
            ExternalFileFormatDefinition {
                name,
                format,
                format_options,
                data_compression,
            },
        ))
    }

    fn parse_cetas(&mut self) -> Result<Option<ExternalMetadataStatement>, ParseError> {
        self.statement_name = "CREATE EXTERNAL TABLE AS SELECT";
        self.object_name = "table";
        let table_name = self.parse_object_name(3)?;

        if self
            .peek()
            .is_some_and(|token| matches!(&token.token, Token::LParen))
        {
            let column_list_start = self.position;
            if self.has_external_table_clause_after_column_list(column_list_start) {
                return self
                    .parse_external_table(table_name, column_list_start)
                    .map(Some);
            }
            if let Err(error) = self.parse_cetas_output_columns() {
                if self.has_cetas_clause_after_column_list(column_list_start) {
                    return Err(error);
                }
                return Ok(None);
            }
        }

        if !self.consume_keyword("WITH") {
            return Ok(None);
        }
        if !self.consume_token(|token| matches!(token, Token::LParen)) {
            return Ok(None);
        }

        self.expect_keyword("LOCATION")?;
        self.expect_equals("after LOCATION")?;
        let (location, location_token) = self.parse_string_value_with_token("LOCATION")?;
        if location.is_empty() {
            return Err(self.error_at(
                Some(location_token),
                "LOCATION must not be empty",
                ParseErrorKind::SyntaxError,
            ));
        }
        self.expect_comma("after LOCATION")?;

        self.expect_keyword("DATA_SOURCE")?;
        self.expect_equals("after DATA_SOURCE")?;
        let _data_source = self.parse_object_name(1)?;
        self.expect_comma("after DATA_SOURCE")?;

        self.expect_keyword("FILE_FORMAT")?;
        self.expect_equals("after FILE_FORMAT")?;
        let _file_format = self.parse_object_name(1)?;
        self.expect_token(
            |token| matches!(token, Token::RParen),
            "closing parenthesis after CETAS options",
        )?;

        if !self.consume_keyword("AS") {
            return Ok(None);
        }
        let Some(query_start) = self.peek() else {
            return Err(self.error(
                "Expected a SELECT query after AS",
                ParseErrorKind::UnexpectedEof,
            ));
        };
        let query_start_offset = usize::try_from(query_start.span.start.line)
            .ok()
            .zip(usize::try_from(query_start.span.start.column).ok())
            .and_then(|(line, column)| {
                crate::analyzer::helpers::line_col_to_offset(self.source_sql, line, column)
            })
            .ok_or_else(|| {
                self.error_at(
                    Some(query_start),
                    "Could not determine the CETAS query source range",
                    ParseErrorKind::SyntaxError,
                )
            })?;

        Ok(Some(ExternalMetadataStatement::Cetas(CetasDefinition {
            query_range: query_start_offset..self.source_sql.len(),
        })))
    }

    fn parse_external_table(
        &mut self,
        name: Vec<String>,
        column_list_start: usize,
    ) -> Result<ExternalMetadataStatement, ParseError> {
        self.statement_name = "CREATE EXTERNAL TABLE";
        let close_after = self
            .after_matching_parenthesis(column_list_start)
            .ok_or_else(|| {
                self.error(
                    "Expected a closing parenthesis after external table columns",
                    ParseErrorKind::SyntaxError,
                )
            })?;
        let open = self.tokens[column_list_start];
        let close = self.tokens[close_after - 1];
        let column_range = token_byte_range(self.source_sql, open)
            .zip(token_byte_range(self.source_sql, close))
            .map(|(start, end)| start.start..end.end)
            .ok_or_else(|| {
                self.error_at(
                    Some(open),
                    "Could not determine the external table column source range",
                    ParseErrorKind::SyntaxError,
                )
            })?;
        validate_external_table_columns(self.source_sql, column_range)?;
        self.position = close_after;

        self.expect_keyword("WITH")?;
        self.expect_token(
            |token| matches!(token, Token::LParen),
            "opening parenthesis after external table WITH",
        )?;
        let mut saw_location = false;
        let mut saw_data_source = false;
        for _ in 0..2 {
            let Some(option_token) = self.peek() else {
                return Err(self.error(
                    "Expected LOCATION and DATA_SOURCE before FILE_FORMAT",
                    ParseErrorKind::UnexpectedEof,
                ));
            };
            if is_keyword(&option_token.token, "LOCATION") {
                if saw_location {
                    return Err(self.error_at(
                        Some(option_token),
                        "Duplicate LOCATION option in CREATE EXTERNAL TABLE",
                        ParseErrorKind::SyntaxError,
                    ));
                }
                saw_location = true;
                self.position += 1;
                self.expect_equals("after LOCATION")?;
                let (location, location_token) = self.parse_string_value_with_token("LOCATION")?;
                if location.is_empty() {
                    return Err(self.error_at(
                        Some(location_token),
                        "LOCATION must not be empty",
                        ParseErrorKind::SyntaxError,
                    ));
                }
            } else if is_keyword(&option_token.token, "DATA_SOURCE") {
                if saw_data_source {
                    return Err(self.error_at(
                        Some(option_token),
                        "Duplicate DATA_SOURCE option in CREATE EXTERNAL TABLE",
                        ParseErrorKind::SyntaxError,
                    ));
                }
                saw_data_source = true;
                self.position += 1;
                self.expect_equals("after DATA_SOURCE")?;
                let _data_source = self.parse_object_name(1)?;
            } else if is_keyword(&option_token.token, "FILE_FORMAT") {
                return Err(self.error_at(
                    Some(option_token),
                    "FILE_FORMAT must follow LOCATION and DATA_SOURCE",
                    ParseErrorKind::SyntaxError,
                ));
            } else {
                return Err(self.error_at(
                    Some(option_token),
                    "Expected LOCATION or DATA_SOURCE before FILE_FORMAT",
                    ParseErrorKind::SyntaxError,
                ));
            }
            self.expect_comma("between external table options")?;
        }
        if !saw_location || !saw_data_source {
            return Err(self.error(
                "CREATE EXTERNAL TABLE requires LOCATION and DATA_SOURCE before FILE_FORMAT",
                ParseErrorKind::SyntaxError,
            ));
        }

        self.expect_keyword("FILE_FORMAT")?;
        self.expect_equals("after FILE_FORMAT")?;
        let _file_format = self.parse_object_name(1)?;
        self.expect_token(
            |token| matches!(token, Token::RParen),
            "closing parenthesis after external table options",
        )?;
        self.consume_token(|token| matches!(token, Token::SemiColon));
        if self.peek().is_some() {
            return Err(self.error(
                "Unexpected token after CREATE EXTERNAL TABLE statement",
                ParseErrorKind::SyntaxError,
            ));
        }

        Ok(ExternalMetadataStatement::ExternalTable(
            ExternalTableDefinition { name },
        ))
    }

    fn parse_conditional_external_metadata(
        &mut self,
    ) -> Result<Option<ExternalMetadataStatement>, ParseError> {
        let Some(guard) = self.conditional_external_metadata_guard() else {
            return Ok(None);
        };

        self.statement_name = "conditional external metadata";
        self.consume_keyword("IF");
        match guard {
            ConditionalExternalMetadataGuard::NotExists => {
                self.parse_if_not_exists_condition()?;
            }
            ConditionalExternalMetadataGuard::Exists => {
                return Err(self.error(
                    "Expected NOT in conditional external metadata",
                    ParseErrorKind::SyntaxError,
                ));
            }
            ConditionalExternalMetadataGuard::ObjectId => {
                self.parse_object_id_is_null_condition()?;
            }
        }
        let block_body = self.consume_keyword("BEGIN");
        let body_start_position = self.position;
        let body_start_token = self.tokens.get(body_start_position).copied().ok_or_else(|| {
            self.error(
                "Expected CREATE EXTERNAL FILE FORMAT or typed CREATE EXTERNAL TABLE after the conditional guard",
                ParseErrorKind::UnexpectedEof,
            )
        })?;
        let starts_external_create = is_keyword(&body_start_token.token, "CREATE")
            && self
                .tokens
                .get(body_start_position + 1)
                .is_some_and(|token| is_keyword(&token.token, "EXTERNAL"));
        let body_kind = self.tokens.get(body_start_position + 2);
        let is_supported_body_kind = body_kind.is_some_and(|token| {
            is_keyword(&token.token, "TABLE")
                || (is_keyword(&token.token, "FILE")
                    && self
                        .tokens
                        .get(body_start_position + 3)
                        .is_some_and(|token| is_keyword(&token.token, "FORMAT")))
        });
        if !starts_external_create || !is_supported_body_kind {
            return Err(self.error_at(
                Some(body_start_token),
                "Expected CREATE EXTERNAL FILE FORMAT or typed CREATE EXTERNAL TABLE as the conditional guard body",
                ParseErrorKind::SyntaxError,
            ));
        }
        let body_start = token_byte_range(self.source_sql, body_start_token)
            .ok_or_else(|| {
                self.error_at(
                    Some(body_start_token),
                    "Could not determine the conditional external metadata source range",
                    ParseErrorKind::SyntaxError,
                )
            })?
            .start;

        let end_position = if block_body {
            Some(
                (self.position..self.tokens.len())
                    .find(|position| is_keyword(&self.tokens[*position].token, "END"))
                    .ok_or_else(|| {
                        self.error(
                            "Expected END after conditional external metadata",
                            ParseErrorKind::UnexpectedEof,
                        )
                    })?,
            )
        } else {
            None
        };
        let body_end = match end_position {
            Some(end_position) => {
                token_byte_range(self.source_sql, self.tokens[end_position])
                    .ok_or_else(|| {
                        self.error_at(
                            Some(self.tokens[end_position]),
                            "Could not determine the conditional block source range",
                            ParseErrorKind::SyntaxError,
                        )
                    })?
                    .start
            }
            None => self.source_sql.len(),
        };
        let body_sql = self.source_sql.get(body_start..body_end).ok_or_else(|| {
            self.error(
                "Could not read the conditional external metadata source range",
                ParseErrorKind::SyntaxError,
            )
        })?;
        let body = parse_external_metadata_statement(body_sql)
            .map_err(|error| map_fragment_error(self.source_sql, body_sql, body_start, error))?;
        let Some(body) = body else {
            return Err(self.error_at(
                Some(body_start_token),
                "Expected CREATE EXTERNAL FILE FORMAT or typed CREATE EXTERNAL TABLE as the conditional guard body",
                ParseErrorKind::SyntaxError,
            ));
        };
        let conditional_body = match body {
            ExternalMetadataStatement::FileFormat(format) => {
                ExternalMetadataStatement::ConditionalFileFormat(format)
            }
            table @ ExternalMetadataStatement::ExternalTable(_) => table,
            ExternalMetadataStatement::ConditionalFileFormat(_)
            | ExternalMetadataStatement::Cetas(_) => {
                return Err(self.error_at(
                    Some(body_start_token),
                    "Conditional metadata guards support only CREATE EXTERNAL FILE FORMAT or typed CREATE EXTERNAL TABLE bodies",
                    ParseErrorKind::UnsupportedFeature,
                ));
            }
        };

        if let Some(end_position) = end_position {
            self.position = end_position + 1;
            self.consume_token(|token| matches!(token, Token::SemiColon));
            if self.peek().is_some() {
                return Err(self.error(
                    "Unexpected token after conditional external metadata",
                    ParseErrorKind::SyntaxError,
                ));
            }
        }
        Ok(Some(conditional_body))
    }

    fn conditional_external_metadata_guard(&self) -> Option<ConditionalExternalMetadataGuard> {
        if !self
            .tokens
            .first()
            .is_some_and(|token| is_keyword(&token.token, "IF"))
        {
            return None;
        }

        if self
            .tokens
            .get(1)
            .is_some_and(|token| is_keyword(&token.token, "NOT"))
            && self
                .tokens
                .get(2)
                .is_some_and(|token| is_keyword(&token.token, "EXISTS"))
            && self
                .parenthesized_guard_body_start(3)
                .is_some_and(|position| self.external_metadata_body_start(position).is_some())
        {
            return Some(ConditionalExternalMetadataGuard::NotExists);
        }

        if self
            .tokens
            .get(1)
            .is_some_and(|token| is_keyword(&token.token, "EXISTS"))
            && self
                .parenthesized_guard_body_start(2)
                .is_some_and(|position| self.external_metadata_body_start(position).is_some())
        {
            return Some(ConditionalExternalMetadataGuard::Exists);
        }

        if self
            .tokens
            .get(1)
            .is_some_and(|token| is_keyword(&token.token, "OBJECT_ID"))
            && self
                .object_id_guard_body_start()
                .is_some_and(|position| self.external_metadata_body_start(position).is_some())
        {
            return Some(ConditionalExternalMetadataGuard::ObjectId);
        }

        None
    }

    fn parenthesized_guard_body_start(&self, condition_start: usize) -> Option<usize> {
        if self
            .tokens
            .get(condition_start)
            .is_some_and(|token| matches!(&token.token, Token::LParen))
        {
            self.after_matching_parenthesis(condition_start)
        } else {
            Some(condition_start)
        }
    }

    fn object_id_guard_body_start(&self) -> Option<usize> {
        self.object_id_guard_body_start_at(0)
    }

    fn object_id_guard_body_start_at(&self, if_position: usize) -> Option<usize> {
        let function_open = if_position + 2;
        let after_function = if self
            .tokens
            .get(function_open)
            .is_some_and(|token| matches!(&token.token, Token::LParen))
        {
            self.after_matching_parenthesis(function_open)
                .or_else(|| self.object_id_null_test_end(function_open + 1))
                .unwrap_or(function_open + 1)
        } else {
            function_open
        };

        Some(
            self.object_id_null_test_end(after_function)
                .unwrap_or(after_function),
        )
    }

    fn object_id_null_test_end(&self, start: usize) -> Option<usize> {
        for (position, token) in self.tokens.iter().enumerate().skip(start) {
            if !is_keyword(&token.token, "IS") {
                continue;
            }
            let mut after_test = position + 1;
            if self
                .tokens
                .get(after_test)
                .is_some_and(|token| is_keyword(&token.token, "NOT"))
            {
                after_test += 1;
            }
            if self
                .tokens
                .get(after_test)
                .is_some_and(|token| is_keyword(&token.token, "NULL"))
            {
                return Some(after_test + 1);
            }
            return Some(position + 1);
        }
        None
    }

    fn external_metadata_body_start(&self, position: usize) -> Option<usize> {
        self.direct_external_metadata_body_start(position)
            .or_else(|| {
                let body_start = if self
                    .tokens
                    .get(position)
                    .is_some_and(|token| is_keyword(&token.token, "BEGIN"))
                {
                    position + 1
                } else {
                    position
                };
                self.nested_guard_contains_external_metadata(body_start)
                    .then_some(body_start)
            })
    }

    fn direct_external_metadata_body_start(&self, position: usize) -> Option<usize> {
        let body_start = if self
            .tokens
            .get(position)
            .is_some_and(|token| is_keyword(&token.token, "BEGIN"))
        {
            position + 1
        } else {
            position
        };
        let is_create_external = is_keyword(&self.tokens.get(body_start)?.token, "CREATE")
            && self
                .tokens
                .get(body_start + 1)
                .is_some_and(|token| is_keyword(&token.token, "EXTERNAL"));
        let body_kind = self.tokens.get(body_start + 2);
        let supported_body_kind = body_kind.is_some_and(|token| {
            is_keyword(&token.token, "TABLE")
                || (is_keyword(&token.token, "FILE")
                    && self
                        .tokens
                        .get(body_start + 3)
                        .is_some_and(|token| is_keyword(&token.token, "FORMAT")))
        });
        (is_create_external && supported_body_kind).then_some(body_start)
    }

    fn nested_guard_contains_external_metadata(&self, if_position: usize) -> bool {
        if !self
            .tokens
            .get(if_position)
            .is_some_and(|token| is_keyword(&token.token, "IF"))
        {
            return false;
        }

        let body_position = if self
            .tokens
            .get(if_position + 1)
            .is_some_and(|token| is_keyword(&token.token, "NOT"))
            && self
                .tokens
                .get(if_position + 2)
                .is_some_and(|token| is_keyword(&token.token, "EXISTS"))
        {
            self.parenthesized_guard_body_start(if_position + 3)
        } else if self
            .tokens
            .get(if_position + 1)
            .is_some_and(|token| is_keyword(&token.token, "EXISTS"))
        {
            self.parenthesized_guard_body_start(if_position + 2)
        } else if self
            .tokens
            .get(if_position + 1)
            .is_some_and(|token| is_keyword(&token.token, "OBJECT_ID"))
        {
            self.object_id_guard_body_start_at(if_position)
        } else {
            None
        };

        body_position
            .and_then(|position| self.direct_external_metadata_body_start(position))
            .is_some()
    }

    fn parse_if_not_exists_condition(&mut self) -> Result<(), ParseError> {
        self.expect_keyword("NOT")?;
        self.expect_keyword("EXISTS")?;
        let open_position = self.position;
        self.expect_token(
            |token| matches!(token, Token::LParen),
            "opening parenthesis after IF NOT EXISTS",
        )?;
        let close_after_condition =
            self.after_matching_parenthesis(open_position)
                .ok_or_else(|| {
                    self.error(
                        "Expected a closing parenthesis after the IF NOT EXISTS query",
                        ParseErrorKind::SyntaxError,
                    )
                })?;
        let condition_start = open_position + 1;
        let condition_end = close_after_condition - 1;
        if condition_start >= condition_end
            || !is_keyword(&self.tokens[condition_start].token, "SELECT")
        {
            return Err(self.error_at(
                self.tokens.get(condition_start).copied(),
                "IF NOT EXISTS requires a SELECT query",
                ParseErrorKind::SyntaxError,
            ));
        }
        let condition_range = token_byte_range(self.source_sql, self.tokens[condition_start])
            .zip(token_byte_range(
                self.source_sql,
                self.tokens[condition_end - 1],
            ))
            .map(|(start, end)| start.start..end.end)
            .ok_or_else(|| {
                self.error_at(
                    self.tokens.get(condition_start).copied(),
                    "Could not determine the IF NOT EXISTS query source range",
                    ParseErrorKind::SyntaxError,
                )
            })?;
        let condition_sql = self
            .source_sql
            .get(condition_range.clone())
            .ok_or_else(|| {
                self.error(
                    "Could not read the IF NOT EXISTS query source range",
                    ParseErrorKind::SyntaxError,
                )
            })?;
        let condition_output = parse_sql_with_dialect_output(condition_sql, Dialect::Mssql)
            .map_err(|error| {
                map_fragment_error(self.source_sql, condition_sql, condition_range.start, error)
            })?;
        if !matches!(
            condition_output.statements.as_slice(),
            [Statement::Query(_)]
        ) {
            return Err(self.error_at(
                self.tokens.get(condition_start).copied(),
                "IF NOT EXISTS requires a SELECT query",
                ParseErrorKind::SyntaxError,
            ));
        }
        self.position = close_after_condition;
        Ok(())
    }

    fn parse_object_id_is_null_condition(&mut self) -> Result<(), ParseError> {
        let function_start = self.position;
        let function_token = self.peek();
        self.expect_keyword("OBJECT_ID")?;
        let open_position = self.position;
        self.expect_token(
            |token| matches!(token, Token::LParen),
            "opening parenthesis after OBJECT_ID",
        )?;
        let close_after_function =
            self.after_matching_parenthesis(open_position)
                .ok_or_else(|| {
                    self.error_at(
                        Some(self.tokens[open_position]),
                        "Expected a closing parenthesis after OBJECT_ID arguments",
                        ParseErrorKind::SyntaxError,
                    )
                })?;
        let close_position = close_after_function - 1;
        self.position = close_after_function;
        self.expect_keyword("IS")?;
        let not_token = if self
            .peek()
            .is_some_and(|token| is_keyword(&token.token, "NOT"))
        {
            let token = self.peek();
            self.position += 1;
            token
        } else {
            None
        };
        self.expect_keyword("NULL")?;
        let null_position = self.position - 1;

        let condition_range = token_byte_range(self.source_sql, self.tokens[function_start])
            .zip(token_byte_range(
                self.source_sql,
                self.tokens[null_position],
            ))
            .map(|(start, end)| start.start..end.end)
            .ok_or_else(|| {
                self.error_at(
                    function_token,
                    "Could not determine the OBJECT_ID condition source range",
                    ParseErrorKind::SyntaxError,
                )
            })?;
        let condition_sql = self
            .source_sql
            .get(condition_range.clone())
            .ok_or_else(|| {
                self.error(
                    "Could not read the OBJECT_ID condition source range",
                    ParseErrorKind::SyntaxError,
                )
            })?;
        let prefix = "SELECT 1 WHERE ";
        let adapted_sql = format!("{prefix}{condition_sql}");
        let condition_output = parse_sql_with_dialect_output(&adapted_sql, Dialect::Mssql)
            .map_err(|error| {
                map_adapted_columns_error(
                    self.source_sql,
                    &adapted_sql,
                    prefix.len(),
                    condition_range.start,
                    error,
                )
            })?;

        let [Statement::Query(query)] = condition_output.statements.as_slice() else {
            return Err(self.error_at(
                function_token,
                "OBJECT_ID guard requires one valid MSSQL condition expression",
                ParseErrorKind::SyntaxError,
            ));
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            return Err(self.error_at(
                function_token,
                "OBJECT_ID guard requires a SELECT condition expression",
                ParseErrorKind::SyntaxError,
            ));
        };
        let Some(condition) = select.selection.as_ref() else {
            return Err(self.error_at(
                function_token,
                "OBJECT_ID guard requires an IS NULL condition",
                ParseErrorKind::SyntaxError,
            ));
        };
        let object_id_expression = match condition {
            Expr::IsNull(expression) if not_token.is_none() => expression.as_ref(),
            Expr::IsNotNull(expression) if not_token.is_some() => expression.as_ref(),
            _ => {
                return Err(self.error_at(
                    Some(self.tokens[null_position]),
                    "OBJECT_ID guard condition must be OBJECT_ID(...) IS NULL",
                    ParseErrorKind::SyntaxError,
                ));
            }
        };
        let Expr::Function(function) = object_id_expression else {
            return Err(self.error_at(
                function_token,
                "OBJECT_ID guard requires an OBJECT_ID function call",
                ParseErrorKind::SyntaxError,
            ));
        };
        let function_name = function.name.0.first().and_then(|part| part.as_ident());
        if function.name.0.len() != 1
            || !function_name.is_some_and(|name| name.value.eq_ignore_ascii_case("OBJECT_ID"))
        {
            return Err(self.error_at(
                function_token,
                "OBJECT_ID guard requires the unqualified OBJECT_ID function",
                ParseErrorKind::SyntaxError,
            ));
        }

        let FunctionArguments::List(arguments) = &function.args else {
            return Err(self.error_at(
                function_token,
                "OBJECT_ID guard requires a literal object name",
                ParseErrorKind::SyntaxError,
            ));
        };
        if arguments.args.is_empty() {
            return Err(self.error_at(
                Some(self.tokens[close_position]),
                "OBJECT_ID guard requires a literal object name",
                ParseErrorKind::SyntaxError,
            ));
        }
        let argument_tokens = &self.tokens[open_position + 1..close_position];
        let expected_arguments = match argument_tokens {
            [name] if is_object_id_string_literal(&name.token) => 1,
            [name, comma, object_type]
                if is_object_id_string_literal(&name.token)
                    && matches!(&comma.token, Token::Comma)
                    && is_object_id_string_literal(&object_type.token) =>
            {
                2
            }
            _ => {
                let token = argument_tokens.first().copied();
                return Err(self.error_at(
                    token.or(Some(self.tokens[close_position])),
                    "OBJECT_ID guard supports a literal object name and optional literal object type",
                    ParseErrorKind::UnsupportedFeature,
                ));
            }
        };
        if arguments.args.len() != expected_arguments {
            return Err(self.error_at(
                function_token,
                "OBJECT_ID guard supports one or two literal arguments",
                ParseErrorKind::SyntaxError,
            ));
        }
        if let Some(not_token) = not_token {
            return Err(self.error_at(
                Some(not_token),
                "OBJECT_ID IS NOT NULL guards are not supported",
                ParseErrorKind::UnsupportedFeature,
            ));
        }
        Ok(())
    }

    fn parse_cetas_output_columns(&mut self) -> Result<Vec<String>, ParseError> {
        self.expect_token(
            |token| matches!(token, Token::LParen),
            "opening parenthesis before CETAS output column names",
        )?;

        if self
            .peek()
            .is_some_and(|token| matches!(&token.token, Token::RParen))
        {
            return Err(self.error(
                "CETAS output column list must contain at least one column name",
                ParseErrorKind::SyntaxError,
            ));
        }

        let mut columns = vec![self.parse_identifier()?];
        while self.consume_token(|token| matches!(token, Token::Comma)) {
            if self
                .peek()
                .is_some_and(|token| matches!(&token.token, Token::RParen))
            {
                return Err(self.error(
                    "CETAS output column list cannot end with a comma",
                    ParseErrorKind::SyntaxError,
                ));
            }
            columns.push(self.parse_identifier()?);
        }

        self.expect_token(
            |token| matches!(token, Token::RParen),
            "closing parenthesis after CETAS output column names",
        )?;
        Ok(columns)
    }

    fn has_cetas_clause_after_column_list(&self, column_list_start: usize) -> bool {
        let Some(with_position) = self.after_matching_parenthesis(column_list_start) else {
            return false;
        };
        if !self
            .tokens
            .get(with_position)
            .is_some_and(|token| is_keyword(&token.token, "WITH"))
        {
            return false;
        }

        let Some(options_start) = with_position.checked_add(1) else {
            return false;
        };
        let Some(as_position) = self.after_matching_parenthesis(options_start) else {
            return false;
        };
        self.tokens
            .get(as_position)
            .is_some_and(|token| is_keyword(&token.token, "AS"))
    }

    fn has_external_table_clause_after_column_list(&self, column_list_start: usize) -> bool {
        let Some(with_position) = self.after_matching_parenthesis(column_list_start) else {
            return false;
        };
        if !self
            .tokens
            .get(with_position)
            .is_some_and(|token| is_keyword(&token.token, "WITH"))
        {
            return false;
        }
        let Some(options_start) = with_position.checked_add(1) else {
            return false;
        };
        let Some(after_options) = self.after_matching_parenthesis(options_start) else {
            return false;
        };
        !self
            .tokens
            .get(after_options)
            .is_some_and(|token| is_keyword(&token.token, "AS"))
    }

    fn after_matching_parenthesis(&self, open_position: usize) -> Option<usize> {
        if !matches!(&self.tokens.get(open_position)?.token, Token::LParen) {
            return None;
        }

        let mut depth = 0usize;
        for (position, token) in self.tokens.iter().enumerate().skip(open_position) {
            match &token.token {
                Token::LParen => depth += 1,
                Token::RParen => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return position.checked_add(1);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn parse_object_name(&mut self, max_parts: usize) -> Result<Vec<String>, ParseError> {
        let mut parts = vec![self.parse_identifier()?];
        while self.consume_token(|token| matches!(token, Token::Period)) {
            if parts.len() >= max_parts {
                return Err(self.error(
                    format!("External object names may have at most {max_parts} parts"),
                    ParseErrorKind::UnsupportedFeature,
                ));
            }
            parts.push(self.parse_identifier()?);
        }
        Ok(parts)
    }

    fn parse_identifier(&mut self) -> Result<String, ParseError> {
        let Some(token) = self.peek() else {
            return Err(self.error(
                "Expected external file format name",
                ParseErrorKind::SyntaxError,
            ));
        };
        let Token::Word(word) = &token.token else {
            return Err(self.error_at(
                Some(token),
                "Expected an identifier for external file format name",
                ParseErrorKind::SyntaxError,
            ));
        };
        if word.value.is_empty() || word.value.starts_with('@') {
            return Err(self.error_at(
                Some(token),
                format!(
                    "Expected an object identifier for external {} name",
                    self.object_name
                ),
                ParseErrorKind::SyntaxError,
            ));
        }
        if word.quote_style.is_none()
            && matches!(
                word.keyword,
                Keyword::SELECT
                    | Keyword::FROM
                    | Keyword::WHERE
                    | Keyword::WITH
                    | Keyword::AS
                    | Keyword::CREATE
                    | Keyword::ALTER
                    | Keyword::DROP
                    | Keyword::TABLE
                    | Keyword::INSERT
                    | Keyword::UPDATE
                    | Keyword::DELETE
                    | Keyword::JOIN
                    | Keyword::ON
                    | Keyword::GROUP
                    | Keyword::ORDER
                    | Keyword::BY
                    | Keyword::INTO
                    | Keyword::VALUES
                    | Keyword::UNION
            )
        {
            return Err(self.error_at(
                Some(token),
                format!(
                    "Expected an unreserved or delimited external {} name",
                    self.object_name
                ),
                ParseErrorKind::SyntaxError,
            ));
        }
        let name = word.value.clone();
        self.position += 1;
        Ok(name)
    }

    fn parse_format_type(&mut self) -> Result<ExternalFileFormatType, ParseError> {
        let Some(token) = self.peek() else {
            return Err(self.error("Expected FORMAT_TYPE value", ParseErrorKind::SyntaxError));
        };
        let Token::Word(word) = &token.token else {
            return Err(self.error_at(
                Some(token),
                "Expected DELIMITEDTEXT, PARQUET, or DELTA as FORMAT_TYPE",
                ParseErrorKind::SyntaxError,
            ));
        };
        if word.quote_style.is_some() {
            return Err(self.error_at(
                Some(token),
                "FORMAT_TYPE must be an unquoted DELIMITEDTEXT, PARQUET, or DELTA value",
                ParseErrorKind::SyntaxError,
            ));
        }
        let format = match word.value.to_ascii_uppercase().as_str() {
            "DELIMITEDTEXT" => ExternalFileFormatType::DelimitedText,
            "PARQUET" => ExternalFileFormatType::Parquet,
            "DELTA" => ExternalFileFormatType::Delta,
            unsupported => {
                return Err(self.error_at(
                    Some(token),
                    format!("Unsupported external file FORMAT_TYPE '{unsupported}'"),
                    ParseErrorKind::UnsupportedFeature,
                ));
            }
        };
        self.position += 1;
        Ok(format)
    }

    fn parse_format_options(&mut self) -> Result<Vec<DelimitedTextFormatOption>, ParseError> {
        self.expect_token(
            |token| matches!(token, Token::LParen),
            "opening parenthesis after FORMAT_OPTIONS",
        )?;

        let mut options = Vec::new();
        let mut seen = HashSet::new();
        loop {
            let (key, option, key_token) = self.parse_delimited_text_option()?;
            if !seen.insert(key.clone()) {
                return Err(self.error_at(
                    Some(key_token),
                    format!("Duplicate external file format option '{key}'"),
                    ParseErrorKind::SyntaxError,
                ));
            }
            options.push(option);

            if self.consume_token(|token| matches!(token, Token::Comma)) {
                continue;
            }
            self.expect_token(
                |token| matches!(token, Token::RParen),
                "closing parenthesis after FORMAT_OPTIONS",
            )?;
            return Ok(options);
        }
    }

    fn parse_delimited_text_option(
        &mut self,
    ) -> Result<(String, DelimitedTextFormatOption, &'a TokenWithSpan), ParseError> {
        let Some(key_token) = self.peek() else {
            return Err(self.error(
                "Expected DELIMITEDTEXT format option",
                ParseErrorKind::SyntaxError,
            ));
        };
        let Token::Word(key_word) = &key_token.token else {
            return Err(self.error_at(
                Some(key_token),
                "Expected DELIMITEDTEXT format option name",
                ParseErrorKind::SyntaxError,
            ));
        };
        if key_word.quote_style.is_some() {
            return Err(self.error_at(
                Some(key_token),
                "Format option names must be unquoted identifiers",
                ParseErrorKind::SyntaxError,
            ));
        }

        let key = key_word.value.to_ascii_uppercase();
        self.position += 1;
        self.expect_token(
            |token| matches!(token, Token::Eq),
            "equals sign after DELIMITEDTEXT format option",
        )?;

        let option = match key.as_str() {
            "FIELD_TERMINATOR" => {
                let (value, value_token) = self.parse_string_value_with_token(&key)?;
                if value.is_empty() {
                    return Err(self.error_at(
                        Some(value_token),
                        "FIELD_TERMINATOR must not be empty",
                        ParseErrorKind::SyntaxError,
                    ));
                }
                DelimitedTextFormatOption::FieldTerminator(value)
            }
            "STRING_DELIMITER" => {
                DelimitedTextFormatOption::StringDelimiter(self.parse_string_value(&key)?)
            }
            "FIRST_ROW" => DelimitedTextFormatOption::FirstRow(self.parse_first_row()?),
            "DATE_FORMAT" => DelimitedTextFormatOption::DateFormat(self.parse_string_value(&key)?),
            "USE_TYPE_DEFAULT" => {
                DelimitedTextFormatOption::UseTypeDefault(self.parse_boolean_value(&key)?)
            }
            "ENCODING" => {
                let (value, value_token) = self.parse_string_value_with_token(&key)?;
                match value.to_ascii_uppercase().as_str() {
                    "UTF8" => DelimitedTextFormatOption::Encoding(DelimitedTextEncoding::Utf8),
                    "UTF16" => DelimitedTextFormatOption::Encoding(DelimitedTextEncoding::Utf16),
                    _ => {
                        return Err(self.error_at(
                            Some(value_token),
                            "ENCODING must be 'UTF8' or 'UTF16'",
                            ParseErrorKind::UnsupportedFeature,
                        ));
                    }
                }
            }
            _ => {
                return Err(self.error_at(
                    Some(key_token),
                    format!("Unsupported DELIMITEDTEXT format option '{key}'"),
                    ParseErrorKind::UnsupportedFeature,
                ));
            }
        };

        Ok((key, option, key_token))
    }

    fn parse_first_row(&mut self) -> Result<u8, ParseError> {
        let Some(token) = self.peek() else {
            return Err(self.error(
                "Expected integer FIRST_ROW value",
                ParseErrorKind::SyntaxError,
            ));
        };
        let Token::Number(value, _) = &token.token else {
            return Err(self.error_at(
                Some(token),
                "FIRST_ROW must be an integer from 1 through 15",
                ParseErrorKind::SyntaxError,
            ));
        };
        let row = value
            .parse::<u8>()
            .ok()
            .filter(|row| (1..=15).contains(row));
        let Some(row) = row else {
            return Err(self.error_at(
                Some(token),
                "FIRST_ROW must be an integer from 1 through 15",
                ParseErrorKind::SyntaxError,
            ));
        };
        self.position += 1;
        Ok(row)
    }

    fn parse_boolean_value(&mut self, option: &str) -> Result<bool, ParseError> {
        let Some(token) = self.peek() else {
            return Err(self.error(
                format!("Expected TRUE or FALSE for {option}"),
                ParseErrorKind::SyntaxError,
            ));
        };
        let Token::Word(word) = &token.token else {
            return Err(self.error_at(
                Some(token),
                format!("{option} must be TRUE or FALSE"),
                ParseErrorKind::SyntaxError,
            ));
        };
        if word.quote_style.is_some() {
            return Err(self.error_at(
                Some(token),
                format!("{option} must be an unquoted TRUE or FALSE"),
                ParseErrorKind::SyntaxError,
            ));
        }
        let value = if word.value.eq_ignore_ascii_case("TRUE") {
            true
        } else if word.value.eq_ignore_ascii_case("FALSE") {
            false
        } else {
            return Err(self.error_at(
                Some(token),
                format!("{option} must be TRUE or FALSE"),
                ParseErrorKind::SyntaxError,
            ));
        };
        self.position += 1;
        Ok(value)
    }

    fn parse_string_value(&mut self, option: &str) -> Result<String, ParseError> {
        self.parse_string_value_with_token(option)
            .map(|(value, _)| value)
    }

    fn parse_string_value_with_token(
        &mut self,
        option: &str,
    ) -> Result<(String, &'a TokenWithSpan), ParseError> {
        let Some(token) = self.peek() else {
            return Err(self.error(
                format!("Expected string value for {option}"),
                ParseErrorKind::SyntaxError,
            ));
        };
        let value = match &token.token {
            Token::SingleQuotedString(value) | Token::NationalStringLiteral(value) => value.clone(),
            _ => {
                return Err(self.error_at(
                    Some(token),
                    format!("{option} must be a string literal"),
                    ParseErrorKind::SyntaxError,
                ));
            }
        };
        self.position += 1;
        Ok((value, token))
    }

    fn parse_data_compression(
        &mut self,
        format: ExternalFileFormatType,
    ) -> Result<ExternalDataCompression, ParseError> {
        self.expect_keyword("DATA_COMPRESSION")?;
        self.expect_token(
            |token| matches!(token, Token::Eq),
            "'=' after DATA_COMPRESSION",
        )?;
        let (value, value_token) = self.parse_string_value_with_token("DATA_COMPRESSION")?;
        let compression = match (format, value.as_str()) {
            (ExternalFileFormatType::DelimitedText, "org.apache.hadoop.io.compress.GzipCodec")
            | (ExternalFileFormatType::Parquet, "org.apache.hadoop.io.compress.GzipCodec") => {
                ExternalDataCompression::Gzip
            }
            (ExternalFileFormatType::Parquet, "org.apache.hadoop.io.compress.SnappyCodec") => {
                ExternalDataCompression::Snappy
            }
            _ => {
                return Err(self.error_at(
                    Some(value_token),
                    format!(
                        "Unsupported DATA_COMPRESSION value '{value}' for {format:?} external file format"
                    ),
                    ParseErrorKind::UnsupportedFeature,
                ));
            }
        };
        Ok(compression)
    }

    fn expect_keyword(&mut self, expected: &str) -> Result<(), ParseError> {
        if self.consume_keyword(expected) {
            Ok(())
        } else {
            Err(self.error(
                format!("Expected {expected} in {}", self.statement_name),
                ParseErrorKind::SyntaxError,
            ))
        }
    }

    fn consume_keyword(&mut self, expected: &str) -> bool {
        if self
            .peek()
            .is_some_and(|token| is_keyword(&token.token, expected))
        {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect_token(
        &mut self,
        predicate: impl FnOnce(&Token) -> bool,
        expected: &str,
    ) -> Result<(), ParseError> {
        if self.consume_token(predicate) {
            Ok(())
        } else {
            Err(self.error(
                format!("Expected {expected} in {}", self.statement_name),
                ParseErrorKind::SyntaxError,
            ))
        }
    }

    fn expect_equals(&mut self, context: &str) -> Result<(), ParseError> {
        self.expect_token(
            |token| matches!(token, Token::Eq),
            &format!("'=' {context}"),
        )
    }

    fn expect_comma(&mut self, context: &str) -> Result<(), ParseError> {
        self.expect_token(
            |token| matches!(token, Token::Comma),
            &format!("',' {context}"),
        )
    }

    fn consume_token(&mut self, predicate: impl FnOnce(&Token) -> bool) -> bool {
        if self.peek().is_some_and(|token| predicate(&token.token)) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<&'a TokenWithSpan> {
        self.tokens.get(self.position).copied()
    }

    fn error(&self, message: impl Into<String>, kind: ParseErrorKind) -> ParseError {
        self.error_at(self.peek(), message, kind)
    }

    fn error_at(
        &self,
        token: Option<&TokenWithSpan>,
        message: impl Into<String>,
        kind: ParseErrorKind,
    ) -> ParseError {
        let message = message.into();
        let mut error = if let Some(token) = token {
            ParseError::with_position(
                message,
                usize::try_from(token.span.start.line).unwrap_or(1),
                usize::try_from(token.span.start.column).unwrap_or(1),
            )
        } else {
            ParseError::new(message)
        };
        error.dialect = Some(Dialect::Mssql);
        error.kind = if token.is_none() {
            ParseErrorKind::UnexpectedEof
        } else {
            kind
        };
        error
    }
}

fn is_keyword(token: &Token, keyword: &str) -> bool {
    matches!(
        token,
        Token::Word(word)
            if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(keyword)
    )
}

fn is_object_id_string_literal(token: &Token) -> bool {
    matches!(
        token,
        Token::SingleQuotedString(_) | Token::NationalStringLiteral(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn parse_format(sql: &str) -> Result<Option<ExternalMetadataStatement>, ParseError> {
        parse_external_metadata_statement(sql)
    }

    fn file_format(sql: &str) -> ExternalFileFormatDefinition {
        match parse_format(sql)
            .expect("parse")
            .expect("external metadata")
        {
            ExternalMetadataStatement::FileFormat(definition) => definition,
            ExternalMetadataStatement::ConditionalFileFormat(_)
            | ExternalMetadataStatement::ExternalTable(_)
            | ExternalMetadataStatement::Cetas(_) => {
                panic!("expected file format metadata")
            }
        }
    }

    #[test]
    fn parses_delimited_text_options_and_gzip_compression() {
        let format = file_format(
            "CREATE EXTERNAL FILE FORMAT csv_format WITH (\
                FORMAT_TYPE = DELIMITEDTEXT,\
                FORMAT_OPTIONS (FIELD_TERMINATOR = ',', STRING_DELIMITER = '\"', \
                    FIRST_ROW = 2, USE_TYPE_DEFAULT = TRUE, ENCODING = 'UTF8', \
                    DATE_FORMAT = 'MM/dd/yyyy'),\
                DATA_COMPRESSION = 'org.apache.hadoop.io.compress.GzipCodec');",
        );

        assert_eq!(format.name, vec!["csv_format".to_string()]);
        assert_eq!(format.format, ExternalFileFormatType::DelimitedText);
        assert_eq!(
            format.format_options,
            vec![
                DelimitedTextFormatOption::FieldTerminator(",".to_string()),
                DelimitedTextFormatOption::StringDelimiter("\"".to_string()),
                DelimitedTextFormatOption::FirstRow(2),
                DelimitedTextFormatOption::UseTypeDefault(true),
                DelimitedTextFormatOption::Encoding(DelimitedTextEncoding::Utf8),
                DelimitedTextFormatOption::DateFormat("MM/dd/yyyy".to_string()),
            ]
        );
        assert_eq!(format.data_compression, Some(ExternalDataCompression::Gzip));
    }

    #[test]
    fn parses_parquet_without_inventing_relational_metadata() {
        let metadata = parse_format(
            "CREATE EXTERNAL FILE FORMAT [warehouse].[parquet_format] \
             WITH (FORMAT_TYPE = PARQUET, \
             DATA_COMPRESSION = 'org.apache.hadoop.io.compress.SnappyCodec')",
        )
        .expect("parse")
        .expect("external metadata");
        let ExternalMetadataStatement::FileFormat(format) = metadata else {
            panic!("expected file format metadata");
        };

        assert_eq!(
            format.name,
            vec!["warehouse".to_string(), "parquet_format".to_string()]
        );
        assert_eq!(format.format, ExternalFileFormatType::Parquet);
        assert!(format.format_options.is_empty());
        assert_eq!(
            format.data_compression,
            Some(ExternalDataCompression::Snappy)
        );
    }

    #[test]
    fn parses_delta_format_without_compression_or_delimited_options() {
        let format =
            file_format("CREATE EXTERNAL FILE FORMAT delta_format WITH (FORMAT_TYPE = DELTA)");

        assert_eq!(format.format, ExternalFileFormatType::Delta);
        assert!(format.format_options.is_empty());
        assert_eq!(format.data_compression, None);
    }

    #[test]
    fn ignores_comments_and_recognizes_the_metadata_statement() {
        let metadata = parse_format(
            "/* setup */ CREATE /* kind */ EXTERNAL FILE FORMAT [csv] \
             WITH (FORMAT_TYPE = DELIMITEDTEXT /* format */, \
             FORMAT_OPTIONS (FIELD_TERMINATOR = '~|~')) -- trailing comment",
        )
        .expect("parse")
        .expect("external metadata");
        let ExternalMetadataStatement::FileFormat(format) = metadata else {
            panic!("expected file format metadata");
        };
        assert_eq!(
            format.format_options,
            vec![DelimitedTextFormatOption::FieldTerminator(
                "~|~".to_string()
            )]
        );
    }

    #[test]
    fn metadata_classification_has_an_explicit_unsupported_lineage_warning() {
        let metadata =
            parse_format("CREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = DELIMITEDTEXT)")
                .expect("parse")
                .expect("external metadata");
        let issue = metadata.unsupported_lineage_warning();

        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.code, issue_codes::UNSUPPORTED_SYNTAX);
        assert!(issue
            .message
            .contains("external-file lineage is not modeled"));
        assert_eq!(metadata.statement_type(), "CREATE_EXTERNAL_FILE_FORMAT");
    }

    #[test]
    fn parses_documented_cetas_metadata_and_retains_query_range() {
        let sql = concat!(
            "CREATE EXTERNAL TABLE [analytics].[daily_rollup] WITH (",
            "LOCATION = 'output/daily/', ",
            "DATA_SOURCE = lake_source, ",
            "FILE_FORMAT = parquet_format",
            ") AS\r\n",
            "SELECT item_id FROM [analytics].[source_items]"
        );
        let metadata = parse_format(sql).expect("parse").expect("CETAS metadata");
        let ExternalMetadataStatement::Cetas(cetas) = &metadata else {
            panic!("expected CETAS metadata");
        };

        assert!(sql[cetas.query_range.clone()]
            .trim_start()
            .starts_with("SELECT"));
        assert_eq!(metadata.statement_type(), "CREATE_EXTERNAL_TABLE_AS_SELECT");
        let warning = metadata.unsupported_lineage_warning();
        assert_eq!(warning.severity, crate::types::Severity::Warning);
        assert_eq!(warning.code, issue_codes::UNSUPPORTED_SYNTAX);
        assert!(warning.message.contains("file-write lineage"));
    }

    #[test]
    fn parses_standard_external_table_metadata_without_inventing_lineage() {
        let sql = concat!(
            "/* café */ CREATE EXTERNAL TABLE dbo.demo_table /* columns */ ",
            "(id INT, label VARCHAR(20)) WITH (LOCATION = 'data/with spaces/', ",
            "DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet);"
        );
        let metadata = parse_format(sql)
            .expect("valid external table syntax")
            .expect("external table metadata");
        let ExternalMetadataStatement::ExternalTable(table) = &metadata else {
            panic!("expected external table metadata");
        };

        assert_eq!(
            table.name,
            vec!["dbo".to_string(), "demo_table".to_string()]
        );
        assert_eq!(metadata.statement_type(), "CREATE_EXTERNAL_TABLE");
        assert!(metadata
            .unsupported_lineage_warning()
            .message
            .contains("external-file lineage is not modeled"));
    }

    #[test]
    fn accepts_location_and_data_source_in_either_order_for_tables_and_guards() {
        let cases = [
            concat!(
                "CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
                "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
                "FILE_FORMAT = synthetic_format)"
            ),
            concat!(
                "/* café */ CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
                "(DATA_SOURCE = synthetic_store, /* option comment */ ",
                "LOCATION = N'demo/', FILE_FORMAT = synthetic_format)"
            ),
            concat!(
                "IF NOT EXISTS (SELECT 1 FROM sys.external_tables ",
                "WHERE name = 'synthetic_demo') ",
                "CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
                "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
                "FILE_FORMAT = synthetic_format);"
            ),
            concat!(
                "IF OBJECT_ID(N'dbo.synthetic_demo', N'U') IS NULL ",
                "CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
                "(DATA_SOURCE = synthetic_store, LOCATION = N'demo/', ",
                "FILE_FORMAT = synthetic_format);"
            ),
            concat!(
                "IF NOT EXISTS (SELECT 1 FROM sys.external_tables ",
                "WHERE name = 'synthetic_demo') BEGIN\r\n",
                "CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
                "(DATA_SOURCE = synthetic_store, LOCATION = N'demo/', ",
                "FILE_FORMAT = synthetic_format);\r\n",
                "END"
            ),
            concat!(
                "/* café */ IF OBJECT_ID('dbo.synthetic_demo') IS NULL BEGIN\n",
                "CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
                "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
                "FILE_FORMAT = synthetic_format);\n",
                "END"
            ),
        ];

        let expected_name = vec!["dbo".to_string(), "synthetic_demo".to_string()];
        for sql in cases {
            let metadata = parse_format(sql)
                .expect("valid external-table option order")
                .expect("external-table metadata");
            let ExternalMetadataStatement::ExternalTable(table) = metadata else {
                panic!("guarded external tables must reuse the existing metadata variant");
            };
            assert_eq!(table.name, expected_name);
        }
    }

    #[test]
    fn parses_guarded_external_file_format_without_skipping_the_if_query() {
        let sql = concat!(
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
            "WHERE name = 'demo_format') BEGIN ",
            "CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); ",
            "END"
        );
        let metadata = parse_format(sql)
            .expect("valid guarded metadata")
            .expect("conditional external file format");
        let ExternalMetadataStatement::ConditionalFileFormat(format) = &metadata else {
            panic!("expected guarded external file format");
        };

        assert_eq!(format.name, vec!["demo_format"]);
        assert_eq!(format.format, ExternalFileFormatType::Parquet);
        assert_eq!(metadata.statement_type(), "CREATE_EXTERNAL_FILE_FORMAT");
        assert!(metadata
            .unsupported_lineage_warning()
            .message
            .contains("external-file lineage is not modeled"));
    }

    #[test]
    fn parses_bare_and_block_guarded_external_tables_as_metadata_only() {
        let cases = [
            concat!(
                "/* café */ IF NOT EXISTS (SELECT 1 FROM sys.external_tables ",
                "WHERE name = 'synthetic_demo') ",
                "CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) ",
                "WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
                "FILE_FORMAT = synthetic_format);"
            ),
            concat!(
                "-- Unicode and CRLF source positions stay in the original SQL.\r\n",
                "IF NOT EXISTS (\r\n",
                "    SELECT 1 FROM sys.external_tables\r\n",
                "    WHERE name = 'synthetic_demo'\r\n",
                ") /* condition comment */ BEGIN\r\n",
                "    -- END in a comment is not the block terminator.\r\n",
                "    CREATE /* body comment */ EXTERNAL TABLE dbo.synthetic_demo ",
                "(id INT, label VARCHAR(20)) WITH (LOCATION = 'demo/BEGIN; END ELSE', ",
                "DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format);\r\n",
                "END; -- trailing comment"
            ),
        ];

        for sql in cases {
            let metadata = parse_format(sql)
                .expect("valid guarded external table")
                .expect("external table metadata");
            let ExternalMetadataStatement::ExternalTable(table) = &metadata else {
                panic!("guarded external table should reuse the external-table metadata variant");
            };

            assert_eq!(
                table.name,
                vec!["dbo".to_string(), "synthetic_demo".to_string()]
            );
            assert_eq!(metadata.statement_type(), "CREATE_EXTERNAL_TABLE");
            assert!(metadata
                .unsupported_lineage_warning()
                .message
                .contains("external-file lineage is not modeled"));
        }
    }

    #[test]
    fn parses_object_id_guarded_external_tables_and_file_formats() {
        let bare_table = concat!(
            "IF OBJECT_ID(N'dbo.synthetic_rows', N'U') IS NULL ",
            "CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
            "FILE_FORMAT = synthetic_format);"
        );
        let metadata = parse_format(bare_table)
            .expect("valid OBJECT_ID guarded table")
            .expect("external table metadata");
        let ExternalMetadataStatement::ExternalTable(table) = &metadata else {
            panic!("OBJECT_ID guarded table should use the existing table variant");
        };
        assert_eq!(
            table.name,
            vec!["dbo".to_string(), "synthetic_rows".to_string()]
        );
        assert_eq!(metadata.statement_type(), "CREATE_EXTERNAL_TABLE");

        let block_table = concat!(
            "/* café */ IF OBJECT_ID('dbo.synthetic_demo') IS NULL BEGIN\r\n",
            "  -- The END in this comment is not a terminator.\r\n",
            "  CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
            "(LOCATION = 'demo/END', DATA_SOURCE = synthetic_store, ",
            "FILE_FORMAT = synthetic_format);\r\n",
            "END"
        );
        assert!(matches!(
            parse_format(block_table)
                .expect("valid OBJECT_ID block guard")
                .expect("external table metadata"),
            ExternalMetadataStatement::ExternalTable(_)
        ));

        let file_format = concat!(
            "IF OBJECT_ID('synthetic_format') IS NULL BEGIN ",
            "CREATE EXTERNAL FILE FORMAT synthetic_format WITH (FORMAT_TYPE = PARQUET); ",
            "END"
        );
        let metadata = parse_format(file_format)
            .expect("valid OBJECT_ID guarded file format")
            .expect("file format metadata");
        let ExternalMetadataStatement::ConditionalFileFormat(format) = metadata else {
            panic!("OBJECT_ID guarded file format should retain its conditional variant");
        };
        assert_eq!(format.name, vec!["synthetic_format"]);
        assert_eq!(format.format, ExternalFileFormatType::Parquet);
    }

    #[test]
    fn parses_measured_synthetic_object_id_guard_and_unguarded_control() {
        let guarded = concat!(
            "IF OBJECT_ID(N'dbo.synthetic_ext', N'U') IS NULL\n",
            "BEGIN\n",
            "    CREATE EXTERNAL TABLE dbo.synthetic_ext (\n",
            "        id INT\n",
            "    )\n",
            "    WITH (\n",
            "        LOCATION = 'synthetic/path/',\n",
            "        DATA_SOURCE = synthetic_source,\n",
            "        FILE_FORMAT = synthetic_format\n",
            "    );\n",
            "END;"
        );
        let bare_guarded = concat!(
            "IF OBJECT_ID(N'dbo.synthetic_ext', N'U') IS NULL\n",
            "    CREATE EXTERNAL TABLE dbo.synthetic_ext (\n",
            "        id INT\n",
            "    )\n",
            "    WITH (\n",
            "        LOCATION = 'synthetic/path/',\n",
            "        DATA_SOURCE = synthetic_source,\n",
            "        FILE_FORMAT = synthetic_format\n",
            "    );"
        );
        let unguarded = concat!(
            "CREATE EXTERNAL TABLE dbo.synthetic_ext (\n",
            "    id INT\n",
            ")\n",
            "WITH (\n",
            "    LOCATION = 'synthetic/path/',\n",
            "    DATA_SOURCE = synthetic_source,\n",
            "    FILE_FORMAT = synthetic_format\n",
            ");"
        );

        let guarded_metadata = parse_format(guarded)
            .expect("valid measured-shape guard")
            .expect("guarded external-table metadata");
        let bare_metadata = parse_format(bare_guarded)
            .expect("valid unbraced measured-shape guard")
            .expect("guarded external-table metadata");
        let unguarded_metadata = parse_format(unguarded)
            .expect("valid unguarded control")
            .expect("external-table metadata");
        assert_eq!(
            guarded_metadata, unguarded_metadata,
            "the IF OBJECT_ID wrapper must preserve typed external-table metadata"
        );
        assert_eq!(
            bare_metadata, unguarded_metadata,
            "the unbraced IF OBJECT_ID wrapper must preserve typed external-table metadata"
        );
        assert_eq!(guarded_metadata.statement_type(), "CREATE_EXTERNAL_TABLE");
    }

    #[test]
    fn object_id_guarded_external_table_analysis_has_no_fake_lineage() {
        let sql = concat!(
            "IF OBJECT_ID(N'dbo.synthetic_rows', N'U') IS NULL ",
            "CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
            "FILE_FORMAT = synthetic_format)"
        );
        let request = crate::types::AnalyzeRequest {
            sql: sql.to_string(),
            files: None,
            dialect: Dialect::Mssql,
            source_name: Some("object-id-external-table.sql".to_string()),
            options: None,
            schema: None,
            #[cfg(feature = "templating")]
            template_config: None,
        };

        let result = super::super::analyze(&request);

        assert_eq!(result.statements.len(), 1);
        assert_eq!(result.statements[0].statement_type, "CREATE_EXTERNAL_TABLE");
        assert!(result.nodes.is_empty());
        assert!(result.edges.is_empty());
        let warning = result
            .issues
            .iter()
            .find(|issue| issue.code == issue_codes::UNSUPPORTED_SYNTAX)
            .expect("unsupported-lineage warning");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.message, EXTERNAL_TABLE_UNSUPPORTED_LINEAGE_MESSAGE);
        assert_eq!(
            warning.source_name.as_deref(),
            Some("object-id-external-table.sql")
        );
        assert!(!result
            .issues
            .iter()
            .any(|issue| issue.code == issue_codes::PARSE_ERROR));
    }

    #[test]
    fn rejects_unsupported_or_malformed_object_id_guard_shapes() {
        let empty_arguments =
            "IF OBJECT_ID() IS NULL CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)";
        let error = parse_format(empty_arguments).expect_err("missing object name must fail");
        assert_eq!(error.kind, ParseErrorKind::SyntaxError);

        for sql in [
            "IF OBJECT_ID(@object_name) IS NULL CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
            "IF OBJECT_ID('dbo.demo', 'U', 'extra') IS NULL CREATE EXTERNAL TABLE dbo.demo \
             (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
            "IF OBJECT_ID('dbo.demo') CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
            "IF OBJECT_ID('dbo.demo') IS NOT NULL CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
            "IF OBJECT_ID('dbo.demo') IS NULL BEGIN CREATE EXTERNAL TABLE dbo.demo WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format) AS SELECT 1; END",
            "IF OBJECT_ID('dbo.demo') IS NULL BEGIN CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format); SELECT 1; END",
            "IF OBJECT_ID('dbo.demo') IS NULL BEGIN CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format); END ELSE SELECT 1",
            "IF OBJECT_ID('dbo.demo') IS NULL CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format) ELSE SELECT 1",
            "IF OBJECT_ID('outer') IS NULL BEGIN IF OBJECT_ID('inner') IS NULL CREATE EXTERNAL \
             TABLE dbo.demo (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = source, \
             FILE_FORMAT = format); END",
        ] {
            let error = parse_format(sql)
                .expect_err("unsupported or malformed OBJECT_ID guard must be rejected");
            assert_eq!(error.dialect, Some(Dialect::Mssql), "{sql}");
        }

        let not_null = parse_format(
            "IF OBJECT_ID('dbo.demo') IS NOT NULL CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
        )
        .expect_err("IS NOT NULL must be explicitly unsupported");
        assert_eq!(not_null.kind, ParseErrorKind::UnsupportedFeature);

        assert_eq!(
            parse_format("IF 1 = 1 BEGIN PRINT 'CREATE EXTERNAL TABLE'; END")
                .expect("general IF control should remain outside metadata parsing"),
            None
        );
        assert_eq!(
            parse_format(
                "IF 1 = 1 BEGIN CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
                 (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format); END"
            )
            .expect("general IF controls should remain outside metadata parsing"),
            None
        );
        assert_eq!(
            parse_format("IF OBJECT_ID(N'dbo.synthetic_ext', N'U') IS NULL SELECT 1").expect(
                "OBJECT_ID controls with a non-metadata body should remain outside parsing"
            ),
            None
        );
    }

    #[test]
    fn object_id_guard_diagnostics_map_to_original_condition_and_body() {
        let malformed_condition = concat!(
            "/* café */ IF OBJECT_ID(1) IS NULL CREATE EXTERNAL TABLE dbo.demo (id INT) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)"
        );
        let error = parse_format(malformed_condition)
            .expect_err("nonliteral OBJECT_ID argument must be rejected");
        assert_eq!(error.dialect, Some(Dialect::Mssql));
        let error_position = error.position.expect("OBJECT_ID argument position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_condition,
            error_position.line,
            error_position.column,
        )
        .expect("mapped OBJECT_ID argument offset");
        assert!(
            error_offset >= malformed_condition.find("(1)").expect("argument")
                && error_offset < malformed_condition.find(" IS NULL").expect("null test"),
            "condition diagnostics must point into the original OBJECT_ID argument"
        );

        let malformed_syntax = concat!(
            "/* café */ IF OBJECT_ID('dbo.demo',) IS NULL ",
            "CREATE EXTERNAL TABLE dbo.demo (id INT) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)"
        );
        let error = parse_format(malformed_syntax)
            .expect_err("malformed OBJECT_ID argument syntax must fail");
        let error_position = error.position.expect("malformed condition position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_syntax,
            error_position.line,
            error_position.column,
        )
        .expect("mapped malformed condition offset");
        assert!(
            error_offset >= malformed_syntax.find("OBJECT_ID").expect("condition")
                && error_offset < malformed_syntax.find(" IS NULL").expect("null test"),
            "parser errors from the wrapped condition must map to the original condition"
        );

        let malformed_body = concat!(
            "/* café */ IF OBJECT_ID('dbo.demo') IS NULL BEGIN\r\n",
            "CREATE EXTERNAL TABLE dbo.demo (id INT, label) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format);\r\n",
            "END"
        );
        let error =
            parse_format(malformed_body).expect_err("malformed guarded table columns must fail");
        let error_position = error.position.expect("body error position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_body,
            error_position.line,
            error_position.column,
        )
        .expect("mapped guarded table column offset");
        assert!(
            error_offset >= malformed_body.find("label").expect("bad column")
                && error_offset < malformed_body.find("WITH").expect("table options"),
            "body diagnostics must point into the original guarded statement"
        );
    }

    #[test]
    fn guarded_external_table_analysis_reports_metadata_without_fabricating_lineage() {
        let sql = concat!(
            "/* café */ IF NOT EXISTS (SELECT 1 FROM sys.external_tables ",
            "WHERE name = 'synthetic_demo') BEGIN\n",
            "CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
            "FILE_FORMAT = synthetic_format);\n",
            "END"
        );
        let request = crate::types::AnalyzeRequest {
            sql: sql.to_string(),
            files: None,
            dialect: Dialect::Mssql,
            source_name: Some("guarded-external-table.sql".to_string()),
            options: None,
            schema: None,
            #[cfg(feature = "templating")]
            template_config: None,
        };

        let result = super::super::analyze(&request);

        assert_eq!(result.statements.len(), 1);
        assert_eq!(result.statements[0].statement_type, "CREATE_EXTERNAL_TABLE");
        assert!(result.nodes.is_empty());
        assert!(result.edges.is_empty());
        let warning = result
            .issues
            .iter()
            .find(|issue| issue.code == issue_codes::UNSUPPORTED_SYNTAX)
            .expect("unsupported-lineage warning");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.message, EXTERNAL_TABLE_UNSUPPORTED_LINEAGE_MESSAGE);
        assert_eq!(
            warning.source_name.as_deref(),
            Some("guarded-external-table.sql")
        );
        assert!(!result
            .issues
            .iter()
            .any(|issue| issue.code == issue_codes::PARSE_ERROR));
    }

    #[test]
    fn parses_single_statement_guarded_file_formats_with_or_without_semicolons() {
        let cases = [
            (
                concat!(
                    "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
                    "WHERE name = 'demo_parquet') CREATE EXTERNAL FILE FORMAT ",
                    "demo_parquet WITH (FORMAT_TYPE = PARQUET)"
                ),
                ExternalFileFormatType::Parquet,
                0,
            ),
            (
                concat!(
                    "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
                    "WHERE name = 'demo_text') CREATE EXTERNAL FILE FORMAT ",
                    "demo_text WITH (FORMAT_TYPE = DELIMITEDTEXT, ",
                    "FORMAT_OPTIONS (FIELD_TERMINATOR = ','));"
                ),
                ExternalFileFormatType::DelimitedText,
                1,
            ),
        ];

        for (sql, expected_format, expected_options) in cases {
            let metadata = parse_format(sql)
                .expect("valid single-statement guarded metadata")
                .expect("guarded external file format");
            let ExternalMetadataStatement::ConditionalFileFormat(format) = metadata else {
                panic!("expected guarded external file format");
            };
            assert_eq!(format.format, expected_format);
            assert_eq!(format.format_options.len(), expected_options);
        }
    }

    #[test]
    fn rejects_invalid_guarded_external_table_conditions_bodies_and_blocks() {
        for sql in [
            "IF EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
            "IF NOT EXISTS (SELECT FROM sys.external_tables WHERE name = 'demo') \
             CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             CREATE EXTERNAL TABLE dbo.demo (id INT, label) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format)",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             BEGIN CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format);",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             BEGIN CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format); END \
             ELSE SELECT 1",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format) ELSE SELECT 1",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'outer') \
             BEGIN IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'inner') \
             CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format); END",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             BEGIN CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format); \
             SELECT 1; END",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             BEGIN CREATE EXTERNAL TABLE dbo.demo (id INT) WITH \
             (LOCATION = 'demo/', DATA_SOURCE = source, FILE_FORMAT = format); END \
             SELECT 1",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_tables WHERE name = 'demo') \
             CREATE EXTERNAL TABLE dbo.demo WITH (LOCATION = 'demo/', \
             DATA_SOURCE = source, FILE_FORMAT = format) AS SELECT 1",
        ] {
            assert!(
                parse_format(sql).is_err(),
                "invalid or unsupported guarded external-table syntax must be rejected: {sql}"
            );
        }
    }

    #[test]
    fn guarded_external_table_errors_keep_original_condition_and_body_positions() {
        let malformed_body = concat!(
            "/* café */ IF NOT EXISTS (\r\n",
            "  SELECT 1 FROM sys.external_tables WHERE name = 'synthetic_demo'\r\n",
            ") BEGIN\r\n",
            "  CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT, label) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
            "FILE_FORMAT = synthetic_format);\r\n",
            "END"
        );
        let error = parse_format(malformed_body).expect_err("malformed guarded columns must fail");
        assert_eq!(error.dialect, Some(Dialect::Mssql));
        let error_position = error.position.expect("body error position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_body,
            error_position.line,
            error_position.column,
        )
        .expect("mapped body error offset");
        assert!(
            error_offset >= malformed_body.find("label").expect("malformed column")
                && error_offset < malformed_body.find("WITH").expect("table options"),
            "column diagnostics must point into the original guarded body, not its adapted SQL"
        );

        let malformed_condition = concat!(
            "/* café */ IF NOT EXISTS (\n",
            "  SELECT FROM sys.external_tables WHERE name = 'synthetic_demo'\n",
            ") CREATE EXTERNAL TABLE dbo.synthetic_demo (id INT) WITH ",
            "(LOCATION = 'demo/', DATA_SOURCE = synthetic_store, ",
            "FILE_FORMAT = synthetic_format)"
        );
        let error = parse_format(malformed_condition).expect_err("malformed guard query must fail");
        assert_eq!(error.dialect, Some(Dialect::Mssql));
        let error_position = error.position.expect("condition error position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_condition,
            error_position.line,
            error_position.column,
        )
        .expect("mapped condition error offset");
        assert!(
            error_offset
                >= malformed_condition
                    .find("SELECT FROM")
                    .expect("invalid SELECT"),
            "condition diagnostics must point to the original IF query"
        );
    }

    #[test]
    fn rejects_malformed_external_table_definitions() {
        let malformed_columns =
            "/* café */ CREATE EXTERNAL TABLE dbo.demo_table (id INT, label) WITH \
             (LOCATION = 'data/', DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet)";
        let error = parse_format(malformed_columns)
            .expect_err("malformed external table columns must be rejected");
        let error_position = error.position.expect("column error position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_columns,
            error_position.line,
            error_position.column,
        )
        .expect("mapped column error offset");
        assert!(
            error_offset >= malformed_columns.find("label").expect("bad column"),
            "generated CREATE TABLE parser coordinates must map into original columns"
        );

        for sql in [
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT NOT NULL) WITH \
             (LOCATION = 'data/', DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (LOCATION = '', DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (LOCATION = 'data/', LOCATION = 'other/', DATA_SOURCE = demo_storage, \
             FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (DATA_SOURCE = demo_storage, DATA_SOURCE = other_store, LOCATION = 'data/', \
             FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (LOCATION = 'data/', FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (DATA SOURCE = demo_storage, LOCATION = 'data/', FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (DATA_SOURCE = schema.demo_storage, LOCATION = 'data/', \
             FILE_FORMAT = demo_parquet)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (LOCATION = 'data/', DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet, \
             UNKNOWN = 1)",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH \
             (LOCATION = 'data/', DATA_SOURCE = demo_storage, FILE_FORMAT = demo_parquet) AS SELECT 1",
        ] {
            assert!(
                parse_format(sql).is_err(),
                "invalid external table syntax must remain an error: {sql}"
            );
        }

        let duplicate_option = concat!(
            "/* café */ IF OBJECT_ID(N'dbo.demo_table', N'U') IS NULL BEGIN\n",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT) WITH ",
            "(DATA_SOURCE = demo_storage, LOCATION = N'data/', LOCATION = N'other/', ",
            "FILE_FORMAT = demo_parquet);\n",
            "END"
        );
        let error = parse_format(duplicate_option).expect_err("duplicate option must fail");
        let error_position = error.position.expect("duplicate option position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            duplicate_option,
            error_position.line,
            error_position.column,
        )
        .expect("mapped duplicate option offset");
        assert_eq!(
            error_offset,
            duplicate_option.rfind("LOCATION").expect("second LOCATION"),
            "guarded option errors must point to the original duplicate key"
        );
    }

    #[test]
    fn rejects_malformed_guarded_external_file_format_queries_and_blocks() {
        for sql in [
            "IF NOT EXISTS (SELECT FROM sys.external_file_formats WHERE name = 'demo_format') \
             BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); END",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET, UNKNOWN = 1)",
            "IF EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); END",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET);",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); END \
             ELSE SELECT 1",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET) ELSE SELECT 1",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); ELSE SELECT 1",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = CSV)",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); SELECT 1",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = CSV); END",
            "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             BEGIN CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); END SELECT 1",
        ] {
            assert!(
                parse_format(sql).is_err(),
                "malformed guarded DDL must remain an error: {sql}"
            );
        }

        let invalid_if_exists = parse_format(
            "IF EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'demo_format') \
             CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET)",
        )
        .expect_err("file formats retain the IF NOT EXISTS guard requirement");
        assert_eq!(invalid_if_exists.kind, ParseErrorKind::SyntaxError);

        let malformed_body = concat!(
            "/* café */ IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
            "WHERE name = 'demo_format') CREATE EXTERNAL FILE FORMAT demo_format ",
            "WITH (FORMAT_TYPE = CSV)"
        );
        let error = parse_format(malformed_body).expect_err("malformed body must fail parsing");
        let error_position = error.position.expect("body error position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_body,
            error_position.line,
            error_position.column,
        )
        .expect("body error offset");
        assert!(
            error_offset >= malformed_body.find("FORMAT_TYPE").expect("body option"),
            "body error coordinates must map to the original conditional"
        );

        let malformed_query = concat!(
            "/* café */ IF NOT EXISTS (SELECT FROM sys.external_file_formats ",
            "WHERE name = 'demo_format') BEGIN ",
            "CREATE EXTERNAL FILE FORMAT demo_format WITH (FORMAT_TYPE = PARQUET); END"
        );
        let error =
            parse_format(malformed_query).expect_err("malformed condition must fail parsing");
        let error_position = error.position.expect("condition error position");
        let error_offset = crate::analyzer::helpers::line_col_to_offset(
            malformed_query,
            error_position.line,
            error_position.column,
        )
        .expect("condition error offset");
        assert!(
            error_offset >= malformed_query.find("SELECT FROM").expect("invalid SELECT"),
            "condition error coordinates must map to the original conditional"
        );
    }

    #[test]
    fn external_table_analysis_reports_metadata_without_fabricating_lineage() {
        let sql = concat!(
            "-- café\n",
            "CREATE EXTERNAL TABLE dbo.demo_table (id INT, label VARCHAR(20)) ",
            "WITH (LOCATION = 'data/', DATA_SOURCE = demo_storage, ",
            "FILE_FORMAT = demo_parquet)"
        );
        let request = crate::types::AnalyzeRequest {
            sql: sql.to_string(),
            files: None,
            dialect: Dialect::Mssql,
            source_name: Some("external-table.sql".to_string()),
            options: None,
            schema: None,
            #[cfg(feature = "templating")]
            template_config: None,
        };

        let result = super::super::analyze(&request);
        let statement_start = sql.find("CREATE EXTERNAL TABLE").expect("statement start");
        assert_eq!(result.statements.len(), 1);
        assert_eq!(result.statements[0].statement_type, "CREATE_EXTERNAL_TABLE");
        assert_eq!(
            result.statements[0].span,
            Some(crate::types::Span::new(statement_start, sql.len()))
        );
        assert!(result.nodes.is_empty());
        assert!(result.edges.is_empty());
        let warning = result
            .issues
            .iter()
            .find(|issue| issue.code == issue_codes::UNSUPPORTED_SYNTAX)
            .expect("explicit unsupported-lineage warning");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.message, EXTERNAL_TABLE_UNSUPPORTED_LINEAGE_MESSAGE);
        assert_eq!(
            warning.span,
            Some(crate::types::Span::new(statement_start, sql.len()))
        );
        assert!(!result
            .issues
            .iter()
            .any(|issue| issue.code == issue_codes::PARSE_ERROR));
    }

    #[test]
    fn guarded_ddl_ignores_comment_and_string_keyword_text() {
        let sql = concat!(
            "/* setup */ IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats ",
            "WHERE name = 'demo format; END') /* condition */ BEGIN ",
            "CREATE /* metadata */ EXTERNAL FILE FORMAT demo_format WITH ",
            "(FORMAT_TYPE = PARQUET); -- END CREATE EXTERNAL FILE FORMAT\n",
            "END -- trailing comment"
        );
        assert!(matches!(
            parse_format(sql).expect("valid guarded syntax"),
            Some(ExternalMetadataStatement::ConditionalFileFormat(_))
        ));
    }

    #[test]
    fn parses_cetas_name_only_output_columns_with_comments_and_quoted_names() {
        let sql = concat!(
            "CREATE EXTERNAL TABLE [analytics].[daily_rollup] /* target */ ",
            "([SELECT] /* between names */, [output label], source_id) /* options */ ",
            "WITH (LOCATION = 'output/daily/', DATA_SOURCE = lake_source, ",
            "FILE_FORMAT = parquet_format) AS SELECT 1"
        );

        let metadata = parse_format(sql)
            .expect("valid CETAS output-column list")
            .expect("CETAS metadata");
        let ExternalMetadataStatement::Cetas(cetas) = metadata else {
            panic!("expected CETAS metadata");
        };
        assert_eq!(
            sql[cetas.query_range].trim_start(),
            "SELECT 1",
            "the query source range must start after the optional output-column list"
        );
    }

    #[test]
    fn rejects_malformed_cetas_output_column_lists_at_the_original_token() {
        for columns in [
            "()",
            "(id,)",
            "(, id)",
            "('id')",
            "(1)",
            "(id.name)",
            "(id INT)",
        ] {
            let sql = format!(
                "CREATE EXTERNAL TABLE target {columns} WITH \
                 (LOCATION = 'out/', DATA_SOURCE = source, FILE_FORMAT = format) AS SELECT 1"
            );
            let error = parse_format(&sql)
                .expect_err("invalid CETAS output-column syntax must be rejected");
            assert_eq!(error.dialect, Some(Dialect::Mssql), "{columns}");
            assert!(
                error.position.is_some(),
                "malformed output columns should retain a source position: {columns}"
            );
        }
    }

    #[test]
    fn analysis_reports_metadata_without_fabricating_lineage_or_schema() {
        let sql = "CREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = DELIMITEDTEXT)";
        let request = crate::types::AnalyzeRequest {
            sql: sql.to_string(),
            files: None,
            dialect: Dialect::Mssql,
            source_name: Some("metadata.sql".to_string()),
            options: None,
            schema: None,
            #[cfg(feature = "templating")]
            template_config: None,
        };

        let result = super::super::analyze(&request);

        assert_eq!(result.statements.len(), 1);
        assert_eq!(
            result.statements[0].statement_type,
            "CREATE_EXTERNAL_FILE_FORMAT"
        );
        assert_eq!(
            result.statements[0].span,
            Some(crate::types::Span::new(0, sql.len()))
        );
        assert!(result.nodes.is_empty());
        assert!(result.edges.is_empty());
        assert!(result
            .resolved_schema
            .as_ref()
            .is_none_or(|schema| schema.tables.is_empty()));
        let issue = result
            .issues
            .iter()
            .find(|issue| issue.code == issue_codes::UNSUPPORTED_SYNTAX)
            .expect("unsupported-lineage warning");
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.source_name.as_deref(), Some("metadata.sql"));
        assert_eq!(issue.span, Some(crate::types::Span::new(0, sql.len())));
        assert!(!result
            .issues
            .iter()
            .any(|issue| issue.code == issue_codes::PARSE_ERROR));
    }

    #[cfg(feature = "templating")]
    #[test]
    fn templated_metadata_warnings_keep_original_source_span() {
        let sql =
            "CREATE EXTERNAL FILE FORMAT {{ format_name }} WITH (FORMAT_TYPE = DELIMITEDTEXT)";
        let mut context = std::collections::HashMap::new();
        context.insert("format_name".to_string(), serde_json::json!("csv"));
        let request = crate::types::AnalyzeRequest {
            sql: sql.to_string(),
            files: None,
            dialect: Dialect::Mssql,
            source_name: None,
            options: None,
            schema: None,
            template_config: Some(crate::templater::TemplateConfig {
                mode: crate::templater::TemplateMode::Jinja,
                context,
            }),
        };

        let result = super::super::analyze(&request);

        assert_eq!(
            result.statements[0].span,
            Some(crate::types::Span::new(0, sql.len()))
        );
        let issue = result
            .issues
            .iter()
            .find(|issue| issue.code == issue_codes::UNSUPPORTED_SYNTAX)
            .expect("unsupported-lineage warning");
        assert_eq!(issue.span, Some(crate::types::Span::new(0, sql.len())));
    }

    #[test]
    fn returns_none_for_non_metadata_statements() {
        assert_eq!(parse_format("SELECT * FROM orders").expect("parse"), None);
        assert_eq!(
            parse_format("CREATE EXTERNAL TABLE orders (id INT)").expect("parse"),
            None
        );
        assert_eq!(
            parse_format(
                "CREATE EXTERNAL TABLE orders WITH (LOCATION = 'out/', \
                 DATA_SOURCE = lake_source, FILE_FORMAT = parquet_format)"
            )
            .expect("parse"),
            None,
            "external table creation without AS SELECT is not classified as CETAS"
        );
        assert_eq!(
            parse_format("IF 1 = 1 BEGIN SELECT 1; END").expect("ordinary IF parsing"),
            None,
            "ordinary control flow must not be reclassified as metadata"
        );
    }

    #[test]
    fn rejects_unsupported_format_types_and_options() {
        for sql in [
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = CSV)",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = ORC)",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             UNKNOWN = 'x')",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             FORMAT_OPTIONS (ROW_TERMINATOR = '\\n'))",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             FORMAT_OPTIONS (PARSER_VERSION = '2.0'))",
            "CREATE EXTERNAL FILE FORMAT 123 WITH (FORMAT_TYPE = DELIMITEDTEXT)",
        ] {
            let error = parse_format(sql).expect_err("unsupported syntax must fail parsing");
            assert_eq!(error.dialect, Some(Dialect::Mssql));
        }
    }

    #[test]
    fn rejects_unquoted_reserved_names_but_accepts_delimited_names() {
        for name in ["SELECT", "FROM", "WHERE"] {
            let sql = format!("CREATE EXTERNAL FILE FORMAT {name} WITH (FORMAT_TYPE = PARQUET)");
            assert!(
                parse_format(&sql).is_err(),
                "reserved name must fail: {name}"
            );
        }
        assert_eq!(
            file_format("CREATE EXTERNAL FILE FORMAT [SELECT] WITH (FORMAT_TYPE = PARQUET)").name,
            vec!["SELECT"]
        );
        assert_eq!(
            file_format("CREATE EXTERNAL FILE FORMAT csv WITH (FORMAT_TYPE = DELIMITEDTEXT)").name,
            vec!["csv"]
        );
    }

    #[test]
    fn rejects_invalid_format_specific_options_and_compression() {
        for sql in [
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = PARQUET, \
             FORMAT_OPTIONS (FIELD_TERMINATOR = ','))",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELTA, \
             DATA_COMPRESSION = 'org.apache.hadoop.io.compress.GzipCodec')",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = PARQUET, \
             DATA_COMPRESSION = 'org.apache.hadoop.io.compress.DefaultCodec')",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             DATA_COMPRESSION = 'org.apache.hadoop.io.compress.SnappyCodec')",
        ] {
            assert!(parse_format(sql).is_err(), "expected rejection: {sql}");
        }
    }

    #[test]
    fn rejects_duplicate_options_malformed_values_and_trailing_tokens() {
        for sql in [
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             FORMAT_OPTIONS (FIELD_TERMINATOR = ',', FIELD_TERMINATOR = '|'))",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             FORMAT_OPTIONS (FIRST_ROW = 16))",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             FORMAT_OPTIONS (USE_TYPE_DEFAULT = 'TRUE'))",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT, \
             FORMAT_OPTIONS (FIELD_TERMINATOR = 1))",
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = DELIMITEDTEXT); SELECT 1",
        ] {
            assert!(parse_format(sql).is_err(), "expected rejection: {sql}");
        }
    }

    #[test]
    fn parse_errors_preserve_dialect_and_location() {
        let error = parse_format(
            "CREATE EXTERNAL FILE FORMAT f\nWITH (FORMAT_TYPE = DELIMITEDTEXT, UNKNOWN = 1)",
        )
        .expect_err("unknown option");

        assert_eq!(error.dialect, Some(Dialect::Mssql));
        assert!(error.position.is_some());
    }

    #[test]
    fn invalid_compression_error_points_at_the_original_value() {
        let value = "'org.apache.hadoop.io.compress.DefaultCodec'";
        let sql = format!(
            "CREATE EXTERNAL FILE FORMAT f WITH (FORMAT_TYPE = PARQUET, DATA_COMPRESSION = {value})"
        );
        let error = parse_format(&sql).expect_err("unsupported compression");

        assert_eq!(
            error.position.expect("value position").column,
            sql.find(value).expect("compression value") + 1
        );
    }
}
