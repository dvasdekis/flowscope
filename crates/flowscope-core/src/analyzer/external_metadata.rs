//! Parsing and classification for metadata-only external SQL objects.
//!
//! The supported statements are intentionally kept separate from relational
//! analysis: external file formats do not establish table schema, and CETAS
//! output and file-write lineage are not modeled.

use crate::error::{ParseError, ParseErrorKind};
use crate::types::{issue_codes, Dialect, Issue};
use sqlparser::dialect::MsSqlDialect;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer};
use std::collections::HashSet;
use std::ops::Range;

const UNSUPPORTED_LINEAGE_MESSAGE: &str =
    "CREATE EXTERNAL FILE FORMAT is metadata only; external-file lineage is not modeled.";
const CETAS_UNSUPPORTED_LINEAGE_MESSAGE: &str =
    "CREATE EXTERNAL TABLE AS SELECT is parsed, but external-table and file-write lineage are not modeled.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExternalMetadataStatement {
    FileFormat(ExternalFileFormatDefinition),
    Cetas(CetasDefinition),
}

impl ExternalMetadataStatement {
    pub(crate) fn statement_type(&self) -> &'static str {
        match self {
            Self::FileFormat(_) => "CREATE_EXTERNAL_FILE_FORMAT",
            Self::Cetas(_) => "CREATE_EXTERNAL_TABLE_AS_SELECT",
        }
    }

    pub(crate) fn unsupported_lineage_warning(&self) -> Issue {
        match self {
            Self::FileFormat(_) => {
                Issue::warning(issue_codes::UNSUPPORTED_SYNTAX, UNSUPPORTED_LINEAGE_MESSAGE)
            }
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

/// Validates the supported external file-format and CETAS subsets without
/// rewriting or synthesizing SQL. Other statement kinds return `Ok(None)`.
pub(crate) fn parse_external_metadata_statement(
    sql: &str,
) -> Result<Option<ExternalMetadataStatement>, ParseError> {
    let Ok(tokens) = Tokenizer::new(&MsSqlDialect {}, sql).tokenize_with_location() else {
        return Ok(None);
    };

    let mut parser = ExternalMetadataParser::new(sql, &tokens);
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

struct ExternalMetadataParser<'a> {
    source_sql: &'a str,
    tokens: Vec<&'a TokenWithSpan>,
    position: usize,
    statement_name: &'static str,
    object_name: &'static str,
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
        let _table_name = self.parse_object_name(3)?;

        if self
            .peek()
            .is_some_and(|token| matches!(&token.token, Token::LParen))
        {
            let column_list_start = self.position;
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
            ExternalMetadataStatement::Cetas(_) => panic!("expected file format metadata"),
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
