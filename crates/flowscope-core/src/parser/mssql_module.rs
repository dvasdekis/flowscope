use sqlparser::ast::Statement;
use sqlparser::dialect::Dialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Span, Token, TokenWithSpan, Tokenizer, Word};
use std::ops::Range;

/// Parse the narrow procedure-header variants supported by this adapter.
///
/// The source string is never rewritten; adapted and synthetic tokens retain
/// their source or boundary locations.
pub(super) fn parse_compatible_procedure(
    sql: &str,
    dialect: &dyn Dialect,
) -> Option<Result<Vec<Statement>, ParserError>> {
    let mut tokens = Tokenizer::new(dialect, sql).tokenize_with_location().ok()?;
    if !adapt_procedure_headers(&mut tokens) {
        return None;
    }

    let mut parser = Parser::new(dialect).with_tokens_with_locations(tokens);
    Some(parser.parse_statements())
}

#[derive(Debug)]
struct ProcedureHeader {
    procedure_keyword: usize,
    shorthand: bool,
    name_end: Option<usize>,
}

fn adapt_procedure_headers(tokens: &mut Vec<TokenWithSpan>) -> bool {
    let significant = significant_token_indices(tokens);
    let headers = find_procedure_headers(tokens, &significant);
    if headers.is_empty() {
        return false;
    }

    let mut changed = false;
    let mut replacements = Vec::new();
    let mut insertions = Vec::new();
    let mut removed = vec![false; tokens.len()];

    for header in headers {
        if header.shorthand {
            let Some(Token::Word(word)) = tokens.get(header.procedure_keyword).map(|t| &t.token)
            else {
                continue;
            };
            let mut procedure = word.clone();
            procedure.value = "PROCEDURE".to_string();
            procedure.keyword = Keyword::PROCEDURE;
            replacements.push((
                header.procedure_keyword,
                TokenWithSpan::new(
                    Token::Word(procedure),
                    tokens[header.procedure_keyword].span,
                ),
            ));
            changed = true;
        }

        let Some(name_end) = header.name_end else {
            continue;
        };
        let Some(after_name) = next_significant_index(&significant, name_end) else {
            continue;
        };

        if matches!(tokens[after_name].token, Token::LParen) {
            let Some(close_paren) = matching_paren(tokens, after_name) else {
                continue;
            };
            let Some(parameter_ranges) = split_parameters(tokens, after_name + 1..close_paren)
            else {
                continue;
            };
            if adapt_parameter_modifiers(tokens, &parameter_ranges, &mut removed, &mut insertions) {
                changed = true;
            }
        } else if is_parameter_name(&tokens[after_name].token) {
            let Some(as_index) = find_procedure_as(tokens, after_name) else {
                continue;
            };
            let Some(parameter_ranges) = split_parameters(tokens, after_name..as_index) else {
                continue;
            };
            let Some(open_span) = point_span(tokens[after_name].span.start) else {
                continue;
            };
            let Some(close_span) = point_span(tokens[as_index].span.start) else {
                continue;
            };

            insertions.push((
                after_name,
                InsertKind::OpenParen,
                TokenWithSpan::new(Token::LParen, open_span),
            ));
            insertions.push((
                as_index,
                InsertKind::CloseParen,
                TokenWithSpan::new(Token::RParen, close_span),
            ));
            changed = true;
            if adapt_parameter_modifiers(tokens, &parameter_ranges, &mut removed, &mut insertions) {
                changed = true;
            }
        }
    }

    if !changed {
        return false;
    }

    replacements.sort_by_key(|(index, _)| *index);
    replacements.dedup_by_key(|(index, _)| *index);
    for (index, replacement) in replacements {
        tokens[index] = replacement;
    }

    insertions.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut adapted = Vec::with_capacity(tokens.len() + insertions.len());
    let mut insertion_index = 0;
    for index in 0..=tokens.len() {
        while insertions
            .get(insertion_index)
            .is_some_and(|(at, _, _)| *at == index)
        {
            adapted.push(insertions[insertion_index].2.clone());
            insertion_index += 1;
        }
        if index < tokens.len() && !removed[index] {
            adapted.push(tokens[index].clone());
        }
    }
    *tokens = adapted;

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InsertKind {
    OpenParen,
    OutputMode,
    CloseParen,
}

fn find_procedure_headers(tokens: &[TokenWithSpan], significant: &[usize]) -> Vec<ProcedureHeader> {
    let mut headers = Vec::new();

    for position in 0..significant.len() {
        if position > 0 && !matches!(&tokens[significant[position - 1]].token, Token::SemiColon) {
            continue;
        }
        if !word_is(tokens, significant[position], "CREATE") {
            continue;
        }

        let mut procedure_position = position + 1;
        if word_is_at(tokens, significant, procedure_position, "OR")
            && word_is_at(tokens, significant, procedure_position + 1, "ALTER")
        {
            procedure_position += 2;
        }

        let Some(&procedure_keyword) = significant.get(procedure_position) else {
            continue;
        };
        let shorthand = word_is(tokens, procedure_keyword, "PROC");
        if !shorthand && !word_is(tokens, procedure_keyword, "PROCEDURE") {
            continue;
        }

        let name_start = procedure_position + 1;
        let name_end = parse_object_name_end(tokens, significant, name_start);
        headers.push(ProcedureHeader {
            procedure_keyword,
            shorthand,
            name_end,
        });
    }

    headers
}

fn parse_object_name_end(
    tokens: &[TokenWithSpan],
    significant: &[usize],
    name_start: usize,
) -> Option<usize> {
    let mut position = name_start;
    let first_name = word(tokens, *significant.get(position)?)?;
    if first_name.quote_style.is_none() && first_name.value.starts_with('@') {
        return None;
    }
    position += 1;

    while position + 1 < significant.len()
        && matches!(tokens[significant[position]].token, Token::Period)
        && matches!(tokens[significant[position + 1]].token, Token::Word(_))
    {
        position += 2;
    }

    significant.get(position - 1).copied()
}

fn next_significant_index(significant: &[usize], index: usize) -> Option<usize> {
    significant
        .iter()
        .copied()
        .find(|significant_index| *significant_index > index)
}

fn find_procedure_as(tokens: &[TokenWithSpan], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match &token.token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.checked_sub(1)?,
            Token::SemiColon if depth == 0 => return None,
            Token::Word(_) if depth == 0 && word_is(tokens, index, "AS") => {
                return Some(index);
            }
            _ => {}
        }
    }
    None
}

fn matching_paren(tokens: &[TokenWithSpan], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match &token.token {
            Token::LParen => depth += 1,
            Token::RParen => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_parameters(tokens: &[TokenWithSpan], range: Range<usize>) -> Option<Vec<Range<usize>>> {
    let mut parameters = Vec::new();
    let mut start = range.start;
    let mut depth = 0usize;

    for index in range.clone() {
        match &tokens[index].token {
            Token::LParen => depth += 1,
            Token::RParen => {
                depth = depth.checked_sub(1)?;
            }
            Token::Comma if depth == 0 => {
                if significant_token_indices_in_range(tokens, start..index).is_empty() {
                    return None;
                }
                parameters.push(start..index);
                start = index + 1;
            }
            _ => {}
        }
    }

    if significant_token_indices_in_range(tokens, start..range.end).is_empty() {
        return None;
    }
    parameters.push(start..range.end);
    Some(parameters)
}

fn adapt_parameter_modifiers(
    tokens: &[TokenWithSpan],
    parameters: &[Range<usize>],
    removed: &mut [bool],
    insertions: &mut Vec<(usize, InsertKind, TokenWithSpan)>,
) -> bool {
    let mut changed = false;
    for parameter in parameters {
        let significant = significant_token_indices_in_range(tokens, parameter.clone());
        let Some(&last_index) = significant.last() else {
            continue;
        };

        if !word_is(tokens, last_index, "OUTPUT") && !word_is(tokens, last_index, "READONLY") {
            continue;
        }

        let Some(&name_index) = significant.first() else {
            continue;
        };
        if !is_parameter_name(&tokens[name_index].token) {
            continue;
        }

        if word_is(tokens, last_index, "READONLY")
            && !has_user_defined_table_type(tokens, &significant[..significant.len() - 1])
        {
            continue;
        }

        removed[last_index] = true;

        if word_is(tokens, last_index, "OUTPUT") {
            let Some(mut output) = tokens.get(last_index).cloned() else {
                continue;
            };
            let Token::Word(word) = &mut output.token else {
                continue;
            };
            word.value = "OUT".to_string();
            word.keyword = Keyword::OUT;
            insertions.push((name_index, InsertKind::OutputMode, output));
        } else {
            // sqlparser's ProcedureParam does not model READONLY.
        }
        changed = true;
    }
    changed
}

fn has_user_defined_table_type(tokens: &[TokenWithSpan], parameter: &[usize]) -> bool {
    let Some(&name_index) = parameter.first() else {
        return false;
    };
    let Some(name) = word(tokens, name_index) else {
        return false;
    };
    if !name.value.starts_with('@') {
        return false;
    }

    let type_tokens = &parameter[1..];
    let Some(&first_type_index) = type_tokens.first() else {
        return false;
    };
    let Some(first_type) = word(tokens, first_type_index) else {
        return false;
    };
    if first_type.quote_style.is_none() && first_type.keyword != Keyword::NoKeyword {
        return false;
    }

    let mut expected_word = true;
    let mut parts = 0usize;
    for &index in type_tokens {
        if expected_word {
            let Some(type_part) = word(tokens, index) else {
                return false;
            };
            if type_part.quote_style.is_none() && type_part.keyword != Keyword::NoKeyword {
                return false;
            }
            expected_word = false;
            parts += 1;
        } else if matches!(tokens[index].token, Token::Period) {
            expected_word = true;
        } else {
            return false;
        }
    }

    !expected_word && (1..=3).contains(&parts)
}

fn is_parameter_name(token: &Token) -> bool {
    matches!(
        token,
        Token::Word(word)
            if word.quote_style.is_none()
                && word.value.starts_with('@')
                && !word.value.starts_with("@@")
                && word.value.len() > 1
    )
}

fn significant_token_indices(tokens: &[TokenWithSpan]) -> Vec<usize> {
    tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            (!matches!(token.token, Token::Whitespace(_))).then_some(index)
        })
        .collect()
}

fn significant_token_indices_in_range(tokens: &[TokenWithSpan], range: Range<usize>) -> Vec<usize> {
    range
        .filter(|index| !matches!(tokens[*index].token, Token::Whitespace(_)))
        .collect()
}

fn word_is_at(
    tokens: &[TokenWithSpan],
    significant: &[usize],
    position: usize,
    expected: &str,
) -> bool {
    significant
        .get(position)
        .is_some_and(|index| word_is(tokens, *index, expected))
}

fn word_is(tokens: &[TokenWithSpan], index: usize, expected: &str) -> bool {
    word(tokens, index)
        .is_some_and(|word| word.quote_style.is_none() && word.value.eq_ignore_ascii_case(expected))
}

fn word(tokens: &[TokenWithSpan], index: usize) -> Option<&Word> {
    match &tokens.get(index)?.token {
        Token::Word(word) => Some(word),
        _ => None,
    }
}

fn point_span(location: sqlparser::tokenizer::Location) -> Option<Span> {
    (location.line != 0 && location.column != 0).then_some(Span::new(location, location))
}

#[cfg(test)]
fn adapt_procedure_headers_for_test(tokens: &mut Vec<TokenWithSpan>) -> bool {
    adapt_procedure_headers(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_sql_with_dialect, parse_sql_with_dialect_output};
    use crate::types::Dialect as FlowDialect;
    use sqlparser::ast::{ArgMode, CreateFunctionBody, DataType, Spanned, Statement};
    use sqlparser::dialect::MsSqlDialect;
    use sqlparser::tokenizer::{Tokenizer, Whitespace};

    fn parse_mssql(sql: &str) -> crate::error::ParseError {
        parse_sql_with_dialect(sql, FlowDialect::Mssql).expect_err("expected a parse error")
    }

    fn procedure_params(statement: &Statement) -> &[sqlparser::ast::ProcedureParam] {
        let Statement::CreateProcedure {
            params: Some(params),
            ..
        } = statement
        else {
            panic!("expected a CREATE PROCEDURE statement with parameters");
        };
        params
    }

    fn word_span(tokens: &[TokenWithSpan], value: &str) -> Span {
        tokens
            .iter()
            .find_map(|token| match &token.token {
                Token::Word(word) if word.value.eq_ignore_ascii_case(value) => Some(token.span),
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected token {value}"))
    }

    fn text_for_span(sql: &str, span: Span) -> &str {
        fn byte_offset(sql: &str, location: sqlparser::tokenizer::Location) -> usize {
            assert!(location.line > 0 && location.column > 0);
            let line_start = sql
                .split_inclusive('\n')
                .take((location.line - 1) as usize)
                .map(str::len)
                .sum::<usize>();
            let line = &sql[line_start..];
            line.char_indices()
                .nth((location.column - 1) as usize)
                .map(|(offset, _)| line_start + offset)
                .unwrap_or(sql.len())
        }

        let start = byte_offset(sql, span.start);
        let end = byte_offset(sql, span.end);
        &sql[start..end]
    }

    #[test]
    fn parses_unparenthesized_proc_parameters_and_preserves_qualified_name() {
        let sql = "CREATE PROCEDURE [sales].[copy_rows] @limit INT = 10, @ratio DECIMAL(8, 2) = 0.5 AS BEGIN SELECT @limit; END";
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse");

        assert!(output.parser_fallback_used);
        assert_eq!(output.statements.len(), 1);
        let Statement::CreateProcedure { name, body, .. } = &output.statements[0] else {
            panic!("expected CREATE PROCEDURE");
        };
        assert_eq!(name.to_string(), "[sales].[copy_rows]");
        let params = procedure_params(&output.statements[0]);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name.value, "@limit");
        assert_eq!(
            params[0]
                .default
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("10")
        );
        assert_eq!(
            params[1]
                .default
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("0.5")
        );
        assert_eq!(body.statements().len(), 1);
    }

    #[test]
    fn parses_proc_shorthand_output_readonly_and_dynamic_sql_as_opaque_text() {
        let sql = concat!(
            "-- café\r\n",
            "CREATE OR ALTER PROC [dbo].[copy_rows] ",
            "@source_id INT = 7 OUTPUT, @rows dbo.RowList READONLY ",
            "AS BEGIN SELECT N'CREATE PROC hidden @x INT OUTPUT'; END"
        );
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse");

        assert!(output.parser_fallback_used);
        let Statement::CreateProcedure {
            name,
            or_alter,
            body,
            ..
        } = &output.statements[0]
        else {
            panic!("expected CREATE PROCEDURE");
        };
        assert!(*or_alter);
        assert_eq!(name.to_string(), "[dbo].[copy_rows]");
        let params = procedure_params(&output.statements[0]);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].mode, Some(ArgMode::Out));
        assert_eq!(
            params[0]
                .default
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("7")
        );
        assert_eq!(params[1].mode, None);
        assert!(matches!(&params[1].data_type, DataType::Custom(_, _)));
        assert!(
            body.statements()[0]
                .to_string()
                .contains("CREATE PROC hidden"),
            "dynamic SQL text must remain opaque"
        );
    }

    #[test]
    fn parses_unqualified_procedure_name_without_parameters() {
        let output = parse_sql_with_dialect_output(
            "CREATE PROC refresh_cache AS SELECT 1;",
            FlowDialect::Mssql,
        )
        .expect("parse");

        assert!(output.parser_fallback_used);
        let Statement::CreateProcedure { name, params, .. } = &output.statements[0] else {
            panic!("expected CREATE PROCEDURE");
        };
        assert_eq!(name.to_string(), "refresh_cache");
        assert_eq!(params.as_ref().map(Vec::len), Some(0));
    }

    #[test]
    fn leaves_parenthesized_procedure_defaults_on_the_primary_parser_path() {
        let output = parse_sql_with_dialect_output(
            "CREATE PROCEDURE dbo.p (@value INT = 10) AS SELECT @value;",
            FlowDialect::Mssql,
        )
        .expect("parse");

        assert!(!output.parser_fallback_used);
        let params = procedure_params(&output.statements[0]);
        assert_eq!(
            params[0]
                .default
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("10")
        );
    }

    #[test]
    fn adapts_parenthesized_output_and_readonly_without_changing_token_locations() {
        let sql = concat!(
            "-- café\r\n",
            "CREATE PROCEDURE dbo.copy_rows ",
            "(@source_id INT OUTPUT, @rows [dbo].[RowList] READONLY) ",
            "AS SELECT @source_id;"
        );
        let dialect = MsSqlDialect {};
        let original = Tokenizer::new(&dialect, sql)
            .tokenize_with_location()
            .expect("tokenize original");
        let mut adapted = original.clone();
        assert!(adapt_procedure_headers_for_test(&mut adapted));
        let adapted_parse = Parser::new(&dialect)
            .with_tokens_with_locations(adapted.clone())
            .parse_statements();
        assert!(
            adapted_parse.is_ok(),
            "adapted parse failed: {adapted_parse:?}"
        );

        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse");
        assert!(output.parser_fallback_used);
        let params = procedure_params(&output.statements[0]);
        assert_eq!(params[0].mode, Some(ArgMode::Out));
        assert!(matches!(&params[1].data_type, DataType::Custom(_, _)));

        let output_span = word_span(&original, "OUTPUT");
        assert_eq!(word_span(&adapted, "OUT"), output_span);
        let readonly = original
            .iter()
            .find(|token| {
                matches!(&token.token, Token::Word(word) if word.value.eq_ignore_ascii_case("READONLY"))
            })
            .expect("READONLY token");
        assert!(!adapted.contains(readonly));
        for source_token in &original {
            if matches!(
                &source_token.token,
                Token::Whitespace(
                    Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_)
                ) | Token::NationalStringLiteral(_)
            ) {
                assert!(adapted.contains(source_token));
            }
        }
    }

    #[test]
    fn adapts_proc_shorthand_and_unparenthesized_parameters_at_original_locations() {
        let sql = concat!(
            "-- café\r\n",
            "CREATE OR ALTER PROC dbo.copy_rows ",
            "@source_id INT OUTPUT, @rows dbo.RowList READONLY ",
            "AS BEGIN SELECT @source_id; END"
        );
        let dialect = MsSqlDialect {};
        let original = Tokenizer::new(&dialect, sql)
            .tokenize_with_location()
            .expect("tokenize original");
        let mut adapted = original.clone();
        assert!(adapt_procedure_headers_for_test(&mut adapted));

        let adapted_parse = Parser::new(&dialect)
            .with_tokens_with_locations(adapted.clone())
            .parse_statements();
        assert!(
            adapted_parse.is_ok(),
            "adapted parse failed: {adapted_parse:?}"
        );
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse");
        assert!(output.parser_fallback_used);

        assert_eq!(
            word_span(&adapted, "PROCEDURE"),
            word_span(&original, "PROC")
        );
        assert_eq!(word_span(&adapted, "OUT"), word_span(&original, "OUTPUT"));
        assert!(adapted.iter().any(|token| {
            matches!(&token.token, Token::Word(word) if word.value == "PROCEDURE")
        }));
        assert!(adapted.iter().any(|token| {
            matches!(&token.token, Token::LParen)
                && token.span.start == word_span(&original, "@source_id").start
        }));
        assert!(adapted.iter().any(|token| {
            matches!(&token.token, Token::RParen)
                && token.span.start == word_span(&original, "AS").start
        }));
        for source_token in &original {
            if matches!(
                &source_token.token,
                Token::Whitespace(
                    Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_)
                )
            ) {
                assert!(adapted.contains(source_token));
            }
        }
    }

    #[test]
    fn parses_mssql_function_and_trigger_blocks_with_source_spans() {
        let sql = concat!(
            "-- café\n",
            "CREATE OR ALTER FUNCTION dbo.increment_value(@value INT) RETURNS INT ",
            "AS BEGIN DECLARE @next INT; SET @next = @value + 1; RETURN @next; END;\n",
            "CREATE OR ALTER TRIGGER dbo.audit_insert ON dbo.items AFTER INSERT ",
            "AS BEGIN SELECT 1; SELECT 2; END;\n",
            "SELECT 3;"
        );
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse");

        assert!(!output.parser_fallback_used);
        assert_eq!(output.statements.len(), 3);
        let Statement::CreateFunction(function) = &output.statements[0] else {
            panic!("expected CREATE FUNCTION");
        };
        assert_eq!(output.statements[0].span(), Span::empty());
        let Some(CreateFunctionBody::AsBeginEnd(function_body)) = &function.function_body else {
            panic!("expected a BEGIN/END function body");
        };
        assert_eq!(function_body.statements.len(), 3);
        assert_eq!(
            text_for_span(sql, function_body.span()),
            "BEGIN DECLARE @next INT; SET @next = @value + 1; RETURN @next; END"
        );

        let Statement::CreateTrigger(trigger) = &output.statements[1] else {
            panic!("expected CREATE TRIGGER");
        };
        assert_eq!(output.statements[1].span(), Span::empty());
        let trigger_body = trigger.statements.as_ref().expect("trigger statement body");
        assert_eq!(trigger_body.statements().len(), 2);
        assert_eq!(
            text_for_span(sql, trigger_body.span()),
            "BEGIN SELECT 1; SELECT 2; END"
        );
        assert_eq!(output.statements[2].to_string(), "SELECT 3");
    }

    #[test]
    fn parses_mssql_inline_function_return_body_with_original_source_span() {
        let sql = concat!(
            "-- café\n",
            "CREATE OR ALTER FUNCTION dbo.return_rows(@minimum INT) RETURNS TABLE ",
            "AS RETURN (SELECT @minimum AS value); SELECT 2;"
        );
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse");

        assert!(!output.parser_fallback_used);
        assert_eq!(output.statements.len(), 2);
        let Statement::CreateFunction(function) = &output.statements[0] else {
            panic!("expected CREATE FUNCTION");
        };
        assert!(matches!(&function.return_type, Some(DataType::Table(None))));
        let Some(CreateFunctionBody::AsReturnExpr(expression)) = &function.function_body else {
            panic!("expected a RETURN expression body");
        };
        assert_eq!(
            text_for_span(sql, expression.span()),
            "SELECT @minimum AS value"
        );
        assert_eq!(output.statements[1].to_string(), "SELECT 2");
    }

    #[test]
    fn malformed_mssql_function_and_trigger_headers_keep_source_locations() {
        for sql in [
            "-- café\nCREATE OR ALTER FUNCTION dbo.bad(@value INT) TABLE AS RETURN (SELECT @value);",
            "-- café\nCREATE OR ALTER TRIGGER dbo.bad ON dbo.items AS BEGIN SELECT 1; END;",
        ] {
            let error =
                parse_sql_with_dialect(sql, FlowDialect::Mssql).expect_err("malformed module");
            assert_eq!(error.position.map(|position| position.line), Some(2));
        }
    }

    #[test]
    fn one_byte_rewritten_retry_still_adapts_the_procedure_header() {
        let original = "CREATE PROC dbo.read_file @id INT OUTPUT AS BEGIN SELECT * FROM OPENROWSET(BULK 'file.csv', FORMAT = 'CSV') AS f; END";
        let rewritten = original
            .replacen("BULK ", "BULK:", 1)
            .replacen("FORMAT =", "FORMAT :", 1);
        assert_eq!(original.len(), rewritten.len());
        assert!(parse_sql_with_dialect_output(original, FlowDialect::Mssql).is_err());
        let mut tokens = Tokenizer::new(&MsSqlDialect {}, &rewritten)
            .tokenize_with_location()
            .expect("tokenize retry");
        assert!(adapt_procedure_headers_for_test(&mut tokens));
        let adapted_parse = Parser::new(&MsSqlDialect {})
            .with_tokens_with_locations(tokens)
            .parse_statements();
        assert!(
            adapted_parse.is_ok(),
            "adapted retry failed: {adapted_parse:?}"
        );

        let output =
            parse_sql_with_dialect_output(&rewritten, FlowDialect::Mssql).expect("retry parse");
        assert!(output.parser_fallback_used);
        assert!(matches!(
            output.statements.as_slice(),
            [Statement::CreateProcedure { .. }]
        ));
    }

    #[test]
    fn malformed_unparenthesized_parameters_and_modifiers_remain_errors() {
        for sql in [
            "CREATE PROC dbo.p @value INT @other INT AS SELECT 1",
            "CREATE PROC dbo.p @value AS SELECT 1",
            "CREATE PROC dbo.p @value INT, AS SELECT 1",
            "CREATE PROC dbo.p @value INT OUTPUT = 1 AS SELECT 1",
            "CREATE PROC dbo.p @value INT OUTPUT OUTPUT AS SELECT 1",
            "CREATE PROC dbo.p @rows INT READONLY AS SELECT 1",
            "CREATE PROC dbo.p @rows dbo.RowList READONLY READONLY AS SELECT 1",
            "CREATE PROC @p @value INT AS SELECT 1",
            "CREATE PROC dbo.p @@system_value INT AS SELECT 1",
        ] {
            parse_mssql(sql);
        }
    }

    #[test]
    fn malformed_proc_parameter_error_keeps_the_original_source_location() {
        let sql = "CREATE PROC dbo.p @value INT @other INT AS SELECT 1;";
        let error = parse_sql_with_dialect(sql, FlowDialect::Mssql).expect_err("invalid parameter");
        assert_eq!(
            error.position.map(|position| position.column),
            sql.find("@other").map(|offset| offset + 1)
        );
    }

    #[test]
    fn malformed_parenthesized_parameters_and_module_headers_remain_errors() {
        for sql in [
            "CREATE PROCEDURE dbo.p (@value) AS SELECT 1",
            "CREATE PROCEDURE dbo.p (@value INT OUTPUT = 1) AS SELECT 1",
            "CREATE PROCEDURE dbo.p (@value INT OUTPUT OUTPUT) AS SELECT 1",
            "CREATE PROCEDURE dbo.p (@rows dbo.RowList READONLY READONLY) AS SELECT 1",
            "CREATE OR ALTER PROC dbo.p @value INT",
        ] {
            parse_mssql(sql);
        }
    }

    #[test]
    fn procedure_adapter_is_mssql_only_and_leaves_comments_and_literals_alone() {
        let source = concat!(
            "CREATE PROC dbo.p @value INT AS BEGIN ",
            "SELECT N'@not_a_parameter INT OUTPUT', /* @also_not_a_parameter INT */ 1; END"
        );
        assert!(parse_sql_with_dialect_output(source, FlowDialect::Mssql).is_ok());
        assert!(
            parse_sql_with_dialect_output(source, FlowDialect::Generic).is_err(),
            "the MSSQL-only header rewrite must not apply to other dialects"
        );

        let mut tokens = Tokenizer::new(&MsSqlDialect {}, source)
            .tokenize_with_location()
            .expect("tokenize");
        assert!(adapt_procedure_headers_for_test(&mut tokens));
        let adapted_parse = Parser::new(&MsSqlDialect {})
            .with_tokens_with_locations(tokens.clone())
            .parse_statements();
        assert!(
            adapted_parse.is_ok(),
            "adapted parse failed: {adapted_parse:?}"
        );
        let string = tokens.iter().find_map(|token| match &token.token {
            Token::NationalStringLiteral(value) => Some(value),
            _ => None,
        });
        assert_eq!(
            string.map(String::as_str),
            Some("@not_a_parameter INT OUTPUT")
        );
        assert!(tokens.iter().any(|token| {
            matches!(
                &token.token,
                Token::Whitespace(Whitespace::MultiLineComment(comment))
                    if comment == " @also_not_a_parameter INT "
            )
        }));
    }

    #[test]
    fn non_procedure_create_headers_are_not_adapted() {
        let function = "CREATE OR ALTER FUNCTION dbo.f(@value INT) RETURNS INT AS RETURN @value";
        let trigger =
            "CREATE OR ALTER TRIGGER dbo.t ON dbo.items AFTER INSERT AS BEGIN SELECT 1; END";

        for sql in [function, trigger] {
            let mut tokens = Tokenizer::new(&MsSqlDialect {}, sql)
                .tokenize_with_location()
                .expect("tokenize");
            assert!(!adapt_procedure_headers_for_test(&mut tokens), "{sql}");
        }
    }

    #[test]
    fn parses_mssql_create_or_alter_view_without_header_rewriting() {
        let sql = "CREATE OR ALTER VIEW [analytics].[daily_rollup] AS SELECT 1 AS item_id;";
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse view");

        assert!(!output.parser_fallback_used);
        assert!(matches!(
            output.statements.as_slice(),
            [Statement::CreateView(_)]
        ));
    }

    #[test]
    fn malformed_mssql_create_or_alter_view_retains_original_location() {
        let sql = "-- café\r\nCREATE OR ALTER VIEW [analytics].[broken_rollup] AS SELECT FROM;";
        let error = parse_mssql(sql);

        assert_eq!(error.position.map(|position| position.line), Some(2));
    }
}
