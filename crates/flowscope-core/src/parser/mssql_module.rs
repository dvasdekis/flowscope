use sqlparser::ast::Statement;
use sqlparser::dialect::Dialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Span, Token, TokenWithSpan, Tokenizer, Word};
use std::ops::Range;

const MAX_OPTIONAL_MODULE_TERMINATORS: usize = 128;

/// Parse the narrow MSSQL module variants supported by this adapter.
///
/// The source string is never rewritten; adapted and synthetic tokens retain
/// their source or boundary locations.
pub(super) fn parse_compatible_module(
    sql: &str,
    dialect: &dyn Dialect,
) -> Option<Result<Vec<Statement>, ParserError>> {
    let tokens = Tokenizer::new(dialect, sql).tokenize_with_location().ok()?;
    parse_compatible_module_tokens(tokens, dialect)
}

pub(super) fn parse_compatible_module_tokens(
    mut tokens: Vec<TokenWithSpan>,
    dialect: &dyn Dialect,
) -> Option<Result<Vec<Statement>, ParserError>> {
    let standalone_block = is_standalone_mssql_begin_end_block(&tokens);
    if standalone_block {
        tokens = wrap_standalone_mssql_block(tokens, dialect)?;
    }

    let has_module_header = has_mssql_module_header(&tokens);
    let procedure_adapted = adapt_procedure_headers(&mut tokens);
    let function_adapted = adapt_inline_table_function_return(&mut tokens);
    if !procedure_adapted && !function_adapted && !has_module_header {
        return None;
    }

    let parsed = Parser::new(dialect)
        .with_tokens_with_locations(tokens.clone())
        .parse_statements();
    match parsed {
        Ok(statements) => Some(unwrap_standalone_mssql_block(statements, standalone_block)),
        Err(error) if has_module_header => {
            if let Some(recovered) =
                recover_optional_module_terminators(tokens, dialect, error.clone())
            {
                Some(recovered.and_then(|statements| {
                    unwrap_standalone_mssql_block(statements, standalone_block)
                }))
            } else if procedure_adapted || function_adapted {
                Some(Err(error))
            } else {
                None
            }
        }
        Err(error) if procedure_adapted || function_adapted => Some(Err(error)),
        Err(_) => None,
    }
}

fn has_mssql_module_header(tokens: &[TokenWithSpan]) -> bool {
    let significant = significant_token_indices(tokens);
    (0..significant.len()).any(|position| {
        if !word_is_at(tokens, &significant, position, "CREATE") {
            return false;
        }
        let mut module_position = position + 1;
        if word_is_at(tokens, &significant, module_position, "OR")
            && word_is_at(tokens, &significant, module_position + 1, "ALTER")
        {
            module_position += 2;
        }
        ["PROC", "PROCEDURE", "FUNCTION", "TRIGGER"]
            .iter()
            .any(|module| word_is_at(tokens, &significant, module_position, module))
    })
}

fn is_standalone_mssql_begin_end_block(tokens: &[TokenWithSpan]) -> bool {
    let significant = significant_token_indices(tokens);
    let Some(begin_index) = significant
        .iter()
        .copied()
        .find(|index| !matches!(tokens[*index].token, Token::SemiColon | Token::EOF))
    else {
        return false;
    };
    if !word_is(tokens, begin_index, "BEGIN")
        || mssql_word_follows_any(tokens, begin_index, MSSQL_BEGIN_NON_BLOCK_FOLLOWERS)
    {
        return false;
    }

    let Some(end_index) = matching_standalone_block_end(tokens, begin_index) else {
        return false;
    };
    tokens[end_index + 1..].iter().all(|token| {
        matches!(
            token.token,
            Token::Whitespace(_) | Token::SemiColon | Token::EOF
        )
    })
}

fn matching_standalone_block_end(tokens: &[TokenWithSpan], begin_index: usize) -> Option<usize> {
    let mut block_depth = 0i32;
    let mut case_depth = 0i32;
    for (index, token) in tokens.iter().enumerate().skip(begin_index) {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() {
            continue;
        }
        if word.value.eq_ignore_ascii_case("GO") {
            return None;
        }
        if word.value.eq_ignore_ascii_case("CASE") {
            case_depth += 1;
        } else if word.value.eq_ignore_ascii_case("END") {
            if case_depth > 0 {
                case_depth -= 1;
            } else if !mssql_word_follows(tokens, index, "CONVERSATION") {
                block_depth -= 1;
                if block_depth == 0 {
                    return Some(index);
                }
            }
        } else if word.value.eq_ignore_ascii_case("BEGIN")
            && !mssql_word_follows_any(tokens, index, MSSQL_BEGIN_NON_BLOCK_FOLLOWERS)
        {
            block_depth += 1;
        }
    }
    None
}

fn wrap_standalone_mssql_block(
    mut tokens: Vec<TokenWithSpan>,
    dialect: &dyn Dialect,
) -> Option<Vec<TokenWithSpan>> {
    let begin_index = significant_token_indices(&tokens)
        .into_iter()
        .find(|index| !matches!(tokens[*index].token, Token::SemiColon | Token::EOF))?;
    let insertion_span = point_span(tokens[begin_index].span.start)?;
    let mut prefix = Tokenizer::new(dialect, "CREATE PROCEDURE __flowscope_block_wrapper AS ")
        .tokenize_with_location()
        .ok()?
        .into_iter()
        .filter(|token| !matches!(token.token, Token::EOF))
        .map(|mut token| {
            token.span = insertion_span;
            token
        })
        .collect::<Vec<_>>();
    let mut wrapped = tokens.drain(..begin_index).collect::<Vec<_>>();
    wrapped.append(&mut prefix);
    wrapped.extend(tokens);
    Some(wrapped)
}

fn unwrap_standalone_mssql_block(
    statements: Vec<Statement>,
    wrapped: bool,
) -> Result<Vec<Statement>, ParserError> {
    if !wrapped {
        return Ok(statements);
    }

    let [Statement::CreateProcedure { body, .. }] = statements.as_slice() else {
        return Err(ParserError::ParserError(
            "Expected synthetic procedure wrapper for standalone T-SQL block".to_string(),
        ));
    };
    let sqlparser::ast::ConditionalStatements::BeginEnd(block) = body else {
        return Err(ParserError::ParserError(
            "Expected BEGIN/END body for standalone T-SQL block".to_string(),
        ));
    };
    // Keep sqlparser's BEGIN/END statement container without exposing the synthetic procedure.
    Ok(vec![Statement::StartTransaction {
        modes: Vec::new(),
        begin: true,
        transaction: None,
        modifier: None,
        statements: block.statements.clone(),
        exception: None,
        has_end_keyword: true,
    }])
}

fn recover_optional_module_terminators(
    mut tokens: Vec<TokenWithSpan>,
    dialect: &dyn Dialect,
    mut error: ParserError,
) -> Option<Result<Vec<Statement>, ParserError>> {
    let mut inserted_any = false;
    for _ in 0..MAX_OPTIONAL_MODULE_TERMINATORS {
        let Some(candidate) = parser_reported_missing_terminator(&error, &tokens) else {
            return inserted_any.then_some(Err(error));
        };
        if !is_mssql_procedural_block_position(&tokens, candidate)
            || !is_optional_statement_start(&tokens[candidate].token)
        {
            return inserted_any.then_some(Err(error));
        }
        let Some(fragment_start) = complete_statement_start_before(&tokens, candidate, dialect)
        else {
            return inserted_any.then_some(Err(error));
        };

        let insertion_span = point_span(tokens[candidate].span.start)?;
        tokens.insert(
            candidate,
            TokenWithSpan::new(Token::SemiColon, insertion_span),
        );
        inserted_any = true;
        match Parser::new(dialect)
            .with_tokens_with_locations(tokens.clone())
            .parse_statements()
        {
            Ok(statements) => return Some(Ok(statements)),
            Err(next_error) => error = next_error,
        }

        if !is_complete_statement_fragment(
            &tokens[fragment_start..candidate],
            tokens[candidate].span.start,
            dialect,
        ) {
            return Some(Err(error));
        }
    }
    Some(Err(error))
}

fn parser_reported_missing_terminator(
    error: &ParserError,
    tokens: &[TokenWithSpan],
) -> Option<usize> {
    let ParserError::ParserError(message) = error else {
        return None;
    };
    if !message.starts_with("Expected: end of statement, found: ")
        && !message.starts_with("Expected: ;, found: ")
    {
        return None;
    }

    let (_, location) = message.rsplit_once(" at Line: ")?;
    let (line, column) = location.split_once(", Column: ")?;
    let line = line.parse::<u64>().ok()?;
    let column = column.parse::<u64>().ok()?;
    tokens.iter().position(|token| {
        token.span.start.line == line
            && token.span.start.column == column
            && is_optional_statement_start(&token.token)
    })
}

fn is_optional_statement_start(token: &Token) -> bool {
    matches!(
        token,
        Token::Word(word)
            if word.quote_style.is_none()
                && [
                    "BEGIN",
                    "DECLARE",
                    "DELETE",
                    "END",
                    "EXEC",
                    "EXECUTE",
                    "IF",
                    "INSERT",
                    "PRINT",
                    "RAISERROR",
                    "RETURN",
                    "SELECT",
                    "SET",
                    "THROW",
                    "UPDATE",
                    "WHILE",
                ]
                .iter()
                .any(|keyword| word.value.eq_ignore_ascii_case(keyword))
    )
}

fn is_mssql_procedural_block_position(tokens: &[TokenWithSpan], candidate: usize) -> bool {
    let mut block_depth = 0i32;
    let mut case_depth = 0i32;
    for (index, token) in tokens.iter().enumerate().take(candidate) {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() {
            continue;
        }
        if word.value.eq_ignore_ascii_case("GO") {
            block_depth = 0;
            case_depth = 0;
            continue;
        }
        if word.value.eq_ignore_ascii_case("CASE") {
            case_depth += 1;
        } else if word.value.eq_ignore_ascii_case("END") {
            if case_depth > 0 {
                case_depth -= 1;
            } else if !mssql_word_follows(tokens, index, "CONVERSATION") {
                block_depth -= 1;
            }
        } else if word.value.eq_ignore_ascii_case("BEGIN")
            && !mssql_word_follows_any(tokens, index, MSSQL_BEGIN_NON_BLOCK_FOLLOWERS)
        {
            block_depth += 1;
        }
    }
    block_depth > 0 && (!word_is(tokens, candidate, "END") || case_depth == 0)
}

fn complete_statement_start_before(
    tokens: &[TokenWithSpan],
    candidate: usize,
    dialect: &dyn Dialect,
) -> Option<usize> {
    let mut boundaries = Vec::new();
    for index in 0..candidate {
        if matches!(tokens[index].token, Token::SemiColon)
            || (word_is(tokens, index, "BEGIN")
                && !mssql_word_follows_any(tokens, index, MSSQL_BEGIN_NON_BLOCK_FOLLOWERS))
            || word_is(tokens, index, "ELSE")
        {
            boundaries.push(index + 1);
        }
    }
    boundaries.into_iter().rev().find_map(|start| {
        if tokens[start..candidate]
            .iter()
            .any(|token| word_is_token(&token.token, "GO"))
        {
            return None;
        }
        let start = next_significant_token_index(tokens, start, candidate)?;
        is_complete_statement_fragment(
            &tokens[start..candidate],
            tokens[candidate].span.start,
            dialect,
        )
        .then_some(start)
    })
}

const MSSQL_BEGIN_NON_BLOCK_FOLLOWERS: &[&str] = &[
    "TRAN",
    "TRANSACTION",
    "WORK",
    "DIALOG",
    "DISTRIBUTED",
    "CONVERSATION",
    "ISOLATION",
    "READ",
];

fn next_significant_token_index(
    tokens: &[TokenWithSpan],
    mut index: usize,
    end: usize,
) -> Option<usize> {
    while index < end {
        if !matches!(tokens[index].token, Token::Whitespace(_)) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn mssql_word_follows(tokens: &[TokenWithSpan], index: usize, expected: &str) -> bool {
    mssql_word_follows_any(tokens, index, &[expected])
}

fn mssql_word_follows_any(tokens: &[TokenWithSpan], index: usize, expected: &[&str]) -> bool {
    tokens[index + 1..]
        .iter()
        .find_map(|token| match &token.token {
            Token::Whitespace(_) => None,
            Token::Word(word) if word.quote_style.is_none() => Some(word.value.as_str()),
            Token::Word(_) => Some(""),
            _ => Some(""),
        })
        .is_some_and(|next| {
            expected
                .iter()
                .any(|keyword| next.eq_ignore_ascii_case(keyword))
        })
}

fn is_complete_statement_fragment(
    fragment: &[TokenWithSpan],
    end_location: sqlparser::tokenizer::Location,
    dialect: &dyn Dialect,
) -> bool {
    let Some(last_significant) = fragment
        .iter()
        .rposition(|token| !matches!(token.token, Token::Whitespace(_) | Token::EOF))
    else {
        return false;
    };
    let closes_block = word_is(fragment, last_significant, "END");
    if !has_balanced_module_blocks(fragment) {
        return false;
    }

    let Some(end_span) = point_span(end_location) else {
        return false;
    };
    let mut tokens = fragment.to_vec();
    tokens.push(TokenWithSpan::new(Token::EOF, end_span));
    let Ok(statements) = Parser::new(dialect)
        .with_tokens_with_locations(tokens)
        .parse_statements()
    else {
        return false;
    };
    if statements.len() != 1 {
        return false;
    }
    !closes_block
        || matches!(
            statements.first(),
            Some(Statement::If(_) | Statement::While(_) | Statement::StartTransaction { .. })
        )
}

fn has_balanced_module_blocks(tokens: &[TokenWithSpan]) -> bool {
    let mut block_depth = 0i32;
    let mut case_depth = 0i32;
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
            } else if !mssql_word_follows(tokens, index, "CONVERSATION") {
                block_depth -= 1;
                if block_depth < 0 {
                    return false;
                }
            }
        } else if word.value.eq_ignore_ascii_case("BEGIN")
            && !mssql_word_follows_any(tokens, index, MSSQL_BEGIN_NON_BLOCK_FOLLOWERS)
        {
            block_depth += 1;
        }
    }
    block_depth == 0 && case_depth == 0
}

fn adapt_inline_table_function_return(tokens: &mut Vec<TokenWithSpan>) -> bool {
    let significant = significant_token_indices(tokens);
    let functions = find_inline_table_function_returns(tokens, &significant);
    if functions.is_empty() {
        return false;
    }

    let mut insertions = Vec::with_capacity(functions.len() * 2);
    for (with_index, statement_end) in functions {
        if !has_balanced_parentheses(tokens, with_index..statement_end) {
            continue;
        }
        let Some(open_span) = point_span(tokens[with_index].span.start) else {
            continue;
        };
        let boundary = tokens
            .get(statement_end)
            .map(|token| token.span.start)
            .or_else(|| tokens.last().map(|token| token.span.end));
        let Some(close_span) = boundary.and_then(point_span) else {
            continue;
        };

        insertions.push((
            with_index,
            InsertKind::OpenParen,
            TokenWithSpan::new(Token::LParen, open_span),
        ));
        insertions.push((
            statement_end,
            InsertKind::CloseParen,
            TokenWithSpan::new(Token::RParen, close_span),
        ));
    }

    if insertions.is_empty() {
        return false;
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
        if index < tokens.len() {
            adapted.push(tokens[index].clone());
        }
    }
    *tokens = adapted;
    true
}

fn find_inline_table_function_returns(
    tokens: &[TokenWithSpan],
    significant: &[usize],
) -> Vec<(usize, usize)> {
    let mut functions = Vec::new();

    for position in 0..significant.len() {
        if position > 0 && !matches!(tokens[significant[position - 1]].token, Token::SemiColon) {
            continue;
        }

        let mut function_position = position;
        if word_is_at(tokens, significant, function_position, "CREATE") {
            function_position += 1;
            if word_is_at(tokens, significant, function_position, "OR")
                && word_is_at(tokens, significant, function_position + 1, "ALTER")
            {
                function_position += 2;
            }
        } else {
            continue;
        }

        if !word_is_at(tokens, significant, function_position, "FUNCTION") {
            continue;
        }

        let name_start = function_position + 1;
        let Some(name_end) = parse_object_name_end(tokens, significant, name_start) else {
            continue;
        };
        let Some(parameter_open) = next_significant_index(significant, name_end) else {
            continue;
        };
        if !matches!(tokens[parameter_open].token, Token::LParen) {
            continue;
        }
        let Some(parameter_close) = matching_paren(tokens, parameter_open) else {
            continue;
        };
        let Some(returns_index) = next_significant_index(significant, parameter_close) else {
            continue;
        };
        if !word_is(tokens, returns_index, "RETURNS") {
            continue;
        }
        let Some(table_index) = next_significant_index(significant, returns_index) else {
            continue;
        };
        if !word_is(tokens, table_index, "TABLE") {
            continue;
        }

        let Some((_, with_index)) = find_cte_return_after_table(tokens, significant, table_index)
        else {
            continue;
        };
        let Some(statement_end) = function_return_statement_end(tokens, with_index) else {
            continue;
        };
        functions.push((with_index, statement_end));
    }

    functions
}

fn find_cte_return_after_table(
    tokens: &[TokenWithSpan],
    significant: &[usize],
    table_index: usize,
) -> Option<(usize, usize)> {
    for &index in significant.iter().filter(|&&index| index > table_index) {
        if matches!(tokens[index].token, Token::SemiColon | Token::EOF) {
            return None;
        }
        if word_is(tokens, index, "RETURN") {
            let with_index = next_significant_index(significant, index)?;
            return word_is(tokens, with_index, "WITH").then_some((index, with_index));
        }
    }
    None
}

fn function_return_statement_end(tokens: &[TokenWithSpan], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match &token.token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.checked_sub(1)?,
            Token::SemiColon if depth == 0 => return Some(index),
            Token::EOF => return Some(index),
            _ => {}
        }
    }
    Some(tokens.len())
}

fn has_balanced_parentheses(tokens: &[TokenWithSpan], range: Range<usize>) -> bool {
    let mut depth = 0usize;
    for token in &tokens[range] {
        match &token.token {
            Token::LParen => depth += 1,
            Token::RParen => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
            }
            _ => {}
        }
    }
    depth == 0
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

fn word_is_token(token: &Token, expected: &str) -> bool {
    matches!(
        token,
        Token::Word(word)
            if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(expected)
    )
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
    fn inserts_optional_terminators_only_at_valid_mssql_module_statement_boundaries() {
        let cases = [
            (
                "-- café\r\nCREATE OR ALTER PROCEDURE dbo.synthetic_proc AS BEGIN\r\n DECLARE @value INT\r\n SELECT @value = 1\r\nEND",
                2,
            ),
            (
                "CREATE PROCEDURE dbo.synthetic_proc AS BEGIN DECLARE @value INT SET @value = 1 SELECT @value END",
                3,
            ),
        ];
        for (sql, expected_body_statements) in cases {
            let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql)
                .expect("parse semicolon-optional procedure statements");
            assert!(output.parser_fallback_used);
            let [Statement::CreateProcedure { body, .. }] = output.statements.as_slice() else {
                panic!("expected one CREATE PROCEDURE");
            };
            assert_eq!(body.statements().len(), expected_body_statements);
            assert_eq!(
                text_for_span(sql, body.span()),
                sql.get(sql.find("BEGIN").unwrap()..).unwrap(),
                "inserted punctuation must leave module body spans source-aligned"
            );
        }
    }

    #[test]
    fn repairs_optional_terminators_in_nested_mssql_control_flow_blocks() {
        let sql = concat!(
            "CREATE PROCEDURE dbo.synthetic_proc AS BEGIN ",
            "IF 1 = 1 BEGIN DECLARE @nested INT SELECT @nested = 2 END END"
        );
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql)
            .expect("parse statements within nested BEGIN blocks");
        let [Statement::CreateProcedure { body, .. }] = output.statements.as_slice() else {
            panic!("expected one CREATE PROCEDURE");
        };
        let [Statement::If(if_statement)] = body.statements().as_slice() else {
            panic!("expected one IF statement in procedure body");
        };
        let [Statement::Declare { .. }, Statement::Query(_)] =
            if_statement.if_block.statements().as_slice()
        else {
            panic!("expected DECLARE and SELECT statements in the nested block");
        };
        assert_eq!(
            text_for_span(sql, body.span()),
            sql.get(sql.find("BEGIN").unwrap()..).unwrap(),
            "nested block spans must refer to original source text"
        );
    }

    #[test]
    fn repairs_optional_terminators_in_standalone_mssql_begin_end_blocks() {
        let cases = [
            (
                "BEGIN DECLARE @value INT SELECT @value = 1 END",
                2,
                "SELECT @value = 1",
            ),
            (
                "-- café\r\nBEGIN DECLARE @value INT SELECT @value = 1 END;",
                2,
                "SELECT @value = 1",
            ),
            (
                "BEGIN DECLARE @value INT SET @value = 1 SELECT @value END",
                3,
                "SELECT @value",
            ),
        ];
        for (sql, expected_statements, expected_query_span) in cases {
            let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql)
                .expect("parse standalone BEGIN/END statements");
            assert!(output.parser_fallback_used);
            let [Statement::StartTransaction {
                statements,
                has_end_keyword: true,
                ..
            }] = output.statements.as_slice()
            else {
                panic!("expected a standalone BEGIN/END block");
            };
            assert_eq!(statements.len(), expected_statements);
            let Some(Statement::Query(query)) = statements
                .iter()
                .find(|statement| matches!(statement, Statement::Query(_)))
            else {
                panic!("expected the source SELECT statement");
            };
            assert_eq!(
                text_for_span(sql, query.span()),
                expected_query_span,
                "zero-width recovery punctuation must preserve query source spans"
            );
        }
    }

    #[test]
    fn standalone_mssql_block_recovery_handles_nested_blocks_and_comments() {
        let sql = concat!(
            "BEGIN IF 1 = 1 BEGIN DECLARE @nested INT /* gap */ ",
            "SELECT @nested = 2 END END"
        );
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql)
            .expect("parse nested standalone BEGIN/END blocks");
        let [Statement::StartTransaction { statements, .. }] = output.statements.as_slice() else {
            panic!("expected a standalone BEGIN/END block");
        };
        let [Statement::If(if_statement)] = statements.as_slice() else {
            panic!("expected one IF statement");
        };
        let [Statement::Declare { .. }, Statement::Query(query)] =
            if_statement.if_block.statements().as_slice()
        else {
            panic!("expected DECLARE and SELECT inside the nested block");
        };
        assert_eq!(
            text_for_span(sql, query.span()),
            "SELECT @nested = 2",
            "nested source spans must survive synthetic wrapper parsing"
        );
    }

    #[test]
    fn standalone_block_recovery_rejects_malformed_fragments_and_transaction_begin() {
        for sql in [
            "BEGIN DECLARE @value INT, SELECT @value = 1 END",
            "BEGIN DECLARE @value INT SELECT FROM END",
            "BEGIN DECLARE @value INT SELECT @value = 1, END",
            "BEGIN DECLARE @value INT GO SELECT @value = 1 END",
        ] {
            assert!(
                parse_sql_with_dialect_output(sql, FlowDialect::Mssql).is_err(),
                "malformed SQL or a GO-separated fragment must not be repaired: {sql}"
            );
        }

        let dialect = MsSqlDialect {};
        let transaction_tokens = Tokenizer::new(&dialect, "BEGIN TRANSACTION; SELECT 1;")
            .tokenize_with_location()
            .expect("tokenize transaction");
        assert!(
            !is_standalone_mssql_begin_end_block(&transaction_tokens),
            "transaction BEGIN must not be wrapped as a procedural block"
        );
        let transaction =
            parse_sql_with_dialect_output("BEGIN TRANSACTION; SELECT 1;", FlowDialect::Mssql)
                .expect("the primary parser should retain transaction behavior");
        assert!(!transaction.parser_fallback_used);
    }

    #[test]
    fn optional_terminator_recovery_keeps_malformed_fragments_and_go_errors() {
        for sql in [
            "CREATE PROCEDURE dbo.p AS BEGIN DECLARE @value INT, SELECT @value = 1 END",
            "CREATE PROCEDURE dbo.p AS BEGIN DECLARE @value INT SELECT FROM END",
            "CREATE PROCEDURE dbo.p AS BEGIN DECLARE @value INT SELECT @value = 1, END",
            "CREATE PROCEDURE dbo.p AS BEGIN DECLARE @value INT GO SELECT @value = 1 END",
        ] {
            assert!(
                parse_sql_with_dialect_output(sql, FlowDialect::Mssql).is_err(),
                "malformed SQL or a GO-separated fragment must not be repaired: {sql}"
            );
        }
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
    fn parses_unparenthesized_cte_return_bodies_for_mssql_inline_functions() {
        for modifier in ["CREATE", "CREATE OR ALTER"] {
            let sql = format!(
                "-- café\r\n{modifier} FUNCTION dbo.demo_fn() RETURNS TABLE AS RETURN \
                 WITH demo_cte AS (SELECT 1 AS demo_value) \
                 SELECT demo_value FROM demo_cte;\r\nSELECT 2;"
            );
            let output = parse_sql_with_dialect_output(&sql, FlowDialect::Mssql).expect("parse");

            assert!(
                output.parser_fallback_used,
                "expected token adaptation for {modifier}"
            );
            assert_eq!(output.statements.len(), 2, "{modifier}");
            let Statement::CreateFunction(function) = &output.statements[0] else {
                panic!("expected CREATE FUNCTION for {modifier}");
            };
            let Some(CreateFunctionBody::AsReturnExpr(expression)) = &function.function_body else {
                panic!("expected a RETURN expression body for {modifier}");
            };
            assert_eq!(
                text_for_span(&sql, expression.span()),
                "WITH demo_cte AS (SELECT 1 AS demo_value) SELECT demo_value FROM demo_cte",
                "{modifier}"
            );
            assert_eq!(
                text_for_span(&sql, output.statements[1].span()),
                "SELECT 2",
                "{modifier}"
            );
            assert_eq!(output.statements[1].to_string(), "SELECT 2", "{modifier}");
        }
    }

    #[test]
    fn parses_unparenthesized_cte_return_body_through_eof() {
        let sql = "CREATE FUNCTION dbo.demo_rows() RETURNS TABLE AS RETURN WITH demo_cte AS (SELECT 1 AS demo_value) SELECT demo_value FROM demo_cte";
        let output = parse_sql_with_dialect_output(sql, FlowDialect::Mssql).expect("parse");

        assert!(output.parser_fallback_used);
        assert_eq!(output.statements.len(), 1);
        let Statement::CreateFunction(function) = &output.statements[0] else {
            panic!("expected CREATE FUNCTION");
        };
        let Some(CreateFunctionBody::AsReturnExpr(expression)) = &function.function_body else {
            panic!("expected a RETURN expression body");
        };
        assert_eq!(
            text_for_span(sql, expression.span()),
            "WITH demo_cte AS (SELECT 1 AS demo_value) SELECT demo_value FROM demo_cte"
        );
    }

    #[test]
    fn malformed_unparenthesized_cte_function_returns_remain_errors_at_source_positions() {
        for sql in [
            "-- café\r\nCREATE FUNCTION dbo.bad() RETURNS TABLE AS RETURN WITH demo_cte AS SELECT 1 SELECT 1;",
            "-- café\r\nCREATE OR ALTER FUNCTION dbo.bad() RETURNS TABLE AS RETURN WITH demo_cte AS (SELECT 1);",
            "-- café\r\nCREATE OR ALTER FUNCTION dbo.bad() RETURNS TABLE AS RETURN WITH demo_cte AS (SELECT 1) SELECT FROM demo_cte;",
        ] {
            let error = parse_mssql(sql);
            assert_eq!(error.position.map(|position| position.line), Some(2));
        }
    }

    #[test]
    fn unparenthesized_cte_function_adapter_is_mssql_only() {
        let sql = "CREATE FUNCTION dbo.demo_fn() RETURNS TABLE AS RETURN WITH demo_cte AS (SELECT 1 AS demo_value) SELECT demo_value FROM demo_cte;";

        assert!(parse_sql_with_dialect_output(sql, FlowDialect::Mssql).is_ok());
        assert!(parse_sql_with_dialect_output(sql, FlowDialect::Generic).is_err());
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
