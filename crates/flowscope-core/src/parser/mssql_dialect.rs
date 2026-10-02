use core::any::TypeId;

use sqlparser::ast::{Expr, GranteesType, ObjectName, Statement};
use sqlparser::dialect::{Dialect, MsSqlDialect, Precedence};
use sqlparser::keywords::Keyword;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::Token;

#[derive(Debug, Default)]
pub(super) struct MssqlParserDialect(MsSqlDialect);

impl Dialect for MssqlParserDialect {
    fn dialect(&self) -> TypeId {
        self.0.dialect()
    }

    fn is_delimited_identifier_start(&self, ch: char) -> bool {
        self.0.is_delimited_identifier_start(ch)
    }

    fn is_identifier_start(&self, ch: char) -> bool {
        self.0.is_identifier_start(ch)
    }

    fn is_identifier_part(&self, ch: char) -> bool {
        self.0.is_identifier_part(ch)
    }

    fn identifier_quote_style(&self, identifier: &str) -> Option<char> {
        self.0.identifier_quote_style(identifier)
    }

    fn convert_type_before_value(&self) -> bool {
        self.0.convert_type_before_value()
    }

    fn supports_outer_join_operator(&self) -> bool {
        self.0.supports_outer_join_operator()
    }

    fn supports_left_associative_joins_without_parens(&self) -> bool {
        self.0.supports_left_associative_joins_without_parens()
    }

    fn supports_create_table_column_definition_trailing_commas(&self) -> bool {
        self.0
            .supports_create_table_column_definition_trailing_commas()
    }

    fn supports_connect_by(&self) -> bool {
        self.0.supports_connect_by()
    }

    fn supports_eq_alias_assignment(&self) -> bool {
        self.0.supports_eq_alias_assignment()
    }

    fn supports_try_convert(&self) -> bool {
        self.0.supports_try_convert()
    }

    fn supports_boolean_literals(&self) -> bool {
        self.0.supports_boolean_literals()
    }

    fn supports_named_fn_args_with_colon_operator(&self) -> bool {
        self.0.supports_named_fn_args_with_colon_operator()
    }

    fn supports_named_fn_args_with_expr_name(&self) -> bool {
        self.0.supports_named_fn_args_with_expr_name()
    }

    fn supports_named_fn_args_with_rarrow_operator(&self) -> bool {
        self.0.supports_named_fn_args_with_rarrow_operator()
    }

    fn supports_start_transaction_modifier(&self) -> bool {
        self.0.supports_start_transaction_modifier()
    }

    fn supports_end_transaction_modifier(&self) -> bool {
        self.0.supports_end_transaction_modifier()
    }

    fn supports_set_stmt_without_operator(&self) -> bool {
        self.0.supports_set_stmt_without_operator()
    }

    fn supports_table_versioning(&self) -> bool {
        self.0.supports_table_versioning()
    }

    fn supports_nested_comments(&self) -> bool {
        self.0.supports_nested_comments()
    }

    fn supports_object_name_double_dot_notation(&self) -> bool {
        self.0.supports_object_name_double_dot_notation()
    }

    fn get_reserved_grantees_types(&self) -> &[GranteesType] {
        self.0.get_reserved_grantees_types()
    }

    fn is_select_item_alias(&self, explicit: bool, kw: &Keyword, parser: &mut Parser) -> bool {
        self.0.is_select_item_alias(explicit, kw, parser)
    }

    fn is_table_factor_alias(&self, explicit: bool, kw: &Keyword, parser: &mut Parser) -> bool {
        self.0.is_table_factor_alias(explicit, kw, parser)
    }

    fn parse_statement(&self, parser: &mut Parser) -> Option<Result<Statement, ParserError>> {
        self.0.parse_statement(parser)
    }

    fn parse_prefix(&self, parser: &mut Parser) -> Option<Result<Expr, ParserError>> {
        let is_try_parse = match &parser.peek_token_ref().token {
            Token::Word(word)
                if word.quote_style.is_none() && word.value.eq_ignore_ascii_case("TRY_PARSE") =>
            {
                matches!(&parser.peek_nth_token_ref(1).token, Token::LParen)
            }
            _ => false,
        };

        if is_try_parse {
            Some(parse_try_parse(parser))
        } else if let Some(prefix) = parse_nonreserved_mssql_keyword(parser) {
            Some(prefix)
        } else {
            self.0.parse_prefix(parser)
        }
    }

    fn parse_infix(
        &self,
        parser: &mut Parser,
        expr: &Expr,
        precedence: u8,
    ) -> Option<Result<Expr, ParserError>> {
        if parser.parse_keyword(Keyword::COLLATE) {
            Some(
                parser
                    .parse_object_name(false)
                    .map(|collation| Expr::Collate {
                        expr: Box::new(expr.clone()),
                        collation,
                    }),
            )
        } else {
            self.0.parse_infix(parser, expr, precedence)
        }
    }

    fn get_next_precedence(&self, parser: &Parser) -> Option<Result<u8, ParserError>> {
        match parser.peek_token().token {
            Token::Word(word) if word.keyword == Keyword::COLLATE => {
                Some(Ok(self.0.prec_value(Precedence::DoubleColon)))
            }
            _ => self.0.get_next_precedence(parser),
        }
    }

    fn is_reserved_for_identifier(&self, kw: Keyword) -> bool {
        MSSQL_RESERVED_FOR_IDENTIFIER.contains(&kw)
    }
}

// Keep generic prefix grammars from reinterpreting T-SQL identifiers as other-dialect literals.
fn parse_nonreserved_mssql_keyword(parser: &mut Parser) -> Option<Result<Expr, ParserError>> {
    let Token::Word(word) = &parser.peek_token_ref().token else {
        return None;
    };
    if word.quote_style.is_none() && word.keyword == Keyword::PRIOR {
        return if is_prior_operand_start(&parser.peek_nth_token_ref(1).token) {
            None
        } else {
            Some(parser.parse_identifier().map(Expr::Identifier))
        };
    }

    if word.quote_style.is_some()
        || word.keyword == Keyword::NoKeyword
        || MSSQL_RESERVED_FOR_IDENTIFIER.contains(&word.keyword)
    {
        return None;
    }

    let keyword = word.keyword;
    let next_token = &parser.peek_nth_token_ref(1).token;
    if matches!(next_token, Token::Period) {
        return Some(parser.parse_identifier().map(Expr::Identifier));
    }

    if matches!(next_token, Token::LParen) && is_mssql_special_parenthesized_prefix(keyword) {
        return None;
    }

    if matches!(next_token, Token::LParen) {
        return Some(
            parser
                .parse_identifier()
                .and_then(|identifier| parser.parse_function(ObjectName::from(vec![identifier]))),
        );
    }

    Some(parser.parse_identifier().map(Expr::Identifier))
}

fn is_prior_operand_start(token: &Token) -> bool {
    match token {
        Token::Word(word) if word.quote_style.is_none() => !matches!(
            word.keyword,
            Keyword::AS
                | Keyword::FROM
                | Keyword::WHERE
                | Keyword::GROUP
                | Keyword::HAVING
                | Keyword::ORDER
                | Keyword::UNION
                | Keyword::INTERSECT
                | Keyword::EXCEPT
                | Keyword::INTO
                | Keyword::FETCH
                | Keyword::FOR
                | Keyword::OPTION
                | Keyword::JOIN
                | Keyword::ON
                | Keyword::AND
                | Keyword::OR
                | Keyword::IS
                | Keyword::LIKE
                | Keyword::IN
                | Keyword::BETWEEN
                | Keyword::COLLATE
                | Keyword::WHEN
                | Keyword::THEN
                | Keyword::ELSE
                | Keyword::END
        ),
        Token::Word(_)
        | Token::Number(..)
        | Token::SingleQuotedString(..)
        | Token::DoubleQuotedString(..)
        | Token::NationalStringLiteral(..)
        | Token::HexStringLiteral(..)
        | Token::LParen
        | Token::Plus
        | Token::Minus
        | Token::Tilde
        | Token::AtSign
        | Token::Placeholder(..) => true,
        _ => false,
    }
}

fn is_mssql_special_parenthesized_prefix(keyword: Keyword) -> bool {
    // Preserve dedicated AST parsing for supported T-SQL parenthesized forms.
    matches!(
        keyword,
        Keyword::CAST
            | Keyword::CEIL
            | Keyword::FLOOR
            | Keyword::SUBSTRING
            | Keyword::TRIM
            | Keyword::TRY_CAST
    )
}

fn parse_try_parse(parser: &mut Parser) -> Result<Expr, ParserError> {
    parser.next_token();
    parser.expect_token(&Token::LParen)?;
    let expr = parser.parse_expr()?;
    parser.expect_keyword_is(Keyword::AS)?;
    let data_type = parser.parse_data_type()?;
    let culture = if parser.parse_keyword(Keyword::USING) {
        Some(Box::new(parser.parse_expr()?))
    } else {
        None
    };
    parser.expect_token(&Token::RParen)?;

    Ok(Expr::TryParse {
        expr: Box::new(expr),
        data_type,
        culture,
    })
}

// Microsoft Learn's Transact-SQL reserved-keyword list, limited to keywords
// represented by sqlparser 0.61. The hook cannot distinguish reserved words
// that sqlparser does not represent in its Keyword enum.
// This uses the T-SQL list, not Microsoft's separate ODBC compatibility list.
// https://learn.microsoft.com/en-us/sql/t-sql/language-elements/reserved-keywords-transact-sql
const MSSQL_RESERVED_FOR_IDENTIFIER: &[Keyword] = &[
    Keyword::ADD,
    Keyword::ALL,
    Keyword::ALTER,
    Keyword::AND,
    Keyword::ANY,
    Keyword::AS,
    Keyword::ASC,
    Keyword::AUTHORIZATION,
    Keyword::BEGIN,
    Keyword::BETWEEN,
    Keyword::BROWSE,
    Keyword::BY,
    Keyword::CASCADE,
    Keyword::CASE,
    Keyword::CHECK,
    Keyword::CLOSE,
    Keyword::CLUSTERED,
    Keyword::COALESCE,
    Keyword::COLLATE,
    Keyword::COLUMN,
    Keyword::COMMIT,
    Keyword::COMPUTE,
    Keyword::CONSTRAINT,
    Keyword::CONTAINS,
    Keyword::CONTINUE,
    Keyword::CONVERT,
    Keyword::CREATE,
    Keyword::CROSS,
    Keyword::CURRENT,
    Keyword::CURRENT_DATE,
    Keyword::CURRENT_TIME,
    Keyword::CURRENT_TIMESTAMP,
    Keyword::CURRENT_USER,
    Keyword::CURSOR,
    Keyword::DATABASE,
    Keyword::DEALLOCATE,
    Keyword::DECLARE,
    Keyword::DEFAULT,
    Keyword::DELETE,
    Keyword::DENY,
    Keyword::DESC,
    Keyword::DISTINCT,
    Keyword::DOUBLE,
    Keyword::DROP,
    Keyword::ELSE,
    Keyword::END,
    Keyword::ESCAPE,
    Keyword::EXCEPT,
    Keyword::EXEC,
    Keyword::EXECUTE,
    Keyword::EXISTS,
    Keyword::EXTERNAL,
    Keyword::FETCH,
    Keyword::FILE,
    Keyword::FOR,
    Keyword::FOREIGN,
    Keyword::FROM,
    Keyword::FULL,
    Keyword::FUNCTION,
    Keyword::GRANT,
    Keyword::GROUP,
    Keyword::HAVING,
    Keyword::IDENTITY,
    Keyword::IDENTITY_INSERT,
    Keyword::IF,
    Keyword::IN,
    Keyword::INDEX,
    Keyword::INNER,
    Keyword::INSERT,
    Keyword::INTERSECT,
    Keyword::INTO,
    Keyword::IS,
    Keyword::JOIN,
    Keyword::KEY,
    Keyword::KILL,
    Keyword::LEFT,
    Keyword::LIKE,
    Keyword::LOAD,
    Keyword::MERGE,
    Keyword::NATIONAL,
    Keyword::NOT,
    Keyword::NULL,
    Keyword::NULLIF,
    Keyword::OF,
    Keyword::OFF,
    Keyword::OFFSETS,
    Keyword::ON,
    Keyword::OPEN,
    Keyword::OPTION,
    Keyword::OR,
    Keyword::ORDER,
    Keyword::OUTER,
    Keyword::OVER,
    Keyword::PERCENT,
    Keyword::PIVOT,
    Keyword::PLAN,
    Keyword::PRECISION,
    Keyword::PRIMARY,
    Keyword::PRINT,
    Keyword::PROCEDURE,
    Keyword::PUBLIC,
    Keyword::RAISERROR,
    Keyword::READ,
    Keyword::REFERENCES,
    Keyword::REPLICATION,
    Keyword::RESTRICT,
    Keyword::RETURN,
    Keyword::REVOKE,
    Keyword::RIGHT,
    Keyword::ROLLBACK,
    Keyword::RULE,
    Keyword::SCHEMA,
    Keyword::SELECT,
    Keyword::SESSION_USER,
    Keyword::SET,
    Keyword::SOME,
    Keyword::STATISTICS,
    Keyword::SYSTEM_USER,
    Keyword::TABLE,
    Keyword::TABLESAMPLE,
    Keyword::THEN,
    Keyword::TO,
    Keyword::TOP,
    Keyword::TRANSACTION,
    Keyword::TRIGGER,
    Keyword::TRUNCATE,
    Keyword::TRY_CONVERT,
    Keyword::UNION,
    Keyword::UNIQUE,
    Keyword::UNPIVOT,
    Keyword::UPDATE,
    Keyword::USE,
    Keyword::USER,
    Keyword::VALUES,
    Keyword::VARYING,
    Keyword::VIEW,
    Keyword::WHEN,
    Keyword::WHERE,
    Keyword::WHILE,
    Keyword::WITH,
    Keyword::WITHIN,
];

#[cfg(test)]
mod tests {
    use core::ops::ControlFlow;

    use super::*;
    use sqlparser::ast::{
        visit_expressions, BinaryOperator, CastKind, ConnectByKind, Expr, SelectItem, SetExpr,
        Spanned, Statement,
    };
    use sqlparser::dialect::GenericDialect;
    use sqlparser::tokenizer::Location;

    #[test]
    fn wrapper_forwards_mssql_join_and_table_column_capabilities() {
        let dialect = MssqlParserDialect::default();
        assert!(!dialect.supports_left_associative_joins_without_parens());
        assert!(dialect.supports_create_table_column_definition_trailing_commas());
    }

    #[test]
    fn reserved_keyword_set_matches_mssql_not_generic_sql_keywords() {
        let dialect = MssqlParserDialect::default();
        let dialect: &dyn Dialect = &dialect;

        assert!(dialect.is::<MsSqlDialect>());
        assert!(!dialect.is_reserved_for_identifier(Keyword::TRIM));
        assert!(!dialect.is_reserved_for_identifier(Keyword::SUBSTRING));
        assert!(!dialect.is_reserved_for_identifier(Keyword::CAST));
        assert!(dialect.is_reserved_for_identifier(Keyword::EXISTS));
        assert!(dialect.is_reserved_for_identifier(Keyword::SELECT));
    }

    #[test]
    fn mssql_collate_binds_before_comparison_and_preserves_span() {
        let dialect = MssqlParserDialect::default();
        let sql = "SELECT t.demo_value FROM dbo.synthetic_table AS t WHERE t.demo_value COLLATE Latin1_General_100_CI_AS = N'demo'";
        let statements = Parser::parse_sql(&dialect, sql).expect("MSSQL COLLATE predicate");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        let Some(Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right: _,
        }) = &select.selection
        else {
            panic!("expected equality predicate");
        };
        let Expr::Collate { expr, collation } = left.as_ref() else {
            panic!("expected COLLATE on the comparison's left operand");
        };
        assert!(matches!(expr.as_ref(), Expr::CompoundIdentifier(_)));
        assert_eq!(collation.to_string(), "Latin1_General_100_CI_AS");

        let collated_source = "t.demo_value COLLATE Latin1_General_100_CI_AS";
        let start = sql.find(collated_source).unwrap() as u64 + 1;
        let end = sql.find(" = N'demo'").unwrap() as u64 + 1;
        assert_eq!(left.span().start, Location::new(1, start));
        assert_eq!(left.span().end, Location::new(1, end));
    }

    #[test]
    fn mssql_collate_precedence_is_isolated_from_generic_dialect() {
        let mssql = MssqlParserDialect::default();
        let sql = "SELECT a + b COLLATE Latin1_General_100_CI_AS = c";
        let statements = Parser::parse_sql(&mssql, sql).expect("MSSQL COLLATE precedence");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        let sqlparser::ast::SelectItem::UnnamedExpr(Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            ..
        }) = &select.projection[0]
        else {
            panic!("expected comparison in projection");
        };
        let Expr::BinaryOp {
            left: _,
            op: BinaryOperator::Plus,
            right,
        } = left.as_ref()
        else {
            panic!("expected addition before comparison");
        };
        assert!(matches!(right.as_ref(), Expr::Collate { .. }));

        let generic = GenericDialect {};
        let mssql_parser = Parser::new(&mssql)
            .try_with_sql("COLLATE Latin1_General_100_CI_AS")
            .unwrap();
        let generic_parser = Parser::new(&generic)
            .try_with_sql("COLLATE Latin1_General_100_CI_AS")
            .unwrap();
        let mssql_precedence = mssql.get_next_precedence_default(&mssql_parser).unwrap();
        let generic_precedence = generic
            .get_next_precedence_default(&generic_parser)
            .unwrap();
        assert_eq!(generic_precedence, generic.prec_unknown());
        assert!(mssql_precedence > generic_precedence);

        assert!(Parser::parse_sql(
            &generic,
            "SELECT t.demo_value COLLATE Latin1_General_100_CI_AS = N'demo'"
        )
        .is_err());
    }

    #[test]
    fn mssql_collate_requires_a_collation_name() {
        let dialect = MssqlParserDialect::default();

        assert!(Parser::parse_sql(&dialect, "SELECT t.demo_value COLLATE").is_err());
        assert!(Parser::parse_sql(&dialect, "SELECT t.demo_value COLLATE = N'demo'").is_err());
    }

    #[test]
    fn native_mssql_interval_prefix_baseline_reproduces_public_failure() {
        let dialect = MsSqlDialect {};
        assert!(
            Parser::parse_sql(&dialect, "SELECT INTERVAL FROM dbo.synthetic_table").is_err(),
            "the pinned generic prefix parser consumes FROM as an INTERVAL value"
        );
    }

    #[test]
    fn mssql_nonreserved_prefix_preserves_connect_by_prior_support() {
        let dialect = MssqlParserDialect::default();
        assert!(dialect.supports_connect_by());

        let statements = Parser::parse_sql(&dialect, "SELECT PRIOR FROM dbo.synthetic_table")
            .expect("bare PRIOR column before FROM");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::Identifier(identifier))
                if identifier.value.eq_ignore_ascii_case("PRIOR")
        ));

        let statements = Parser::parse_sql(&dialect, "SELECT PRIOR + 1 FROM dbo.synthetic_table")
            .expect("PRIOR identifier in an operator expression");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::BinaryOp {
                left,
                op: BinaryOperator::Plus,
                ..
            }) if matches!(left.as_ref(), Expr::Identifier(identifier)
                if identifier.value.eq_ignore_ascii_case("PRIOR"))
        ));

        let statements = Parser::parse_sql(
            &dialect,
            "SELECT employee_id FROM employees CONNECT BY PRIOR employee_id = manager_id",
        )
        .expect("the forwarded MSSQL CONNECT BY parser feature");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        let Some(ConnectByKind::ConnectBy { relationships, .. }) = select.connect_by.first() else {
            panic!("expected a CONNECT BY clause");
        };
        let [Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        }] = relationships.as_slice()
        else {
            panic!("expected a single equality relationship");
        };
        assert!(matches!(
            left.as_ref(),
            Expr::Prior(expr)
                if matches!(expr.as_ref(), Expr::Identifier(identifier)
                    if identifier.value.eq_ignore_ascii_case("employee_id"))
        ));
        assert!(matches!(
            right.as_ref(),
            Expr::Identifier(identifier) if identifier.value.eq_ignore_ascii_case("manager_id")
        ));
    }

    #[test]
    fn mssql_nonreserved_keywords_remain_identifiers_in_bare_expression_positions() {
        let dialect = MssqlParserDialect::default();
        for keyword in ["INTERVAL", "TRIM", "SUBSTRING", "DATE", "TRY_PARSE"] {
            let sql =
                format!("SELECT {keyword} /* expression boundary */ FROM dbo.synthétic_table");
            let statements =
                Parser::parse_sql(&dialect, &sql).expect("non-reserved keyword column");
            let [Statement::Query(query)] = statements.as_slice() else {
                panic!("expected one query statement");
            };
            let SetExpr::Select(select) = query.body.as_ref() else {
                panic!("expected a SELECT query");
            };
            assert!(matches!(
                &select.projection[0],
                SelectItem::UnnamedExpr(Expr::Identifier(identifier))
                    if identifier.value.eq_ignore_ascii_case(keyword)
            ));
        }

        let statements = Parser::parse_sql(
            &dialect,
            "SELECT INTERVAL AS interval_alias, INTERVAL implicit_alias FROM dbo.synthetic_table",
        )
        .expect("explicit and implicit aliases after bare keyword identifiers");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        for (projection, expected_alias) in select
            .projection
            .iter()
            .zip(["interval_alias", "implicit_alias"])
        {
            assert!(matches!(
                projection,
                SelectItem::ExprWithAlias {
                    expr: Expr::Identifier(identifier),
                    alias,
                } if identifier.value.eq_ignore_ascii_case("INTERVAL")
                    && alias.value.eq_ignore_ascii_case(expected_alias)
            ));
        }

        let statements = Parser::parse_sql(
            &dialect,
            "SELECT DATE 'date_alias' FROM dbo.synthetic_table",
        )
        .expect("DATE column with a T-SQL single-quoted alias");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::ExprWithAlias {
                expr: Expr::Identifier(identifier),
                alias,
            } if identifier.value.eq_ignore_ascii_case("DATE")
                && alias.value == "date_alias"
                && alias.quote_style == Some('\'')
        ));

        let statements = Parser::parse_sql(
            &dialect,
            "SELECT INTERVAL.demo_value FROM dbo.synthetic_table",
        )
        .expect("qualified non-reserved keyword column");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts))
                if parts[0].value.eq_ignore_ascii_case("INTERVAL")
        ));

        let statements =
            Parser::parse_sql(&dialect, "SELECT INTERVAL + 1 * 2 FROM dbo.synthetic_table")
                .expect("non-reserved keyword as a binary expression");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        let SelectItem::UnnamedExpr(Expr::BinaryOp {
            left,
            op: BinaryOperator::Plus,
            right,
        }) = &select.projection[0]
        else {
            panic!("expected addition with the keyword identifier on the left");
        };
        assert!(matches!(
            left.as_ref(),
            Expr::Identifier(identifier) if identifier.value.eq_ignore_ascii_case("INTERVAL")
        ));
        assert!(matches!(
            right.as_ref(),
            Expr::BinaryOp {
                op: BinaryOperator::Multiply,
                ..
            }
        ));

        let statements = Parser::parse_sql(
            &dialect,
            "SELECT demo_value FROM dbo.synthetic_table WHERE INTERVAL IS NULL",
        )
        .expect("bare keyword in a predicate");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.selection,
            Some(Expr::IsNull(expr))
                if matches!(expr.as_ref(), Expr::Identifier(identifier)
                    if identifier.value.eq_ignore_ascii_case("INTERVAL"))
        ));
    }

    #[test]
    fn mssql_nonreserved_keyword_policy_preserves_functions_and_rejects_malformed_sql() {
        let dialect = MssqlParserDialect::default();
        let statements = Parser::parse_sql(
            &dialect,
            "SELECT CURRENT_TIMESTAMP, TRIM(N' x '), SUBSTRING(N'abc', 1, 2), TRY_CAST(N'1' AS INT), FLOOR(1.2), INTERVAL(N'1') FROM dbo.synthetic_table",
        )
        .expect("valid T-SQL function forms");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::Function(_))
        ));
        assert!(matches!(
            &select.projection[1],
            SelectItem::UnnamedExpr(Expr::Trim { .. })
        ));
        assert!(matches!(
            &select.projection[2],
            SelectItem::UnnamedExpr(Expr::Substring { .. })
        ));
        assert!(matches!(
            &select.projection[3],
            SelectItem::UnnamedExpr(Expr::Cast { .. })
        ));
        assert!(matches!(
            &select.projection[4],
            SelectItem::UnnamedExpr(Expr::Floor { .. })
        ));
        assert!(matches!(
            &select.projection[5],
            SelectItem::UnnamedExpr(Expr::Function(_))
        ));

        for sql in [
            "SELECT INTERVAL FROM",
            "SELECT INTERVAL FROM dbo.",
            "SELECT INTERVAL COLLATE = N'demo'",
            "SELECT INTERVAL '1' DAY FROM dbo.synthetic_table",
            "SELECT CASE FROM dbo.synthetic_table",
        ] {
            assert!(Parser::parse_sql(&dialect, sql).is_err(), "accepted {sql}");
        }
    }

    #[test]
    fn mssql_cast_and_convert_prefixes_preserve_target_types() {
        let dialect = MssqlParserDialect::default();
        let statements = Parser::parse_sql(
            &dialect,
            "SELECT CAST(N'1' AS INT), CONVERT(INT, N'1'), TRY_CAST(N'1' AS INT), TRY_CONVERT(INT, N'1')",
        )
        .expect("T-SQL CAST and CONVERT forms");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::Cast {
                kind: CastKind::Cast,
                data_type,
                ..
            }) if data_type.to_string() == "INT"
        ));
        assert!(matches!(
            &select.projection[1],
            SelectItem::UnnamedExpr(Expr::Convert {
                is_try: false,
                data_type: Some(data_type),
                target_before_value: true,
                ..
            }) if data_type.to_string() == "INT"
        ));
        assert!(matches!(
            &select.projection[2],
            SelectItem::UnnamedExpr(Expr::Cast {
                kind: CastKind::TryCast,
                data_type,
                ..
            }) if data_type.to_string() == "INT"
        ));
        assert!(matches!(
            &select.projection[3],
            SelectItem::UnnamedExpr(Expr::Convert {
                is_try: true,
                data_type: Some(data_type),
                target_before_value: true,
                ..
            }) if data_type.to_string() == "INT"
        ));
    }

    #[test]
    fn mssql_try_parse_treats_bare_nonreserved_keywords_as_input_and_culture_identifiers() {
        let dialect = MssqlParserDialect::default();
        let statements =
            Parser::parse_sql(&dialect, "SELECT TRY_PARSE(INTERVAL AS DATE USING DATE)")
                .expect("bare nonreserved keywords in TRY_PARSE expression children");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        let SelectItem::UnnamedExpr(Expr::TryParse {
            expr,
            culture: Some(culture),
            ..
        }) = &select.projection[0]
        else {
            panic!("expected TRY_PARSE with culture");
        };
        assert!(matches!(
            expr.as_ref(),
            Expr::Identifier(identifier) if identifier.value.eq_ignore_ascii_case("INTERVAL")
        ));
        assert!(matches!(
            culture.as_ref(),
            Expr::Identifier(identifier) if identifier.value.eq_ignore_ascii_case("DATE")
        ));
    }

    #[test]
    fn mssql_nonreserved_keyword_policy_is_isolated_from_generic_prefixes() {
        let generic = GenericDialect {};
        assert!(
            Parser::parse_sql(&generic, "SELECT INTERVAL FROM dbo.synthetic_table").is_err(),
            "generic dialect retains its existing INTERVAL prefix behavior"
        );

        let statements = Parser::parse_sql(&generic, "SELECT INTERVAL '1' DAY")
            .expect("generic INTERVAL literal");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::Interval(_))
        ));

        let statements = Parser::parse_sql(&generic, "SELECT DATE 'date_alias'")
            .expect("generic dialect retains typed string literals");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::TypedString(_))
        ));
    }

    #[test]
    fn mssql_try_parse_preserves_type_culture_display_and_span() {
        let dialect = MssqlParserDialect::default();
        let sql = "CREATE OR ALTER VIEW dbo.synthetic_view AS SELECT TRY_PARSE(N'2024-01-02' AS DATETIME USING N'en-US') AS parsed_value";
        let statements = Parser::parse_sql(&dialect, sql).expect("MSSQL TRY_PARSE view");
        let [Statement::CreateView(view)] = statements.as_slice() else {
            panic!("expected one CREATE VIEW statement");
        };
        let SetExpr::Select(select) = view.query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        let SelectItem::ExprWithAlias { expr, alias } = &select.projection[0] else {
            panic!("expected an aliased TRY_PARSE expression");
        };
        assert_eq!(alias.value, "parsed_value");
        let Expr::TryParse {
            expr: input,
            data_type,
            culture: Some(culture),
        } = expr
        else {
            panic!("expected a typed TRY_PARSE AST node with culture");
        };
        assert_eq!(input.to_string(), "N'2024-01-02'");
        assert_eq!(data_type.to_string(), "DATETIME");
        assert_eq!(culture.to_string(), "N'en-US'");
        assert_eq!(
            expr.to_string(),
            "TRY_PARSE(N'2024-01-02' AS DATETIME USING N'en-US')"
        );
        assert_eq!(expr.span().start, input.span().start);
        assert_eq!(expr.span().end, culture.span().end);

        let input_start = sql.find("N'2024-01-02'").unwrap() as u64 + 1;
        assert_eq!(expr.span().start, Location::new(1, input_start));
    }

    #[test]
    fn mssql_try_parse_supports_optional_culture_and_visits_expression_children() {
        let dialect = MssqlParserDialect::default();
        let statements = Parser::parse_sql(
            &dialect,
            "SELECT TRY_PARSE(source_value AS DATETIME USING culture_value), TRY_PARSE('2024-01-02' AS DATE)",
        )
        .expect("MSSQL TRY_PARSE expressions");
        let mut visited_identifiers = Vec::new();
        let traversal = visit_expressions(&statements, |expr| {
            if let Expr::Identifier(identifier) = expr {
                visited_identifiers.push(identifier.value.clone());
            }
            ControlFlow::<()>::Continue(())
        });
        assert!(matches!(traversal, ControlFlow::Continue(())));

        assert!(visited_identifiers.contains(&"source_value".to_string()));
        assert!(visited_identifiers.contains(&"culture_value".to_string()));

        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        let SelectItem::UnnamedExpr(Expr::TryParse { culture, .. }) = &select.projection[1] else {
            panic!("expected a TRY_PARSE expression without culture");
        };
        assert!(culture.is_none());
    }

    #[test]
    fn mssql_try_parse_rejects_malformed_grammar() {
        let dialect = MssqlParserDialect::default();

        for sql in [
            "SELECT TRY_PARSE(N'value' DATETIME)",
            "SELECT TRY_PARSE(N'value' AS)",
            "SELECT TRY_PARSE(N'value' AS DATETIME USING)",
            "SELECT TRY_PARSE(N'value' AS DATETIME USING N'en-US'",
        ] {
            assert!(Parser::parse_sql(&dialect, sql).is_err(), "accepted {sql}");
        }
    }

    #[test]
    fn mssql_try_parse_syntax_is_isolated_from_generic_dialect() {
        let generic = GenericDialect {};
        let statements = Parser::parse_sql(&generic, "SELECT TRY_PARSE(N'value')")
            .expect("generic function syntax remains valid");
        let [Statement::Query(query)] = statements.as_slice() else {
            panic!("expected one query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected a SELECT query");
        };
        assert!(matches!(
            &select.projection[0],
            SelectItem::UnnamedExpr(Expr::Function(_))
        ));
        assert!(Parser::parse_sql(
            &generic,
            "SELECT TRY_PARSE(N'value' AS DATETIME USING N'en-US')"
        )
        .is_err());
    }
}
