use core::any::TypeId;

use sqlparser::ast::{GranteesType, Statement};
use sqlparser::dialect::{Dialect, MsSqlDialect};
use sqlparser::keywords::Keyword;
use sqlparser::parser::{Parser, ParserError};

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

    fn get_next_precedence(&self, parser: &Parser) -> Option<Result<u8, ParserError>> {
        self.0.get_next_precedence(parser)
    }

    fn is_reserved_for_identifier(&self, kw: Keyword) -> bool {
        MSSQL_RESERVED_FOR_IDENTIFIER.contains(&kw)
    }
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
    use super::*;

    #[test]
    fn reserved_keyword_set_matches_mssql_not_generic_sql_keywords() {
        let dialect = MssqlParserDialect::default();
        let dialect: &dyn Dialect = &dialect;

        assert!(dialect.is::<MsSqlDialect>());
        assert!(!dialect.is_reserved_for_identifier(Keyword::TRIM));
        assert!(!dialect.is_reserved_for_identifier(Keyword::SUBSTRING));
        assert!(dialect.is_reserved_for_identifier(Keyword::EXISTS));
        assert!(dialect.is_reserved_for_identifier(Keyword::SELECT));
    }
}
