use sqlparser::ast::{Merge, Statement, TableFactor, Update};

pub fn extract_tables(statements: &[Statement]) -> Vec<String> {
    let mut tables = Vec::new();

    for statement in statements {
        match statement {
            Statement::Query(query) => {
                extract_tables_from_query_body(&query.body, &mut tables);
            }
            Statement::Insert(insert) => {
                tables.push(insert.table.to_string());
                if let Some(source) = &insert.source {
                    extract_tables_from_query_body(&source.body, &mut tables);
                }
            }
            Statement::Update(Update { table, from, .. }) => {
                extract_tables_from_table_factor(&table.relation, &mut tables);
                for join in &table.joins {
                    extract_tables_from_table_factor(&join.relation, &mut tables);
                }

                if let Some(from_kind) = from {
                    match from_kind {
                        sqlparser::ast::UpdateTableFromKind::BeforeSet(ts)
                        | sqlparser::ast::UpdateTableFromKind::AfterSet(ts) => {
                            for t in ts {
                                extract_tables_from_table_factor(&t.relation, &mut tables);
                                for join in &t.joins {
                                    extract_tables_from_table_factor(&join.relation, &mut tables);
                                }
                            }
                        }
                    }
                }
            }
            Statement::Delete(delete) => {
                for obj in &delete.tables {
                    tables.push(obj.to_string());
                }

                let from_tables = match &delete.from {
                    sqlparser::ast::FromTable::WithFromKeyword(ts)
                    | sqlparser::ast::FromTable::WithoutKeyword(ts) => ts,
                };

                for t in from_tables {
                    extract_tables_from_table_factor(&t.relation, &mut tables);
                    for join in &t.joins {
                        extract_tables_from_table_factor(&join.relation, &mut tables);
                    }
                }

                if let Some(using) = &delete.using {
                    for t in using {
                        extract_tables_from_table_factor(&t.relation, &mut tables);
                        for join in &t.joins {
                            extract_tables_from_table_factor(&join.relation, &mut tables);
                        }
                    }
                }
            }
            Statement::Merge(Merge { table, source, .. }) => {
                extract_tables_from_table_factor(table, &mut tables);
                extract_tables_from_table_factor(source, &mut tables);
            }
            _ => {}
        }
    }

    tables
}

fn extract_tables_from_query_body(body: &sqlparser::ast::SetExpr, tables: &mut Vec<String>) {
    use sqlparser::ast::SetExpr;

    match body {
        SetExpr::Select(select) => {
            for table_with_joins in &select.from {
                extract_tables_from_table_factor(&table_with_joins.relation, tables);

                for join in &table_with_joins.joins {
                    extract_tables_from_table_factor(&join.relation, tables);
                }
            }
        }
        SetExpr::Query(query) => {
            extract_tables_from_query_body(&query.body, tables);
        }
        SetExpr::SetOperation { left, right, .. } => {
            extract_tables_from_query_body(left, tables);
            extract_tables_from_query_body(right, tables);
        }
        SetExpr::Values(_) => {}
        SetExpr::Insert(stmt) => {
            if let sqlparser::ast::Statement::Insert(insert) = stmt {
                tables.push(insert.table.to_string());
                if let Some(source) = &insert.source {
                    extract_tables_from_query_body(&source.body, tables);
                }
            }
        }
        SetExpr::Update(stmt) => {
            if let sqlparser::ast::Statement::Update(Update { table, from, .. }) = stmt {
                extract_tables_from_table_factor(&table.relation, tables);
                for join in &table.joins {
                    extract_tables_from_table_factor(&join.relation, tables);
                }

                if let Some(from_kind) = from {
                    match from_kind {
                        sqlparser::ast::UpdateTableFromKind::BeforeSet(ts)
                        | sqlparser::ast::UpdateTableFromKind::AfterSet(ts) => {
                            for t in ts {
                                extract_tables_from_table_factor(&t.relation, tables);
                                for join in &t.joins {
                                    extract_tables_from_table_factor(&join.relation, tables);
                                }
                            }
                        }
                    }
                }
            }
        }
        SetExpr::Table(table) => {
            if let Some(name) = &table.table_name {
                tables.push(name.clone());
            }
        }
        SetExpr::Delete(stmt) => {
            if let sqlparser::ast::Statement::Delete(delete) = stmt {
                for obj in &delete.tables {
                    tables.push(obj.to_string());
                }

                let from_tables = match &delete.from {
                    sqlparser::ast::FromTable::WithFromKeyword(ts)
                    | sqlparser::ast::FromTable::WithoutKeyword(ts) => ts,
                };

                for t in from_tables {
                    extract_tables_from_table_factor(&t.relation, tables);
                    for join in &t.joins {
                        extract_tables_from_table_factor(&join.relation, tables);
                    }
                }

                if let Some(using) = &delete.using {
                    for t in using {
                        extract_tables_from_table_factor(&t.relation, tables);
                        for join in &t.joins {
                            extract_tables_from_table_factor(&join.relation, tables);
                        }
                    }
                }
            }
        }
        SetExpr::Merge(stmt) => {
            if let sqlparser::ast::Statement::Merge(Merge { table, source, .. }) = stmt {
                extract_tables_from_table_factor(table, tables);
                extract_tables_from_table_factor(source, tables);
            }
        }
    }
}

fn extract_tables_from_table_factor(table_factor: &TableFactor, tables: &mut Vec<String>) {
    match table_factor {
        TableFactor::Table { name, .. } => {
            tables.push(name.to_string());
        }
        TableFactor::Derived { subquery, .. } => {
            extract_tables_from_query_body(&subquery.body, tables);
        }
        TableFactor::TableFunction { .. } => {}
        TableFactor::Function { .. } => {}
        TableFactor::UNNEST { .. } => {}
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            extract_tables_from_table_factor(&table_with_joins.relation, tables);
            for join in &table_with_joins.joins {
                extract_tables_from_table_factor(&join.relation, tables);
            }
        }
        TableFactor::Pivot { .. } => {}
        TableFactor::Unpivot { .. } => {}
        TableFactor::MatchRecognize { .. } => {}
        TableFactor::JsonTable { .. } => {}
        TableFactor::OpenJsonTable { json_expr, .. } => {
            extract_tables_from_expr(json_expr, tables);
        }
        // TODO: Implement table extraction for XMLTABLE
        TableFactor::XmlTable { passing, .. } => {
            for argument in &passing.arguments {
                extract_tables_from_expr(&argument.expr, tables);
            }
        }
        // TODO: Implement table extraction for semantic views
        TableFactor::SemanticView { .. } => {}
    }
}

fn extract_tables_from_expr(expr: &sqlparser::ast::Expr, tables: &mut Vec<String>) {
    use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, FunctionArguments};

    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() > 1 => {
            tables.push(
                parts[..parts.len() - 1]
                    .iter()
                    .map(|ident| ident.value.clone())
                    .collect::<Vec<_>>()
                    .join("."),
            );
        }
        Expr::Function(function) => {
            if let FunctionArguments::List(arguments) = &function.args {
                for argument in &arguments.args {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) = argument {
                        extract_tables_from_expr(argument, tables);
                    }
                }
            }
        }
        Expr::Nested(inner) => extract_tables_from_expr(inner, tables),
        Expr::Subquery(query) => extract_tables_from_query_body(&query.body, tables),
        Expr::BinaryOp { left, right, .. } => {
            extract_tables_from_expr(left, tables);
            extract_tables_from_expr(right, tables);
        }
        Expr::UnaryOp { expr, .. } => extract_tables_from_expr(expr, tables),
        Expr::Cast { expr, .. } => extract_tables_from_expr(expr, tables),
        Expr::Extract { expr, .. } => extract_tables_from_expr(expr, tables),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(operand) = operand {
                extract_tables_from_expr(operand, tables);
            }
            for condition in conditions {
                extract_tables_from_expr(&condition.condition, tables);
                extract_tables_from_expr(&condition.result, tables);
            }
            if let Some(else_result) = else_result {
                extract_tables_from_expr(else_result, tables);
            }
        }
        Expr::Exists { subquery, .. } => extract_tables_from_query_body(&subquery.body, tables),
        Expr::InSubquery { subquery, expr, .. } => {
            extract_tables_from_expr(expr, tables);
            extract_tables_from_query_body(&subquery.body, tables);
        }
        _ => {
            // Literals and expression forms without nested SQL relations do not
            // contribute table names to the legacy extractor.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;

    #[test]
    fn test_extract_single_table() {
        let sql = "SELECT * FROM users";
        let statements = parse_sql(sql).unwrap();
        let tables = extract_tables(&statements);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0], "users");
    }

    #[test]
    fn test_extract_multiple_tables_join() {
        let sql = "SELECT * FROM users JOIN orders ON users.id = orders.user_id";
        let statements = parse_sql(sql).unwrap();
        let tables = extract_tables(&statements);
        assert_eq!(tables.len(), 2);
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"orders".to_string()));
    }

    #[test]
    fn test_extract_with_schema() {
        let sql = "SELECT * FROM public.users";
        let statements = parse_sql(sql).unwrap();
        let tables = extract_tables(&statements);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0], "public.users");
    }

    #[test]
    fn test_extract_delete() {
        // DELETE FROM users WHERE id = 1
        let sql = "DELETE FROM users WHERE id = 1";
        let statements = parse_sql(sql).unwrap();
        let tables = extract_tables(&statements);
        // Currently expected to fail until implemented
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0], "users");
    }

    #[test]
    fn test_extract_merge() {
        // MERGE INTO target t USING source s ON t.id = s.id ...
        let sql = "MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.val = s.val";
        let statements = parse_sql(sql).unwrap();
        let tables = extract_tables(&statements);
        // Currently expected to fail until implemented
        assert_eq!(tables.len(), 2);
        assert!(tables.contains(&"target".to_string()));
        assert!(tables.contains(&"source".to_string()));
    }
}
