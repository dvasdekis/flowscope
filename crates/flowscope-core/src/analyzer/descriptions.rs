//! Extracts plain-text descriptions from SQL comment constructs and applies
//! them to the corresponding lineage nodes.
//!
//! Three sources are recognized — all structured SQL, all plain text:
//! - `COMMENT ON TABLE <name> IS '...'`
//! - `COMMENT ON COLUMN <path>.<col> IS '...'`
//! - Inline `CREATE TABLE` column-level and table-level `COMMENT '...'` clauses
//!
//! Free-form `--` / `/* */` SQL comments are intentionally out of scope:
//! sqlparser discards them during parsing and associating them with nodes
//! would require a separate tokenizer pass with proximity heuristics.

use std::collections::HashMap;
use std::sync::Arc;

use sqlparser::ast::{
    ColumnOption, CommentDef, CommentObject, CreateTable, CreateTableOptions, ObjectName,
    SqlOption, Statement,
};

use super::input::{StatementInput, StatementInputKind};
use super::Analyzer;
use crate::types::{Edge, EdgeType, Node, NodeType};

/// Identifies a table or column targetable by a SQL comment.
///
/// `table_canonical` is the analyzer's canonicalized form so `customers`
/// and `public.customers` only collide when they resolve to the same
/// table in the current search path.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct DescriptionKey {
    pub(crate) table_canonical: String,
    pub(crate) column: Option<String>,
}

impl DescriptionKey {
    fn table(canonical: String) -> Self {
        Self {
            table_canonical: canonical,
            column: None,
        }
    }
    fn column(canonical: String, column: String) -> Self {
        Self {
            table_canonical: canonical,
            column: Some(column),
        }
    }
}

impl<'a> Analyzer<'a> {
    /// Build the `(target → description)` map from structured SQL comments.
    ///
    /// Called during DDL pre-collection so the map is populated before any
    /// per-statement lineage analysis runs.
    pub(crate) fn collect_description_map(
        &self,
        statements: &[StatementInput],
    ) -> HashMap<DescriptionKey, Arc<str>> {
        let mut map: HashMap<DescriptionKey, Arc<str>> = HashMap::new();

        for input in statements {
            let StatementInputKind::Parsed(statement) = &input.statement else {
                continue;
            };
            match statement.as_ref() {
                Statement::Comment {
                    object_type,
                    object_name,
                    comment,
                    ..
                } => {
                    self.record_comment_statement(
                        &mut map,
                        *object_type,
                        object_name,
                        comment.as_deref(),
                    );
                }
                Statement::CreateTable(ct) => {
                    self.record_create_table_comments(&mut map, ct);
                }
                _ => {}
            }
        }

        map
    }

    fn record_comment_statement(
        &self,
        map: &mut HashMap<DescriptionKey, Arc<str>>,
        object_type: CommentObject,
        object_name: &ObjectName,
        text: Option<&str>,
    ) {
        match object_type {
            CommentObject::Table => {
                let path = object_name.to_string();
                let resolution = self.canonicalize_table_reference(&path);
                set_description(map, DescriptionKey::table(resolution.canonical), text);
            }
            CommentObject::Column => {
                let Some((table_path, column)) = split_column_target(object_name) else {
                    return;
                };
                let resolution = self.canonicalize_table_reference(&table_path);
                let column_norm = self.normalize_identifier(&column);
                set_description(
                    map,
                    DescriptionKey::column(resolution.canonical, column_norm),
                    text,
                );
            }
            // Schema / Extension / other targets are not surfaced on nodes.
            _ => {}
        }
    }

    fn record_create_table_comments(
        &self,
        map: &mut HashMap<DescriptionKey, Arc<str>>,
        ct: &CreateTable,
    ) {
        let table_path = ct.name.to_string();
        let resolution = self.canonicalize_table_reference(&table_path);
        let table_canonical = resolution.canonical;

        if let Some(text) = table_level_comment(ct) {
            set_description(
                map,
                DescriptionKey::table(table_canonical.clone()),
                Some(text),
            );
        }

        for column in &ct.columns {
            for option in &column.options {
                if let ColumnOption::Comment(text) = &option.option {
                    let column_name = self.normalize_identifier(&column.name.value);
                    set_description(
                        map,
                        DescriptionKey::column(table_canonical.clone(), column_name),
                        Some(text),
                    );
                }
            }
        }
    }

    /// Write the collected descriptions onto matching flat-graph nodes.
    ///
    /// Column nodes are matched by walking Ownership edges back to a
    /// table/view node whose canonical path matches a description key.
    pub(crate) fn apply_descriptions(&self, nodes: &mut [Node], edges: &[Edge]) {
        if self.descriptions.is_empty() {
            return;
        }

        let mut table_canonical: HashMap<Arc<str>, String> = HashMap::new();
        for node in nodes.iter() {
            if matches!(node.node_type, NodeType::Table | NodeType::View) {
                let path = node
                    .qualified_name
                    .as_deref()
                    .unwrap_or_else(|| node.label.as_ref());
                let resolution = self.canonicalize_table_reference(path);
                table_canonical.insert(node.id.clone(), resolution.canonical);
            }
        }

        let mut column_owner: HashMap<Arc<str>, String> = HashMap::new();
        for edge in edges {
            if edge.edge_type == EdgeType::Ownership {
                if let Some(owner) = table_canonical.get(&edge.from) {
                    column_owner.insert(edge.to.clone(), owner.clone());
                }
            }
        }

        for node in nodes.iter_mut() {
            if node.description.is_some() {
                continue;
            }
            match node.node_type {
                NodeType::Table | NodeType::View => {
                    let Some(canonical) = table_canonical.get(&node.id) else {
                        continue;
                    };
                    let key = DescriptionKey::table(canonical.clone());
                    if let Some(desc) = self.descriptions.get(&key) {
                        node.description = Some(desc.clone());
                    }
                }
                NodeType::Column => {
                    let Some(owner) = column_owner.get(&node.id) else {
                        continue;
                    };
                    let column_norm = self.normalize_identifier(node.label.as_ref());
                    let key = DescriptionKey::column(owner.clone(), column_norm);
                    if let Some(desc) = self.descriptions.get(&key) {
                        node.description = Some(desc.clone());
                    }
                }
                _ => {}
            }
        }
    }
}

/// Applies a structured SQL description in source order.
///
/// Later statements win. `NULL` or blank comments remove any prior value so the
/// graph reflects the last visible description in the script.
fn set_description(
    map: &mut HashMap<DescriptionKey, Arc<str>>,
    key: DescriptionKey,
    text: Option<&str>,
) {
    match text.map(str::trim).filter(|text| !text.is_empty()) {
        Some(trimmed) => {
            map.insert(key, Arc::from(trimmed));
        }
        None => {
            map.remove(&key);
        }
    }
}

fn split_column_target(name: &ObjectName) -> Option<(String, String)> {
    if name.0.len() < 2 {
        return None;
    }
    let parts: Vec<String> = name.0.iter().map(|part| part.to_string()).collect();
    let column = parts.last()?.clone();
    let table_path = parts[..parts.len() - 1].join(".");
    Some((table_path, column))
}

fn table_level_comment(ct: &CreateTable) -> Option<&str> {
    if let Some(comment) = ct.comment.as_ref() {
        return Some(comment_def_text(comment));
    }

    let CreateTableOptions::Plain(options) = &ct.table_options else {
        return None;
    };

    for option in options {
        if let SqlOption::Comment(def) = option {
            return Some(comment_def_text(def));
        }
    }

    None
}

fn comment_def_text(def: &CommentDef) -> &str {
    match def {
        CommentDef::WithEq(text) | CommentDef::WithoutEq(text) => text.as_str(),
    }
}
