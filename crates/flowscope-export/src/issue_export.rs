use flowscope_core::{
    types::{LintConfidence, LintEngine, LintFallbackSource},
    AnalyzeResult, Issue, IssueAutofixApplicability, Severity,
};

pub(crate) const ISSUE_HEADERS: [&str; 14] = [
    "Severity",
    "Code",
    "Message",
    "Statement",
    "Span Start",
    "Span End",
    "Source Name",
    "SQLFluff Name",
    "Lint Engine",
    "Lint Confidence",
    "Lint Fallback Source",
    "Autofix Applicability",
    "Autofix Edit Count",
    "Autofix JSON",
];

#[derive(Debug, Clone)]
pub(crate) struct IssueExportRow {
    pub(crate) severity: &'static str,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) statement: String,
    pub(crate) span_start: String,
    pub(crate) span_end: String,
    pub(crate) source_name: String,
    pub(crate) sqlfluff_name: String,
    pub(crate) lint_engine: String,
    pub(crate) lint_confidence: String,
    pub(crate) lint_fallback_source: String,
    pub(crate) autofix_applicability: String,
    pub(crate) autofix_edit_count: String,
    pub(crate) autofix_json: String,
}

pub(crate) fn issue_rows(result: &AnalyzeResult) -> Vec<IssueExportRow> {
    result
        .issues
        .iter()
        .map(|issue| issue_row(result, issue))
        .collect()
}

fn issue_row(result: &AnalyzeResult, issue: &Issue) -> IssueExportRow {
    let statement = issue.statement_index.map(|index| index.to_string());
    let source_name = issue
        .source_name
        .clone()
        .or_else(|| {
            issue.statement_index.and_then(|index| {
                result
                    .statements
                    .iter()
                    .find(|statement| statement.statement_index == index)
                    .and_then(|statement| statement.source_name.clone())
            })
        })
        .unwrap_or_default();
    let (span_start, span_end) = issue
        .span
        .map(|span| (span.start.to_string(), span.end.to_string()))
        .unwrap_or_default();
    let (autofix_applicability, autofix_edit_count, autofix_json) = issue
        .autofix
        .as_ref()
        .map(|autofix| {
            (
                autofix_applicability(autofix.applicability).to_string(),
                autofix.edits.len().to_string(),
                serde_json::to_string(autofix).unwrap_or_default(),
            )
        })
        .unwrap_or_default();

    IssueExportRow {
        severity: severity(issue.severity),
        code: issue.code.clone(),
        message: issue.message.clone(),
        statement: statement.unwrap_or_default(),
        span_start,
        span_end,
        source_name,
        sqlfluff_name: issue.sqlfluff_name.clone().unwrap_or_default(),
        lint_engine: issue
            .lint_engine
            .map(lint_engine)
            .unwrap_or_default()
            .to_string(),
        lint_confidence: issue
            .lint_confidence
            .map(lint_confidence)
            .unwrap_or_default()
            .to_string(),
        lint_fallback_source: issue
            .lint_fallback_source
            .map(lint_fallback_source)
            .unwrap_or_default()
            .to_string(),
        autofix_applicability,
        autofix_edit_count,
        autofix_json,
    }
}

fn severity(value: Severity) -> &'static str {
    match value {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

fn lint_engine(value: LintEngine) -> &'static str {
    match value {
        LintEngine::Semantic => "semantic",
        LintEngine::Lexical => "lexical",
        LintEngine::Document => "document",
    }
}

fn lint_confidence(value: LintConfidence) -> &'static str {
    match value {
        LintConfidence::High => "high",
        LintConfidence::Medium => "medium",
        LintConfidence::Low => "low",
    }
}

fn lint_fallback_source(value: LintFallbackSource) -> &'static str {
    match value {
        LintFallbackSource::ParserFallback => "parser_fallback",
        LintFallbackSource::TokenizerFallback => "tokenizer_fallback",
        LintFallbackSource::HeuristicRule => "heuristic_rule",
    }
}

fn autofix_applicability(value: IssueAutofixApplicability) -> &'static str {
    match value {
        IssueAutofixApplicability::Safe => "safe",
        IssueAutofixApplicability::Unsafe => "unsafe",
        IssueAutofixApplicability::DisplayOnly => "displayOnly",
    }
}
