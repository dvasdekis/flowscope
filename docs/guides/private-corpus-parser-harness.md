# Private corpus parser harness

This opt-in harness supports parser-coverage work ([#24](https://github.com/dvasdekis/flowscope/issues/24)), with bounded acceptance in [#14](https://github.com/dvasdekis/flowscope/issues/14), per-file classification in [#15](https://github.com/dvasdekis/flowscope/issues/15), and diagnostics to help address parser gaps in [#21](https://github.com/dvasdekis/flowscope/issues/21). It measures parsing only: it does not run analysis, lineage extraction, linting, or autofixes.

## Privacy and safety

- Use only an authorized, external checkout. The corpus root must be outside and non-overlapping with the FlowScope workspace.
- Pin the checkout by supplying its full Git commit ID. The harness requires `HEAD` to match and reads immutable blob objects from that commit, not working-tree file contents. Git replacement refs and lazy fetching are disabled so object substitution cannot change the snapshot and partial clones cannot fetch or mutate checkout state during a run.
- Child Git commands clear inherited repository/object-store redirection, route inherited trace output (including packfile tracing) to the OS null device, and suppress stderr, preventing accidental access through another object store or path-bearing Git trace files.
- Inventory comes exclusively from the pinned Git tree and includes tracked `.sql` blobs only. Tree records are streamed in Git's deterministic tree order; duplicate worktree files, untracked files, and local edits cannot alter the snapshot.
- Only regular-file `.sql` blobs are accepted; tracked SQL symlink entries are rejected. Inventory record/path bytes, file count, per-file bytes, total SQL bytes, manifest bytes, and concurrent parser workers are all bounded.
- The runner never prints source SQL, ASTs, repository paths, filenames, or formatted parser diagnostics. Its output contains the pinned commit, aggregate per-file dialect and input-class counts, file/byte/successfully-parsed-statement totals, parse/input-error counts, parser fallback counts, observed UTF-8 BOM count, error-kind totals, elapsed time, and periodic aggregate progress only. A parser-error file can still contribute counts for independently parsed valid statements; the file remains a parser error.
- Per-file parser diagnostics are disabled by default. To explicitly authorize a separate private report, set `FLOWSCOPE_SQL_CORPUS_PRIVATE_REPORT` to an absolute path in an existing owner-only directory outside both the FlowScope workspace and corpus checkout. The report is created exclusively with mode `0600`; existing files are never overwritten, partial reports are removed on ordinary failures, and the run fails closed if the filesystem cannot enforce restrictive permissions. This output is supported only on Unix.
- The optional JSONL report has one record per parser-error file: relative Git path, dialect, first error kind/message and position in the original file, plus a message-truncation flag. It does not include an absolute path or a separate SQL-source field, but parser messages can quote an offending token; treat the report as sensitive. Messages are capped at 4 KiB and the report at 64 MiB. The report path, contents, and diagnostics are never printed.
- A required version-1 JSON classification manifest is supplied through `FLOWSCOPE_SQL_CORPUS_MANIFEST`. Keep this target-specific manifest outside the FlowScope workspace. Its `expected_commit` must match the pinned checkout, and its `files` array must match every tracked `.sql` Git path exactly once. Paths, manifest contents, and detailed records are never printed.
- Every manifest file record explicitly declares its `dialect`, `input_class` (`standalone_sql`, `batch_script`, or `intentional_fragment`), `artifact_class` (`authored`, `generated`, or `unknown`), `encoding` (`utf8`, `utf8_bom`, or `unknown`), marker review statuses, `batch_context`, `preprocessing` list, and optional private `classification_reason`. A nonempty reason is required for intentional fragments, unknown artifacts/encodings, present or unreviewed markers, and external context requirements; the reason is never printed. BOM presence must agree with the declared encoding; BOM bytes are not stripped. Marker status values are `reviewed_present`, `reviewed_absent`, and `unreviewed`; context values are `none`, `mssql_go_batches`, and `external_context_required`.
- Marker statuses are reviewed inventory assertions supplied by the private manifest author. The harness does not claim that parser success proves markers absent, does not echo marker values, and does not automatically substitute SQLCMD, Flyway, or Jinja/dbt content.
- The runner currently accepts only an empty `preprocessing` list and parses the committed UTF-8 bytes unchanged. It does not guess SQLCMD/Flyway/Jinja substitutions, inject surrounding context, normalize encodings, or perform custom batch rewrites; `batch_script` inputs use the dialect-aware splitter described below. This no-op preprocessing policy preserves original UTF-8 byte offsets by identity; any future transformation must first be justified by an authorized inventory and add tested source-offset mapping. An `unknown` encoding is counted as an input error, separately from parser errors, and is not silently skipped.
- For an entry classified as `batch_script`, the parse-only runner uses FlowScope's dialect-aware statement splitter. MSSQL `GO` must be alone on a line (optional positive repeat count, trailing `--` or same-line `/* ... */` comments); the splitter ignores `GO` text inside strings and comments, preserves original byte ranges (repeated statements share their original range), and bounds `GO n` expansion to 1,000 repetitions per separator, 100,000 expanded statement ranges, and 100,000 separators. A split-limit failure is counted as an input error. Empty batches produce no synthetic statement. MSSQL also permits omitting semicolons for most statements in the current engine version ([Microsoft syntax conventions](https://learn.microsoft.com/en-us/sql/t-sql/language-elements/transact-sql-syntax-conventions-transact-sql?view=sql-server-ver17)); FlowScope recognizes a bounded set of top-level statement starts on a new line only when the preceding slice parses as one complete MSSQL statement. It parses each resulting slice independently, so malformed fragments remain errors. Other dialects keep the existing splitter. This is statement splitting, not SQLCMD variable substitution.
- `standalone_sql` entries are parsed as one input buffer and are not split on MSSQL `GO`; only `batch_script` applies GO boundaries. If a standalone parse fails, the statement total may be recovered from independently parsed statement ranges; MSSQL recovery is skipped when its ranges would reinterpret a `GO` boundary. The file still counts as one parser error. The harness uses `analyzer::parse_only_sql_with_dialect_output`, and analysis shares its underlying statement parser helper. That shared path applies the Synapse `OPENROWSET ... WITH (...)` compatibility adapter and validates the supported metadata-only MSSQL DDL subsets: `CREATE EXTERNAL FILE FORMAT`, typed `CREATE EXTERNAL TABLE` without `AS SELECT`, and `IF NOT EXISTS (SELECT ...)` guarding one `CREATE EXTERNAL FILE FORMAT` statement, either bare or inside `BEGIN`/`END`. Both guarded forms validate their `SELECT` and body rather than skipping control flow or inferring lineage; `ELSE` branches are unsupported and remain errors. Valid metadata DDL counts as one parsed statement without running analysis or lint; malformed options, conditions, and bodies remain parser errors with their original error kind and diagnostic when available. Batch-script diagnostic positions are mapped from each parsed range back to the original source file. Non-MSSQL dialects do not use these MSSQL adapters.
- `batch_context: "mssql_go_batches"` is valid only with `dialect: "mssql"` and `input_class: "batch_script"`; inconsistent combinations fail closed. A `batch_script` can use the splitter for any supported dialect, while only MSSQL interprets `GO`.
- Classification totals (dialects, input/artifact classes, reviewed marker presence, batch-context needs) are aggregate-only. A run still attempts every classified supported-encoding blob, including generated inputs and intentional fragments; classification never suppresses parse errors.
- The corpus is read-only from the harness. Do not upload raw terminal logs if your environment treats the commit ID or aggregate metrics as restricted.

## Run

Provide the checkout root, its full commit ID, and a target-specific manifest. Declare the dialect for each tracked SQL path in that manifest:

```sh
FLOWSCOPE_SQL_CORPUS_DIR=/absolute/path/to/authorized/checkout \
FLOWSCOPE_SQL_CORPUS_COMMIT=<full-git-commit-id> \
FLOWSCOPE_SQL_CORPUS_MANIFEST=/absolute/path/to/private/classification.json \
just private-corpus-parse
```

The manifest shape is strict (unknown fields and unsupported schema versions are rejected). A synthetic example is:

```json
{
	"schema_version": 1,
	"expected_commit": "<full-git-commit-id>",
	"files": [
		{
			"path": "example.sql",
			"dialect": "mssql",
			"input_class": "batch_script",
			"artifact_class": "authored",
			"encoding": "utf8",
			"markers": {
				"sqlcmd_variables": "reviewed_absent",
				"flyway_placeholders": "reviewed_absent",
				"jinja_dbt_markers": "reviewed_absent"
			},
			"batch_context": "mssql_go_batches",
			"preprocessing": [],
			"classification_reason": null
		}
	]
}
```

Do not copy this example into a target-specific manifest in this repository. `unknown` artifact/encoding classifications and `unreviewed` marker states remain visible in aggregate output; they are not interpreted as absent or as permission to drop files. Unsupported preprocessing entries reject the run rather than being silently ignored.

The ignored integration test is skipped by normal test runs. It runs only through this explicit command (or an equivalent `cargo test ... -- --ignored --nocapture` invocation).

## Public synthetic regression coverage

The private corpus is not used in public tests. The coverage gate in [#22](https://github.com/dvasdekis/flowscope/issues/22) keeps each supported grammar change testable independently:

| Construct | Synthetic regression location |
| --- | --- |
| MSSQL `GO` boundaries, comments, malformed repeats, original byte ranges, and non-MSSQL behavior (#16) | `crates/flowscope-core/src/analyzer/input.rs` (`mssql_statement_ranges_*`, `mssql_go_*`, `non_mssql_statement_splitting_*`); `crates/flowscope-core/src/analyzer/tests.rs` (`split_statements_reports_mssql_repeat_expansion_limit`) |
| Procedural block recovery, nested control flow, malformed blocks, and later statements (#17) | `crates/flowscope-core/src/analyzer/input.rs` (`collect_statements_mssql_*`) |
| MSSQL module headers, parameter declarations, and `CREATE OR ALTER VIEW` source diagnostics (#18) | `crates/flowscope-core/src/parser/mssql_module.rs` |
| Inline table-valued function `RETURN WITH ... SELECT ...` bodies without outer parentheses, including EOF without a final semicolon, malformed returns, original source spans, and non-MSSQL isolation | `crates/flowscope-core/src/parser/mssql_module.rs` (`parses_unparenthesized_cte_return_bodies_for_mssql_inline_functions`, `parses_unparenthesized_cte_return_body_through_eof`, `malformed_unparenthesized_cte_function_returns_remain_errors_at_source_positions`, `unparenthesized_cte_function_adapter_is_mssql_only`) |
| MSSQL nonreserved special-expression keywords used as identifiers, unchanged function expressions, malformed/reserved expressions, AST spans, and non-MSSQL isolation | `crates/flowscope-core/src/parser/mod.rs` (`test_mssql_nonreserved_trim_identifier_preserves_ast_and_span`, `test_mssql_other_nonreserved_special_keyword_falls_back_to_identifier`, `test_mssql_trim_function_and_literal_forms_remain_special_expressions`, `test_mssql_reserved_special_expression_does_not_fall_back_to_identifier`, `test_mssql_malformed_trim_expression_still_fails`, `test_non_mssql_trim_keyword_behavior_is_unchanged`); `crates/flowscope-core/src/parser/mssql_dialect.rs` |
| External file-format metadata DDL, invalid options, and metadata-only lineage behavior (#19) | `crates/flowscope-core/src/analyzer/external_metadata.rs`; `crates/flowscope-core/src/analyzer/input.rs` |
| Guarded `CREATE EXTERNAL FILE FORMAT` under `IF NOT EXISTS (SELECT ...)`, with a single bare or `BEGIN`/`END` body, including condition/body validation, malformed guards, `ELSE` rejection, and comments/strings | `crates/flowscope-core/src/analyzer/external_metadata.rs`; `crates/flowscope-core/src/analyzer/input.rs` |
| Typed Synapse `CREATE EXTERNAL TABLE ... WITH (LOCATION, DATA_SOURCE, FILE_FORMAT)` without `AS SELECT`, malformed column/options, original source ranges, and explicit unsupported-file-lineage behavior | `crates/flowscope-core/src/analyzer/external_metadata.rs`; `crates/flowscope-core/src/analyzer/input.rs` |
| Synapse `OPENROWSET` options (`ROWSET_OPTIONS`, CSV options, and `DELTA`), parenthesized `BULK` file lists, multiple rowsets, schema declarations and `COLLATE`, malformed variants, source spans, and unsupported external-file lineage (#20) | `crates/flowscope-core/src/analyzer/input.rs` (`mssql_*openrowset*`); `crates/flowscope-core/src/analyzer/tests.rs` (`synapse_openrowset_*`) |
| MSSQL semicolon-optional newline boundaries, including `EXEC`/`DROP VIEW`, `BEGIN`/`SET`, and `WHILE`/`SET`, plus comments/strings, malformed fragments, and unchanged non-MSSQL splitting | `crates/flowscope-core/src/analyzer/input.rs` (`mssql_statement_ranges_recognize_optional_newline_separators`, `mssql_optional_statement_*`) |
| Narrow Synapse CETAS grammar, including the optional name-only output-column list before `WITH`, is validated and reported metadata-only; it must not produce table or file-write lineage | `crates/flowscope-core/src/analyzer/external_metadata.rs`; `crates/flowscope-core/src/analyzer/input.rs` (`synapse_cetas_parses_with_an_explicit_unsupported_lineage_warning`, `synapse_cetas_optional_output_columns_use_parse_only_validation`) |
| Parser-only corpus accounting and classification (#14–#15) | `crates/flowscope-core/tests/private_corpus_parse.rs` (non-ignored synthetic repository tests) |

The native CLI and WASM entry points also have synthetic tests in `crates/flowscope-cli/tests/synapse_cli.rs` and `crates/flowscope-wasm/tests/analysis.rs`. These tests check parsing and original-source behavior, not a claim that remote files or dynamic SQL have lineage.

MSSQL identifier fallback uses Microsoft's T-SQL reserved-keyword list rather than sqlparser's cross-dialect keyword policy. The independent synthetic reproducer `SELECT 1 WHERE TRIM = 'demo';` exercises a nonreserved spelling that sqlparser initially treats as a special expression. The dialect permits identifier fallback after that expression fails to parse; it does not rewrite source text or introduce token-specific exceptions. Function expressions and reserved-keyword failures retain focused regressions. The hook can classify only spellings represented in sqlparser's `Keyword` enum, so this is not a comprehensive reserved-word validator. Passing synthetic tests alone does not establish that the previously measured private predicate failures are resolved; those require remeasurement against the pinned corpus.

The pattern regressions are synthetic examples, not an approved full-corpus acceptance baseline. CETAS support is intentionally limited to a one-to-three-part target name, an optional one-or-more output-column **name** list before `WITH`, the required options in documented order (`LOCATION`, `DATA_SOURCE`, `FILE_FORMAT`), and exactly one parsed `SELECT` after `AS`. Microsoft documents the optional list as `column_name [,...n]` and explicitly disallows column definitions such as data types, collation, and nullability; the Synapse CETAS guide directs dedicated SQL pool to that syntax and serverless SQL pool to it for complete syntax. Reject options and typed definitions remain outside this adapter. Even for accepted syntax, external-table and file-write lineage are not modeled, and analysis emits an unsupported-lineage warning instead of inventing dataflow. See [Microsoft's CETAS Transact-SQL syntax](https://learn.microsoft.com/en-us/sql/t-sql/statements/create-external-table-as-select-transact-sql?view=azure-sqldw-latest) and [Synapse CETAS guidance](https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/develop-tables-cetas).

Microsoft's Synapse `OPENROWSET` syntax lists optional `DATA_SOURCE` before required `FORMAT`; the Serverless SQL pool owner also confirmed that `DATA_SOURCE` after `FORMAT` is accepted. The adapter accepts either placement while still requiring `FORMAT` and rejecting duplicate options, malformed values, and unknown arguments. Microsoft also documents the parenthesized `BULK ('path1', 'path2')` form in its [multiple-CSV-files example](https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/query-folders-multiple-csv-files). The adapter recognizes this literal-list form, including a single-item list, while rejecting empty, trailing-comma, and malformed lists. It accepts the documented `COLLATE` option on declared rowset columns while retaining their parsed data types. These narrow MSSQL-only adaptations preserve source-byte positions; external file paths remain unsupported lineage and do not become table nodes.

The external-table adapter validates the typed column list through the MSSQL `CREATE TABLE` parser and accepts only the required options in `LOCATION`, `DATA_SOURCE`, `FILE_FORMAT` order. This subset has no column or table constraints. It classifies the DDL as metadata-only and emits an explicit unsupported-lineage warning; it does not add an external table or file node. The guarded file-format adapter validates the `IF NOT EXISTS` query and a single supported metadata DDL body, either bare or enclosed by `BEGIN`/`END`, while retaining the complete conditional source span. `ELSE` branches, additional body statements, and malformed bodies remain parser errors. These additions cover only the listed forms; additional external-table options or other external metadata constructs remain outside this parser subset.

Per-file diagnostics are opt-in. When they are authorized, additionally set:

```sh
FLOWSCOPE_SQL_CORPUS_PRIVATE_REPORT=/absolute/path/in/an-owner-only-directory/parser-diagnostics.jsonl
```

The directory must already exist and allow only its owner access; the report path must not overlap the workspace or corpus. Choose this destination only when your environment approves storing parser messages there.

To run the synthetic pinned-repository tests without accessing the external corpus, use:

```sh
cargo test -p flowscope-core --test private_corpus_parse
```

This runs the non-ignored synthetic tests and leaves the external-corpus test skipped.

## Resource limits

Defaults are 10,000 tracked files, 10 MiB per file, 100 MiB total input, and four workers. The configurable environment variables are:

- `FLOWSCOPE_SQL_CORPUS_MAX_FILES` (hard maximum: 100,000)
- `FLOWSCOPE_SQL_CORPUS_MAX_FILE_BYTES` (hard maximum: 10 MiB)
- `FLOWSCOPE_SQL_CORPUS_MAX_TOTAL_BYTES` (hard maximum: 512 MiB)
- `FLOWSCOPE_SQL_CORPUS_WORKERS` (hard maximum: 16)

Limits must be positive integers. Git inventory output is capped at 32 MiB, individual paths at 16 KiB, the JSON manifest at 4 MiB, and the optional private report at 64 MiB. Input is read one file at a time per worker and each worker's AST is discarded immediately after aggregate counts are collected. Parse failures are measurements, not harness failures; setup, inventory, and resource-limit violations stop the run with a generic message that does not disclose a path or parser diagnostic.
