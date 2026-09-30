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
- For an entry classified as `batch_script`, the parse-only runner uses FlowScope's dialect-aware statement splitter. MSSQL `GO` must be alone on a line (optional positive repeat count, trailing `--` or same-line `/* ... */` comments); the splitter ignores `GO` text inside strings and comments, preserves original byte ranges (repeated statements share their original range), and bounds `GO n` expansion to 1,000 repetitions per separator, 100,000 expanded statement ranges, and 100,000 separators. A split-limit failure is counted as an input error. Empty batches produce no synthetic statement. This is statement splitting, not SQLCMD variable substitution.
- `standalone_sql` entries are parsed as one input buffer and are not split on MSSQL `GO`; only `batch_script` applies GO boundaries. If a standalone parse fails, the statement total may be recovered from independently parsed statement ranges; MSSQL recovery is skipped when its ranges would reinterpret a `GO` boundary. The file still counts as one parser error. The harness uses `analyzer::parse_only_sql_with_dialect_output`, and analysis shares its underlying statement parser helper. That shared path applies the Synapse `OPENROWSET ... WITH (...)` compatibility adapter and validates supported `CREATE EXTERNAL FILE FORMAT` metadata DDL. Valid metadata DDL counts as one parsed statement without running analysis or lint; malformed options remain parser errors with their original error kind and diagnostic when available. Batch-script diagnostic positions are mapped from each parsed range back to the original source file. Non-MSSQL dialects do not use these MSSQL adapters.
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
| External file-format metadata DDL, invalid options, and metadata-only lineage behavior (#19) | `crates/flowscope-core/src/analyzer/external_metadata.rs`; `crates/flowscope-core/src/analyzer/input.rs` |
| Synapse `OPENROWSET` options (`ROWSET_OPTIONS`, CSV options, and `DELTA`), multiple rowsets, schema declarations, malformed variants, source spans, and unsupported external-file lineage (#20) | `crates/flowscope-core/src/analyzer/input.rs` (`mssql_*openrowset*`); `crates/flowscope-core/src/analyzer/tests.rs` (`synapse_openrowset_*`) |
| Narrow Synapse CETAS grammar (`CREATE EXTERNAL TABLE name WITH (LOCATION = '...', DATA_SOURCE = name, FILE_FORMAT = name) AS SELECT ...`) is validated and reported metadata-only; it must not produce table or file-write lineage | `crates/flowscope-core/src/analyzer/external_metadata.rs`; `crates/flowscope-core/src/analyzer/input.rs` (`synapse_cetas_parses_with_an_explicit_unsupported_lineage_warning`) |
| Parser-only corpus accounting and classification (#14–#15) | `crates/flowscope-core/tests/private_corpus_parse.rs` (non-ignored synthetic repository tests) |

The native CLI and WASM entry points also have synthetic tests in `crates/flowscope-cli/tests/synapse_cli.rs` and `crates/flowscope-wasm/tests/analysis.rs`. These tests check parsing and original-source behavior, not a claim that remote files or dynamic SQL have lineage.

The pattern regressions are synthetic examples, not an approved full-corpus acceptance baseline. CETAS support is intentionally limited to a one-to-three-part target name, the required options in documented order (`LOCATION`, `DATA_SOURCE`, `FILE_FORMAT`), and exactly one parsed `SELECT` after `AS`; optional CETAS column lists and reject options are outside this adapter. Even for accepted syntax, external-table and file-write lineage are not modeled, and analysis emits an unsupported-lineage warning instead of inventing dataflow. See [Microsoft's Synapse CETAS syntax and examples](https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/develop-tables-cetas).

The Synapse `OPENROWSET` grammar places optional `DATA_SOURCE` before the required `FORMAT`; the adapter accepts that order only and rejects `DATA_SOURCE` after `FORMAT`, as shown in [Microsoft's `OPENROWSET` syntax](https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/develop-openrowset#syntax). This option-order rule does not confirm or add support for other external metadata/context constructs; no such additional construct is covered by these synthetic regressions.

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
