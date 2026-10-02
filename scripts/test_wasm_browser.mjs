#!/usr/bin/env node

import { access, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const wasmDir = path.join(repoRoot, 'packages', 'core', 'wasm');
const bindingsPath = path.join(wasmDir, 'flowscope_wasm.js');
const binaryPath = path.join(wasmDir, 'flowscope_wasm_bg.wasm');

const harness = `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>FlowScope real WASM integration</title></head>
  <body data-status="running">Running FlowScope real WASM integration…</body>
  <script type="module">
    import init, { analyze_sql_json, get_version, split_statements_json } from '/flowscope_wasm.js';

    const body = document.body;
    const analyzeMssql = (sql) => JSON.parse(analyze_sql_json(JSON.stringify({
      sql,
      dialect: 'mssql',
    })));
    const hasIssue = (result, code) => result.issues.some((issue) => issue.code === code);
    const hasWarning = (result, code) => result.issues.some(
      (issue) => issue.code === code && issue.severity === 'warning'
    );
    const isMetadata = (result, statementType) =>
      result.statements.length === 1 &&
      result.statements[0].statementType === statementType &&
      result.nodes.length === 0 &&
      result.edges.length === 0 &&
      hasWarning(result, 'UNSUPPORTED_SYNTAX') &&
      !hasIssue(result, 'PARSE_ERROR');
    const isOpenrowset = (result) =>
      result.statements.length === 1 &&
      !hasIssue(result, 'PARSE_ERROR') &&
      hasWarning(result, 'UNSUPPORTED_SYNTAX') &&
      result.nodes.every((node) => node.type !== 'table');
    try {
      await init('/flowscope_wasm_bg.wasm');
      const request = {
        sql: 'SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id',
        dialect: 'postgres',
        schema: {
          tables: [
            { name: 'users', columns: [{ name: 'id', dataType: 'integer' }] },
            {
              name: 'orders',
              columns: [
                { name: 'user_id', dataType: 'integer' },
                { name: 'total', dataType: 'numeric' }
              ]
            }
          ]
        }
      };
      const result = JSON.parse(analyze_sql_json(JSON.stringify(request)));
      const tableLabels = result.nodes
        .filter((node) => node.type === 'table')
        .map((node) => node.label);
      const errors = result.issues.filter((issue) => issue.severity === 'error');

      const goSql = 'SELECT 1;\\nGO 2\\nSELECT 2;\\nGO\\n';
      const mssqlResult = analyzeMssql(goSql);
      const mssqlSplitResult = JSON.parse(split_statements_json(JSON.stringify({
        sql: goSql,
        dialect: 'mssql',
      })));
      const aggregateResult = JSON.parse(analyze_sql_json(JSON.stringify({
        sql: 'SELECT 3;',
        sourceName: 'inline.sql',
        dialect: 'mssql',
        files: [
          { name: 'first.sql', content: 'SELECT 1;\\n'.repeat(501) },
          { name: 'second.sql', content: 'SELECT 2;\\n'.repeat(501) },
        ],
      })));
      if (
        aggregateResult.summary.issueCount.errors !== 0 ||
        aggregateResult.summary.statementCount !== 1003 ||
        aggregateResult.statements.length !== 1003 ||
        !aggregateResult.statements.slice(0, 501).every(
          (statement) => statement.sourceName === 'first.sql'
        ) ||
        !aggregateResult.statements.slice(501, 1002).every(
          (statement) => statement.sourceName === 'second.sql'
        ) ||
        aggregateResult.statements[1002].sourceName !== 'inline.sql'
      ) {
        throw new Error('MSSQL aggregate range budget truncated a valid multi-file request');
      }
      const moduleSql = "CREATE OR ALTER PROC dbo.copy_rows @source_id INT = 7 OUTPUT, @rows dbo.RowList READONLY AS BEGIN SELECT N'CREATE PROC hidden @x INT OUTPUT'; END";
      const moduleResult = analyzeMssql(moduleSql);
      const malformedModuleResult = analyzeMssql(
        'CREATE OR ALTER PROC dbo.copy_rows @source_id INT, AS SELECT 1;'
      );
      const openrowsetSql = "SELECT file.id FROM OPENROWSET(BULK 'https://storage.example/data/*.parquet', FORMAT = 'PARQUET') WITH (id BIGINT) AS file";
      const synapseResult = analyzeMssql(openrowsetSql);
      const malformedOpenrowsetResult = analyzeMssql(
        "SELECT * FROM OPENROWSET(BULK 'path', FORMAT = 'TEXT') AS file"
      );
      const metadataSql = "/* synthetic metadata */ CREATE EXTERNAL FILE FORMAT [synthetic_csv] WITH (FORMAT_TYPE = DELIMITEDTEXT, FORMAT_OPTIONS (FIELD_TERMINATOR = ',', FIRST_ROW = 2))";
      const metadataResult = analyzeMssql(metadataSql);
      const malformedMetadataResult = analyzeMssql(
        "CREATE EXTERNAL FILE FORMAT synthetic_parquet WITH (FORMAT_TYPE = PARQUET, FORMAT_OPTIONS (FIELD_TERMINATOR = ','))"
      );
      const bareMetadataSql =
        "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'synthetic_bare_format') CREATE EXTERNAL FILE FORMAT synthetic_bare_format WITH (FORMAT_TYPE = PARQUET)";
      const bareMetadataResult = analyzeMssql(bareMetadataSql);
      const malformedBareMetadataResult = analyzeMssql(
        "IF NOT EXISTS (SELECT 1 FROM sys.external_file_formats WHERE name = 'synthetic_bare_format') CREATE EXTERNAL FILE FORMAT synthetic_bare_format WITH (FORMAT_TYPE =)"
      );
      const dataSourceBeforeFormatResult = analyzeMssql(
        "SELECT src.id FROM OPENROWSET(BULK 'data.parquet', DATA_SOURCE = 'synthetic_lake', FORMAT = 'PARQUET') AS src"
      );
      const formatBeforeDataSourceResult = analyzeMssql(
        "SELECT src.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', DATA_SOURCE = 'synthetic_lake') AS src"
      );
      const malformedDataSourceBeforeFormatResult = analyzeMssql(
        "SELECT src.id FROM OPENROWSET(BULK 'data.parquet', DATA_SOURCE = 1, FORMAT = 'PARQUET') AS src"
      );
      const malformedFormatBeforeDataSourceResult = analyzeMssql(
        "SELECT src.id FROM OPENROWSET(BULK 'data.parquet', FORMAT = 'PARQUET', DATA_SOURCE = 1) AS src"
      );
      const trimPredicateResult = analyzeMssql("SELECT 1 WHERE TRIM = 'synthetic'");
      const malformedTrimPredicateResult = analyzeMssql('SELECT 1 WHERE TRIM =');
      const bulkFileListResult = analyzeMssql(
        "SELECT src.id FROM OPENROWSET(BULK ('data/a.parquet', 'data/b.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS src"
      );
      const quotedAliasResults = [
        ['[r]', '[R]'],
        ['"r"', '"R"'],
        ['r', '[R]'],
      ].flatMap(([alias, reference]) =>
        [reference + '.id', reference + '.*'].map((projection) =>
          analyzeMssql(
            "SELECT " + projection +
            " FROM OPENROWSET(BULK 'demo.parquet', FORMAT = 'PARQUET') WITH (id INT) AS " + alias
          )
        )
      );
      const malformedBulkFileListResult = analyzeMssql(
        "SELECT src.id FROM OPENROWSET(BULK ('data/a.parquet',), FORMAT = 'PARQUET') WITH (id INT) AS src"
      );
      const inlineTvfSql =
        'CREATE FUNCTION dbo.synthetic_rows() RETURNS TABLE AS RETURN WITH synthetic_cte AS (SELECT 1 AS synthetic_value) SELECT synthetic_value FROM synthetic_cte';
      const inlineTvfResult = analyzeMssql(inlineTvfSql);
      const malformedInlineTvfResult = analyzeMssql(
        'CREATE FUNCTION dbo.synthetic_rows() RETURNS TABLE AS RETURN WITH synthetic_cte AS (SELECT 1) SELECT FROM synthetic_cte'
      );
      const cetasNameListResult = analyzeMssql(
        "CREATE EXTERNAL TABLE dbo.synthetic_export ([export_id]) WITH (LOCATION = 'synthetic-output/', DATA_SOURCE = synthetic_storage, FILE_FORMAT = synthetic_format) AS SELECT id FROM dbo.synthetic_source"
      );
      const malformedCetasNameListResult = analyzeMssql(
        "CREATE EXTERNAL TABLE dbo.synthetic_export (export_id,) WITH (LOCATION = 'synthetic-output/', DATA_SOURCE = synthetic_storage, FILE_FORMAT = synthetic_format) AS SELECT id FROM dbo.synthetic_source"
      );
      const malformedTypedCetasNameListResult = analyzeMssql(
        "CREATE EXTERNAL TABLE dbo.synthetic_export (export_id INT) WITH (LOCATION = 'synthetic-output/', DATA_SOURCE = synthetic_storage, FILE_FORMAT = synthetic_format) AS SELECT id FROM dbo.synthetic_source"
      );
      const bulkBoundaryResults = ['', '\\n', '\\r\\n', '/* list boundary */'].map(
        (separator) => analyzeMssql(
          "SELECT src.id FROM OPENROWSET(BULK" + separator +
          "('demo/a.parquet', 'demo/b.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS src"
        )
      );
      const procedureRowsetSql =
        "CREATE OR ALTER PROCEDURE dbo.synthetic_rows AS BEGIN SELECT src.id FROM OPENROWSET(BULK\\n('demo/a.parquet'), FORMAT = 'PARQUET') WITH (id INT) AS src; END";
      const procedureRowsetResult = analyzeMssql(procedureRowsetSql);
      const guardedTableResults = [
        "IF NOT EXISTS (SELECT 1) CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
        "IF NOT EXISTS (SELECT 1) BEGIN CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format); END",
        "IF OBJECT_ID(N'dbo.synthetic_rows', N'U') IS NULL CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (DATA_SOURCE = synthetic_store, LOCATION = 'demo/', FILE_FORMAT = synthetic_format)",
        "IF OBJECT_ID('dbo.synthetic_rows') IS NULL BEGIN CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format); END",
      ].map(analyzeMssql);
      const mssqlExpressionResults = [
        "CREATE OR ALTER VIEW dbo.synthetic_view AS SELECT t.demo_value FROM dbo.synthetic_table AS t WHERE t.demo_value COLLATE Latin1_General_100_CI_AS = N'demo'",
        "CREATE OR ALTER VIEW dbo.synthetic_view AS SELECT TRY_PARSE(N'2024-01-02' AS DATETIME USING N'en-US') AS parsed_value",
        "SELECT INTERVAL FROM dbo.synthetic_table",
        "SELECT INTERVAL + 1 AS interval_value, INTERVAL implicit_alias FROM dbo.synthetic_table WHERE INTERVAL IS NULL",
        "SELECT TRY_PARSE(INTERVAL AS DATE USING DATE) FROM dbo.synthetic_table",
        "SELECT CAST(INTERVAL AS INT), CONVERT(INT, INTERVAL), TRY_CAST(INTERVAL AS INT), TRY_CONVERT(INT, INTERVAL) FROM dbo.synthetic_table",
        "SELECT a.id FROM dbo.synthetic_a AS a LEFT JOIN dbo.synthetic_b AS b INNER JOIN dbo.synthetic_c AS c ON b.id = c.id ON a.id = b.id",
      ].map(analyzeMssql);
      const optionalTerminatorResults = [
        "CREATE OR ALTER PROCEDURE dbo.synthetic_proc AS BEGIN DECLARE @value INT SELECT @value = 1 END",
        "BEGIN DECLARE @value INT SELECT @value = 1 END",
      ].map(analyzeMssql);
      const tableColumnCommaResults = [
        "CREATE TABLE #synthetic_result (demo_value NVARCHAR(MAX),);",
        "CREATE PROCEDURE dbo.synthetic_proc AS BEGIN CREATE TABLE #synthetic_result (demo_value NVARCHAR(MAX),); END;",
      ].map(analyzeMssql);
      const malformedSynapseResults = [
        malformedBareMetadataResult,
        malformedDataSourceBeforeFormatResult,
        malformedFormatBeforeDataSourceResult,
        malformedTrimPredicateResult,
        malformedBulkFileListResult,
        malformedInlineTvfResult,
        malformedCetasNameListResult,
        malformedTypedCetasNameListResult,
        ...[
          "SELECT * FROM OPENROWSET(BULK\\n('demo/a.parquet',), FORMAT = 'PARQUET') AS src",
          "SELECT * FROM OPENROWSET(BULK(), FORMAT = 'PARQUET') AS src",
          "CREATE PROCEDURE dbo.synthetic_rows AS BEGIN SELECT * FROM OPENROWSET(BULK('demo/a.parquet'), FORMAT = 'PARQUET') WITH (id) AS src; END",
          "IF NOT EXISTS (SELECT FROM) CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
          "IF NOT EXISTS (SELECT 1) BEGIN CREATE EXTERNAL TABLE dbo.synthetic_rows (id) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format); END",
          "IF NOT EXISTS (SELECT 1) CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format) ELSE SELECT 1",
          "SELECT t.demo_value COLLATE FROM dbo.synthetic_table AS t",
          "SELECT TRY_PARSE(N'2024-01-02' AS)",
          "SELECT INTERVAL FROM dbo.",
          "SELECT a.id FROM dbo.synthetic_a AS a LEFT JOIN dbo.synthetic_b AS b INNER JOIN dbo.synthetic_c AS c ON b.id = c.id ON",
          "CREATE TABLE #synthetic_result (demo_value INT,,);",
          "SELECT COALESCE(1,);",
          "CREATE PROCEDURE dbo.synthetic_proc AS BEGIN DECLARE @value SELECT FROM END",
          "IF OBJECT_ID() IS NULL CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
          "IF OBJECT_ID('dbo.synthetic_rows') CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (LOCATION = 'demo/', DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
          "CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (DATA_SOURCE = synthetic_store, DATA_SOURCE = synthetic_store, FILE_FORMAT = synthetic_format)",
          "CREATE EXTERNAL TABLE dbo.synthetic_rows (id INT) WITH (DATA_SOURCE = synthetic_store, LOCATION = '', FILE_FORMAT = synthetic_format)",
        ].map(analyzeMssql),
      ];

      if (result.statements.length !== 1 || result.summary.statementCount !== 1) {
        throw new Error('Expected one analyzed statement');
      }
      if (!tableLabels.includes('users') || !tableLabels.includes('orders')) {
        throw new Error('Expected users and orders table nodes: ' + JSON.stringify(tableLabels));
      }
      if (errors.length > 0) {
        throw new Error('Analysis returned errors: ' + JSON.stringify(errors));
      }
      if (mssqlResult.statements.length !== 3 || hasIssue(mssqlResult, 'PARSE_ERROR')) {
        throw new Error(
          'MSSQL GO batch analysis failed: ' + JSON.stringify(mssqlResult.issues)
        );
      }
      const goSpans = mssqlSplitResult.statements;
      if (mssqlSplitResult.error ||
          goSpans.length !== 3 ||
          goSpans[0].start !== 0 ||
          goSpans[0].end !== 8 ||
          goSpans[1].start !== goSpans[0].start ||
          goSpans[1].end !== goSpans[0].end ||
          goSpans[2].start !== 15 ||
          goSpans[2].end !== 23) {
        throw new Error('MSSQL GO split ranges changed: ' + JSON.stringify(mssqlSplitResult));
      }
      if (moduleResult.statements.length !== 1 ||
          moduleResult.statements[0].statementType !== 'CREATE_PROCEDURE' ||
          moduleResult.statements[0].span.start !== 0 ||
          moduleResult.statements[0].span.end !== moduleSql.length ||
          moduleResult.nodes.length !== 0 ||
          moduleResult.edges.length !== 0 ||
          hasIssue(moduleResult, 'PARSE_ERROR')) {
        throw new Error('Synapse procedure header analysis failed: ' + JSON.stringify(moduleResult));
      }
      if (!hasIssue(malformedModuleResult, 'PARSE_ERROR')) {
        throw new Error('Malformed Synapse procedure parameters were accepted');
      }
      if (synapseResult.statements.length !== 1 ||
          hasIssue(synapseResult, 'PARSE_ERROR') ||
          !hasWarning(synapseResult, 'UNSUPPORTED_SYNTAX') ||
          synapseResult.nodes.some((node) => node.type === 'table')) {
        throw new Error(
          'Synapse OPENROWSET analysis failed: ' + JSON.stringify(synapseResult.issues)
        );
      }
      if (!hasIssue(malformedOpenrowsetResult, 'PARSE_ERROR')) {
        throw new Error('Malformed Synapse OPENROWSET syntax was accepted');
      }
      if (metadataResult.statements.length !== 1 ||
          metadataResult.statements[0].statementType !== 'CREATE_EXTERNAL_FILE_FORMAT' ||
          metadataResult.nodes.length !== 0 ||
          metadataResult.edges.length !== 0 ||
          !hasWarning(metadataResult, 'UNSUPPORTED_SYNTAX') ||
          hasIssue(metadataResult, 'PARSE_ERROR')) {
        throw new Error('External metadata was incorrectly analyzed as a table');
      }
      if (!hasIssue(malformedMetadataResult, 'PARSE_ERROR')) {
        throw new Error('Unsupported external file format options were accepted');
      }
      if (!isMetadata(bareMetadataResult, 'CREATE_EXTERNAL_FILE_FORMAT')) {
        throw new Error('Bare IF external metadata analysis failed: ' + JSON.stringify(bareMetadataResult));
      }
      if (!isOpenrowset(dataSourceBeforeFormatResult) ||
          !isOpenrowset(formatBeforeDataSourceResult)) {
        throw new Error(
          'Synapse OPENROWSET option ordering failed: ' +
          JSON.stringify([
            dataSourceBeforeFormatResult.issues,
            formatBeforeDataSourceResult.issues,
          ])
        );
      }
      if (trimPredicateResult.statements.length !== 1 ||
          hasIssue(trimPredicateResult, 'PARSE_ERROR')) {
        throw new Error(
          'MSSQL nonreserved TRIM predicate failed: ' +
          JSON.stringify(trimPredicateResult.issues)
        );
      }
      if (!isOpenrowset(bulkFileListResult)) {
        throw new Error('Synapse BULK file list analysis failed: ' + JSON.stringify(bulkFileListResult.issues));
      }
      if (!quotedAliasResults.every((rowset) =>
        isOpenrowset(rowset) &&
        !hasIssue(rowset, 'UNKNOWN_COLUMN') &&
        rowset.nodes.filter((node) => node.type === 'column').length === 1 &&
        rowset.nodes.some((node) =>
          node.type === 'column' && node.label === 'id' && node.metadata?.data_type === 'INTEGER'
        ) &&
        rowset.nodes.every((node) => !node.qualifiedName) &&
        rowset.edges.every((edge) => edge.type !== 'data_flow') &&
        !(rowset.resolvedSchema?.tables.length)
      )) {
        throw new Error('Quoted OPENROWSET alias types or external-lineage boundary failed');
      }
      if (inlineTvfResult.statements.length !== 1 ||
          inlineTvfResult.statements[0].span.end !== inlineTvfSql.length ||
          hasIssue(inlineTvfResult, 'PARSE_ERROR')) {
        throw new Error('Inline TVF CTE without a final semicolon failed: ' + JSON.stringify(inlineTvfResult));
      }
      if (!isMetadata(cetasNameListResult, 'CREATE_EXTERNAL_TABLE_AS_SELECT')) {
        throw new Error('CETAS output-name list analysis failed: ' + JSON.stringify(cetasNameListResult));
      }
      if (!bulkBoundaryResults.every(isOpenrowset)) {
        throw new Error('Synapse BULK lexical boundary analysis failed');
      }
      if (procedureRowsetResult.statements.length !== 1 ||
          procedureRowsetResult.statements[0].statementType !== 'CREATE_PROCEDURE' ||
          procedureRowsetResult.statements[0].span.end !== procedureRowsetSql.length ||
          hasIssue(procedureRowsetResult, 'PARSE_ERROR')) {
        throw new Error('OPENROWSET schema in a procedure body failed');
      }
      if (!guardedTableResults.every((table) => isMetadata(table, 'CREATE_EXTERNAL_TABLE'))) {
        throw new Error('Guarded external-table metadata analysis failed');
      }
      if (![...mssqlExpressionResults, ...optionalTerminatorResults, ...tableColumnCommaResults].every(
        (statement) => statement.statements.length === 1 && !hasIssue(statement, 'PARSE_ERROR')
      )) {
        throw new Error('MSSQL expression, table-column comma or optional terminator analysis failed');
      }
      if (malformedSynapseResults.some((synapseResult) => !hasIssue(synapseResult, 'PARSE_ERROR'))) {
        throw new Error(
          'A malformed Synapse SQL counterpart was accepted: ' +
          JSON.stringify(malformedSynapseResults.map((synapseResult) => synapseResult.issues))
        );
      }

      body.dataset.status = 'passed';
      body.textContent = JSON.stringify({
        version: get_version(),
        statementCount: result.summary.statementCount,
        tableLabels,
        mssqlStatementCount: mssqlResult.summary.statementCount,
        aggregateMssqlStatementCount: aggregateResult.summary.statementCount,
        moduleStatementType: moduleResult.statements[0].statementType,
        synapseStatementCount: synapseResult.summary.statementCount,
        metadataStatementType: metadataResult.statements[0].statementType,
        bareIfMetadataType: bareMetadataResult.statements[0].statementType,
        openrowsetOptionOrders: 2,
        bulkFileList: true,
        quotedRowsetAliases: quotedAliasResults.length,
        inlineTvfCteWithoutFinalSemicolon: true,
        cetasOutputNameList: true,
        bulkLexicalBoundaries: bulkBoundaryResults.length,
        procedureRowsetSchema: true,
        guardedExternalTables: guardedTableResults.length,
        mssqlExpressions: mssqlExpressionResults.length,
        optionalProceduralTerminators: optionalTerminatorResults.length,
        tableColumnTrailingCommas: tableColumnCommaResults.length,
        malformedSynapseCases: malformedSynapseResults.length,
      });
    } catch (error) {
      body.dataset.status = 'failed';
      body.textContent = error instanceof Error ? error.stack ?? error.message : String(error);
    }
  </script>
</html>`;

const candidates = [
  process.env.CHROME_BIN,
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
].filter(Boolean);

async function findBrowser() {
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next known executable.
    }
  }
  throw new Error('Chromium was not found. Set CHROME_BIN to a Chromium-compatible browser.');
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address()));
  });
}

function runBrowser(executable, url) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      executable,
      [
        '--headless=new',
        '--disable-gpu',
        '--no-sandbox',
        '--dump-dom',
        '--virtual-time-budget=15000',
        url,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let stdout = '';
    let stderr = '';
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('Timed out waiting for the browser integration test'));
    }, 30000);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`Chromium exited with ${code}:\n${stderr}`));
        return;
      }
      resolve(stdout);
    });
  });
}

async function main() {
  try {
    await Promise.all([access(bindingsPath), access(binaryPath)]);
  } catch {
    throw new Error('Built WASM assets are missing. Run `just build-wasm-dev` first.');
  }

  const [bindings, binary, browser] = await Promise.all([
    readFile(bindingsPath),
    readFile(binaryPath),
    findBrowser(),
  ]);
  const server = createServer((request, response) => {
    switch (request.url) {
      case '/':
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(harness);
        break;
      case '/flowscope_wasm.js':
        response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
        response.end(bindings);
        break;
      case '/flowscope_wasm_bg.wasm':
        response.writeHead(200, { 'content-type': 'application/wasm' });
        response.end(binary);
        break;
      default:
        response.writeHead(404).end();
    }
  });

  try {
    const address = await listen(server);
    if (!address || typeof address === 'string') throw new Error('Failed to bind test server');
    const dom = await runBrowser(browser, `http://127.0.0.1:${address.port}/`);
    if (!dom.includes('data-status="passed"')) {
      const failure = dom.match(/<body[^>]*>([\s\S]*?)<\/body>/)?.[1] ?? dom;
      throw new Error(`Browser integration failed:\n${failure}`);
    }
    const result = dom.match(/<body[^>]*>([\s\S]*?)<\/body>/)?.[1] ?? 'passed';
    console.log(`Real WASM browser integration passed: ${result}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
