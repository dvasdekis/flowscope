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

      body.dataset.status = 'passed';
      body.textContent = JSON.stringify({
        version: get_version(),
        statementCount: result.summary.statementCount,
        tableLabels,
        mssqlStatementCount: mssqlResult.summary.statementCount,
        moduleStatementType: moduleResult.statements[0].statementType,
        synapseStatementCount: synapseResult.summary.statementCount,
        metadataStatementType: metadataResult.statements[0].statementType,
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
