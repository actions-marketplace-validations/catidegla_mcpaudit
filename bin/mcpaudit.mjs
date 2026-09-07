#!/usr/bin/env node
/**
 * mcpaudit
 *
 * Audits MCP server configuration and tool metadata for the OWASP MCP Top 10.
 * Runs locally, reads nothing it was not pointed at, and never calls out to a
 * model or an API.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { discover, wellKnownConfigPaths } from '../src/discover.mjs';
import { analyze, buildBaseline, verifyBaseline, readBaseline, writeBaseline, BASELINE_FILE } from '../src/engine.mjs';
import { visible, CONFIDENCE } from '../src/finding.mjs';
import { renderFindings, renderSummary } from '../src/report/pretty.mjs';
import { toSarif } from '../src/report/sarif.mjs';
import { OWASP_MCP } from '../src/owasp.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8'));

const argv = process.argv.slice(2);
const has = (name) => argv.includes(`--${name}`);
const value = (name, fallback = null) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? fallback : argv[i + 1];
};
const all = (name) => argv.reduce((acc, a, i) => (a === `--${name}` ? [...acc, argv[i + 1]] : acc), []);

const FAIL_LEVELS = { critical: 4, high: 3, medium: 2, low: 1, never: 99 };
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function usage() {
  console.log(`
mcpaudit ${pkg.version}
Audit MCP servers and agent skills against the OWASP MCP Top 10.

Usage
  mcpaudit [path]                 scan a directory or file (default: current directory)
  mcpaudit installed              scan the MCP configs your clients already have
  mcpaudit pin [path]             record current tool metadata as approved
  mcpaudit verify [path]          report metadata that changed since it was pinned
  mcpaudit rules                  list the OWASP categories this maps to

Options
  --format <pretty|json|sarif>    output format (default: pretty)
  --output <file>                 write to a file instead of stdout
  --all                           include low confidence observations
  --fail-on <level>               exit 1 at this severity or worse
                                  critical, high, medium, low, never (default: high)
  --ignore <rule>                 suppress a rule, repeatable
                                  accepts "poisoning/*" and "rule@path" forms
  --baseline <file>               baseline path (default: ${BASELINE_FILE})
  --depth <n>                     directory recursion depth (default: 6)

Examples
  npx mcpaudit .
  npx mcpaudit installed
  npx mcpaudit . --format sarif --output mcpaudit.sarif
  npx mcpaudit . --fail-on medium --ignore config/unpinned-dependency
`);
}

function cmdRules() {
  console.log(`\nmcpaudit maps every finding to the OWASP MCP Top 10 (beta).\n`);
  for (const entry of Object.values(OWASP_MCP)) {
    console.log(`  ${entry.id}  ${entry.title}`);
    console.log(`             ${entry.summary}\n`);
  }
  console.log('  https://owasp.org/www-project-mcp-top-10/\n');
}

async function collect(path, depth) {
  const targets = await discover(path, { depth });
  if (!targets.length) {
    const where = path ? resolve(path) : 'the well-known client config locations';
    console.error(`Nothing to audit in ${where}.`);
    if (!path) {
      console.error('Looked in:');
      for (const p of wellKnownConfigPaths()) console.error(`  ${p}`);
    }
    console.error('\nPoint mcpaudit at a directory containing MCP configuration, tool manifests, or SKILL.md files.');
    process.exit(2);
  }
  return targets;
}

async function emit(findings, { scanned, hidden, elapsedMs, format, output }) {
  let text;

  if (format === 'sarif') {
    text = `${JSON.stringify(toSarif(findings, { version: pkg.version }), null, 2)}\n`;
  } else if (format === 'json') {
    text = `${JSON.stringify(
      {
        tool: 'mcpaudit',
        version: pkg.version,
        generatedAt: new Date().toISOString(),
        scanned,
        hidden,
        counts: findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] ?? 0) + 1 }), {}),
        findings,
      },
      null,
      2
    )}\n`;
  } else {
    text = renderFindings(findings, { hidden, scanned }) + renderSummary(findings, { hidden, scanned, elapsedMs });
  }

  if (output) {
    await writeFile(output, text);
    if (format !== 'pretty') console.log(`Wrote ${findings.length} finding(s) to ${output}`);
  } else {
    process.stdout.write(text);
  }
}

function exitFor(findings, failOn) {
  if (failOn === 'never') return 0;
  const threshold = FAIL_LEVELS[failOn] ?? FAIL_LEVELS.high;
  return findings.some((f) => SEVERITY_RANK[f.severity] >= threshold) ? 1 : 0;
}

async function main() {
  const command = argv[0] && !argv[0].startsWith('--') ? argv[0] : null;
  const known = new Set(['scan', 'installed', 'pin', 'verify', 'rules', 'help']);

  if (has('help') || command === 'help') return usage();
  if (has('version')) return console.log(pkg.version);
  if (command === 'rules') return cmdRules();

  const positional = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1]?.startsWith('--') !== true);
  const pathArg = known.has(command) ? positional[1] : positional[0];

  const depth = Number(value('depth', 6));
  const format = value('format', 'pretty');
  const output = value('output');
  const failOn = value('fail-on', 'high');
  const ignore = all('ignore').filter(Boolean);
  const baselineFile = value('baseline', BASELINE_FILE);
  const minConfidence = has('all') ? 'low' : 'medium';

  if (!['pretty', 'json', 'sarif'].includes(format)) {
    console.error(`Unknown format "${format}". Use pretty, json or sarif.`);
    process.exit(2);
  }
  if (!(failOn in FAIL_LEVELS)) {
    console.error(`Unknown --fail-on "${failOn}". Use critical, high, medium, low or never.`);
    process.exit(2);
  }

  const scanPath = command === 'installed' ? null : (pathArg ?? '.');
  const started = Date.now();
  const targets = await collect(scanPath, depth);
  const root = scanPath ? resolve(scanPath) : process.cwd();

  if (command === 'pin') {
    const baseline = buildBaseline(targets, { root });
    await writeBaseline(baseline, baselineFile);
    const count = Object.keys(baseline.entries).length;
    console.log(`Pinned ${count} metadata item(s) from ${targets.length} file(s) to ${baselineFile}.`);
    console.log('Run "mcpaudit verify" to detect changes to any of them.');
    return;
  }

  if (command === 'verify') {
    const baseline = await readBaseline(baselineFile);
    if (!baseline) {
      console.error(`No baseline at ${baselineFile}. Run "mcpaudit pin" first.`);
      process.exit(2);
    }

    const drift = verifyBaseline(targets, baseline, { root });
    const shown = visible(drift, { minConfidence });
    const elapsedMs = Date.now() - started;

    await emit(shown, {
      scanned: targets.length,
      hidden: drift.length - shown.length,
      elapsedMs,
      format,
      output,
    });
    process.exitCode = exitFor(shown, failOn);
    return;
  }

  const findings = analyze(targets, { root, ignore });
  const shown = visible(findings, { minConfidence });
  const elapsedMs = Date.now() - started;

  await emit(shown, {
    scanned: targets.length,
    hidden: findings.length - shown.length,
    elapsedMs,
    format,
    output,
  });

  process.exitCode = exitFor(shown, failOn);
}

main().catch((error) => {
  console.error(`mcpaudit: ${error.message}`);
  process.exit(2);
});
