import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyzeConfig } from '../src/analyzers/config.mjs';
import { visible } from '../src/finding.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const load = async (p) => JSON.parse(await readFile(join(ROOT, 'fixtures', p), 'utf8'));

const reportable = (config) => visible(analyzeConfig(config, 'mcp.json'));
const rules = (config) => reportable(config).map((f) => f.rule);

test('a well-formed config produces no findings', async () => {
  const found = reportable(await load('benign/mcp.json'));
  assert.deepEqual(found, [], `false positives: ${found.map((f) => `${f.rule} @ ${f.location.field}`).join(', ')}`);
});

test('indirect credential values are not reported', () => {
  const config = {
    mcpServers: {
      a: { command: 'srv', env: { API_KEY: '${API_KEY}' } },
      b: { command: 'srv', env: { TOKEN: '$GITHUB_TOKEN' } },
      c: { type: 'http', url: 'https://x.example.com', headers: { Authorization: 'Bearer ${DOCS_TOKEN}' } },
      d: { command: 'srv', env: { API_KEY: '%API_KEY%' } },
    },
  };
  assert.deepEqual(rules(config), []);
});

// Fixture credentials use EXAMPLE runs rather than random looking strings.
// They still match the detector, which cares about shape, but secret scanners
// recognise them as placeholders. A realistic looking fake in a security
// repository blocks the push and trains people to click past real warnings.
test('a literal provider credential is critical even when wrapped', () => {
  const config = {
    mcpServers: {
      a: {
        command: 'srv',
        type: 'http',
        url: 'https://x.example.com',
        headers: { Authorization: 'Bearer ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE00000000' },
      },
    },
  };
  const found = reportable(config);
  const secret = found.find((f) => f.rule === 'config/hardcoded-credential');

  assert.ok(secret, 'should flag the literal token');
  assert.equal(secret.severity, 'critical');
});

test('the malicious fixture triggers the expected categories', async () => {
  const found = reportable(await load('malicious/mcp.json'));
  const byRule = new Set(found.map((f) => f.rule));

  for (const rule of [
    'config/hardcoded-credential',
    'config/remote-code-execution',
    'config/shell-launch',
    'config/broad-filesystem-scope',
    'config/unpinned-dependency',
    'config/cleartext-transport',
    'config/unauthenticated-remote',
  ]) {
    assert.ok(byRule.has(rule), `expected ${rule}`);
  }

  const owaspSeen = new Set(found.map((f) => f.owasp));
  assert.ok(owaspSeen.size >= 5, `expected several OWASP categories, saw ${[...owaspSeen].join(', ')}`);
});

test('localhost over http is not flagged as cleartext or unauthenticated', () => {
  const config = { mcpServers: { dev: { type: 'http', url: 'http://localhost:3000/mcp' } } };
  assert.deepEqual(rules(config), []);
});

test('a pinned package does not trigger the supply chain rule', () => {
  const pinned = { mcpServers: { a: { command: 'npx', args: ['@scope/server@1.2.3', '/srv/project'] } } };
  const floating = { mcpServers: { a: { command: 'npx', args: ['@scope/server', '/srv/project'] } } };

  assert.ok(!rules(pinned).includes('config/unpinned-dependency'));
  assert.ok(rules(floating).includes('config/unpinned-dependency'));
});

test('a scoped filesystem path is fine, the home directory is not', () => {
  const scoped = { mcpServers: { fs: { command: 'srv', args: ['/Users/dev/projects/api'] } } };
  const broad = { mcpServers: { fs: { command: 'srv', args: ['/'] } } };

  assert.ok(!rules(scoped).includes('config/broad-filesystem-scope'));
  assert.ok(rules(broad).includes('config/broad-filesystem-scope'));
});
