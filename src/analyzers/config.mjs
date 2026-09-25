/**
 * MCP server configuration analysis.
 *
 * Config files are where the boring, high-impact problems live: a real API key
 * pasted into an env block, a server pulled unpinned from npm on every launch,
 * a filesystem server rooted at the home directory.
 *
 * Config findings are mostly deterministic, so they carry structural weight
 * rather than heuristic weight. Either the key is in the file or it is not.
 */

import { owasp } from '../owasp.mjs';
import { finding, signal } from '../finding.mjs';

/** Provider-issued credentials. These shapes do not occur by accident. */
const SECRET_PATTERNS = [
  { name: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { name: 'Stripe live key', re: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Anthropic key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'OpenAI key', re: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'SendGrid key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { name: 'private key block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'connection string with password', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:@\s/]+:[^@\s]{4,}@/ },
];

/** Values that look secret-shaped but are placeholders. */
const PLACEHOLDER = /^(?:\$\{?[A-Z_]|<|\{\{|your[_-]|xxx+$|changeme|placeholder|example|dummy|test[_-]?key|sk_test_|redacted|\.\.\.)/i;

const SECRET_KEY_NAME = /(?:api[_-]?key|secret|token|password|passwd|credential|auth|private[_-]?key|access[_-]?key)/i;

const SHELL_WRAPPERS = /^(?:ba|z|k|da|)sh$|^cmd(?:\.exe)?$|^powershell(?:\.exe)?$|^pwsh$/i;

/** Variable references anywhere in the value, including "Bearer ${TOKEN}". */
const VAR_REFERENCE = /\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]{2,}|%[A-Za-z_][A-Za-z0-9_]*%/;

function isPlaceholder(value) {
  if (typeof value !== 'string' || !value.trim()) return true;
  const trimmed = value.trim();
  if (PLACEHOLDER.test(trimmed)) return true;

  // Deferencing a variable is the correct pattern, and it is usually wrapped:
  // "Bearer ${DOCS_TOKEN}" must not be reported. A literal credential sitting
  // next to a variable reference still gets flagged.
  if (VAR_REFERENCE.test(trimmed) && !SECRET_PATTERNS.some((p) => p.re.test(trimmed))) return true;

  return false;
}

/** High entropy is a supporting signal, never a finding on its own. */
function shannon(value) {
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function analyzeEnvBlock(env, serverName, file, kind = 'env') {
  const findings = [];
  if (!env || typeof env !== 'object') return findings;

  for (const [key, raw] of Object.entries(env)) {
    const value = typeof raw === 'string' ? raw : '';
    if (isPlaceholder(value)) continue;

    const matched = SECRET_PATTERNS.find((p) => p.re.test(value));
    const namedLikeSecret = SECRET_KEY_NAME.test(key);
    const entropy = value.length >= 20 ? shannon(value) : 0;

    if (!matched && !(namedLikeSecret && value.length >= 16)) continue;

    const signals = [
      matched
        ? signal('known-credential-format', 4, `value matches a ${matched.name}`)
        : signal('secret-shaped-key', 2, `"${key}" names a credential and holds a ${value.length} character literal`),
      namedLikeSecret && matched ? signal('key-name-agrees', 1, `the key is named "${key}"`) : null,
      entropy >= 3.6 ? signal('high-entropy', 1.5, `entropy ${entropy.toFixed(1)} bits per character`) : null,
      // A value that reads a variable at launch is doing the right thing.
      /^\$/.test(value) ? signal('indirect-value', -3, 'value dereferences an environment variable') : null,
    ].filter(Boolean);

    findings.push(
      finding({
        rule: 'config/hardcoded-credential',
        owasp: owasp('MCP01'),
        severity: matched ? 'critical' : 'high',
        title: `Credential written directly into ${kind === 'env' ? 'the server environment' : 'request headers'}`,
        detail:
          `The "${serverName}" server has a literal value for "${key}". Configuration files are copied between ` +
          'machines, committed by mistake, and read by every process that can reach the file. ' +
          (matched ? `The value matches a ${matched.name}, so it is a live credential rather than a placeholder.` : ''),
        remedy:
          'Move the value out of the file and reference it indirectly, then rotate it. Anything that has sat in a ' +
          'config file should be considered exposed.',
        location: { file, server: serverName, field: `${kind}.${key}` },
        signals,
      })
    );
  }

  return findings;
}

function analyzeLaunch(server, name, file) {
  const findings = [];
  const command = String(server.command ?? '');
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  const joined = [command, ...args].join(' ');
  const binary = command.split(/[\\/]/).pop() ?? '';

  // Shell wrapper with an inline script.
  if (SHELL_WRAPPERS.test(binary) && args.some((a) => /^-{1,2}(?:c|Command)$/i.test(a))) {
    findings.push(
      finding({
        rule: 'config/shell-launch',
        owasp: owasp('MCP05'),
        severity: 'high',
        title: 'Server is launched through a shell with an inline script',
        detail:
          `"${name}" runs "${joined}". Anything the script interpolates is evaluated by the shell, and the launch ` +
          'string is a single line in a config file that nobody reviews after the first setup.',
        remedy: 'Invoke the server binary directly with arguments as separate array entries.',
        location: { file, server: name, field: 'command' },
        signals: [
          signal('shell-wrapper', 3, `command is ${binary}`),
          signal('inline-script', 3, 'arguments contain an inline script flag'),
        ],
      })
    );
  }

  // Fetch and execute in one step.
  if (/\b(?:curl|wget|iwr|Invoke-WebRequest)\b[\s\S]*\|[\s\S]*\b(?:sh|bash|zsh|python\d?|node)\b/i.test(joined)) {
    findings.push(
      finding({
        rule: 'config/remote-code-execution',
        owasp: owasp('MCP04'),
        severity: 'critical',
        title: 'Launch command downloads and executes code',
        detail:
          `"${name}" pipes a download straight into an interpreter. Whatever that URL serves runs with your user's ` +
          'privileges every time the server starts, and the content can change between launches without any signal.',
        remedy: 'Pin and vendor the dependency, or install it through a package manager with a lockfile.',
        location: { file, server: name, field: 'args' },
        signals: [
          signal('download-to-interpreter', 4, 'a fetch is piped into a shell or interpreter'),
          signal('mutable-source', 3, 'the executed content can change without notice'),
        ],
      })
    );
  }

  // Unpinned package resolution.
  const pkgArg = args.find((a) => /^(?:@[\w.-]+\/)?[\w.-]+(?:@[\w.-]+)?$/.test(a) && !a.startsWith('-'));
  const usesNpx = /^(?:npx|pnpm|bunx|uvx|uv)$/i.test(binary);
  if (usesNpx && pkgArg) {
    const pinned = /@[\d]+\.[\d]+\.[\d]+/.test(pkgArg);
    const latest = /@latest$/.test(pkgArg);
    if (!pinned) {
      findings.push(
        finding({
          rule: 'config/unpinned-dependency',
          owasp: owasp('MCP04'),
          severity: latest ? 'high' : 'medium',
          title: 'Server package is resolved at launch without a pinned version',
          detail:
            `"${name}" runs ${binary} ${pkgArg}. The published package is re-resolved every start, so a compromised ` +
            'or simply changed release reaches your machine with no review step. Tool descriptions can change this ' +
            'way too, which is the rug pull variant of tool poisoning.',
          remedy: `Pin an exact version, for example ${pkgArg.replace(/@[\w.-]+$/, '')}@1.2.3, and run "mcpaudit pin" to record the tool descriptions you approved.`,
          location: { file, server: name, field: 'args' },
          signals: [
            signal('unpinned-package', latest ? 3 : 2.5, latest ? 'explicitly tracks @latest' : 'no exact version specified'),
            signal('resolved-each-launch', 1.5, `${binary} re-resolves the package on every start`),
          ],
        })
      );
    }
  }

  // Filesystem scope.
  const broadRoot = args.find((a) => /^(?:\/|~|\/home\/[^/]+|\/Users\/[^/]+|[A-Za-z]:\\?)$/.test(a) || /^(?:~|\/)$/.test(a));
  if (broadRoot) {
    findings.push(
      finding({
        rule: 'config/broad-filesystem-scope',
        owasp: owasp('MCP02'),
        severity: 'high',
        title: 'Server is granted a very broad filesystem root',
        detail:
          `"${name}" is configured with "${broadRoot}" as an allowed path. Every tool this server exposes can reach ` +
          'anything under it, including SSH keys, browser profiles and other projects. A prompt injection anywhere in ' +
          'the session inherits that reach.',
        remedy: 'Scope the server to the specific project directories it needs.',
        location: { file, server: name, field: 'args' },
        signals: [
          signal('root-or-home-scope', 3, `path "${broadRoot}" covers the whole user or machine`),
          signal('unbounded-tool-reach', 2, 'all tools on this server inherit the scope'),
        ],
      })
    );
  }

  return findings;
}

function analyzeTransport(server, name, file) {
  const findings = [];
  const url = server.url ?? server.endpoint;
  if (!url || typeof url !== 'string') return findings;

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return findings;
  }

  // Loopback and "every interface" are not the same thing, and lumping them
  // together loses the more interesting of the two. 127/8 and ::1 are only
  // reachable from this machine. 0.0.0.0 and :: are what a server binds to
  // when it is listening on every interface, so a config carrying one is
  // evidence the endpoint is exposed rather than evidence that it is private.
  const loopback = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1)$/i.test(parsed.hostname);
  const allInterfaces = /^(?:0\.0\.0\.0|\[::\]|::)$/.test(parsed.hostname);

  // The connection itself does not leave the host in either case, so there is
  // nobody on the path to rewrite tool descriptions in transit.
  if (parsed.protocol === 'http:' && !loopback && !allInterfaces) {
    findings.push(
      finding({
        rule: 'config/cleartext-transport',
        owasp: owasp('MCP07'),
        severity: 'high',
        title: 'Remote server is reached over plain HTTP',
        detail:
          `"${name}" connects to ${url}. Tool arguments, results and any authorization header travel in cleartext, ` +
          'and anyone on the path can modify tool descriptions in transit.',
        remedy: 'Use HTTPS.',
        location: { file, server: name, field: 'url' },
        signals: [
          signal('cleartext-remote', 3, 'http scheme to a non-local host'),
          signal('mutable-in-transit', 3, 'tool metadata can be rewritten by a network attacker'),
        ],
      })
    );
  }

  const headers = server.headers ?? {};
  const hasAuth = Object.keys(headers).some((h) => /^(?:authorization|x-api-key|x-auth|proxy-authorization)$/i.test(h));
  if (!hasAuth && !loopback) {
    findings.push(
      finding({
        rule: 'config/unauthenticated-remote',
        owasp: owasp('MCP07'),
        severity: 'medium',
        title: allInterfaces
          ? 'Server listens on every interface without an authorization header'
          : 'Remote server is configured without an authorization header',
        detail: allInterfaces
          ? `"${name}" points at ${parsed.origin}. That address is not loopback: it is what a server binds to when it ` +
            'accepts connections on every interface, and there is no authorization or API key header here, so anything ' +
            'that can route to this host can call the server. An unauthenticated MCP endpoint is reachable by more than ' +
            'the agent it was meant for.'
          : `"${name}" points at ${parsed.origin} with no authorization or API key header. Either the endpoint is open ` +
            'to anyone who knows the URL, or authentication happens somewhere this config does not show.',
        remedy: allInterfaces
          ? 'Bind to 127.0.0.1 if only this machine should reach it, or require an authorization header if it is meant to be shared.'
          : 'Confirm how the endpoint authenticates callers. If it does not, treat every result it returns as untrusted input.',
        location: { file, server: name, field: 'headers' },
        signals: [
          signal('no-auth-header', 2.5, 'no authorization, x-api-key or equivalent header'),
          allInterfaces
            ? signal('all-interfaces-bind', 1.5, `${parsed.hostname} accepts connections on every interface`)
            : signal('remote-endpoint', 1.5, `non-local host ${parsed.hostname}`),
        ],
      })
    );
  }

  return findings;
}

/**
 * @param {object} config parsed MCP configuration
 * @param {string} file   path it came from
 */
export function analyzeConfig(config, file) {
  const findings = [];

  // Covers claude_desktop_config.json, .mcp.json, .vscode/mcp.json and the
  // Codex and Cursor equivalents, which all nest servers under one of these.
  const servers = config.mcpServers ?? config.servers ?? config.mcp?.servers ?? {};

  for (const [name, server] of Object.entries(servers)) {
    if (!server || typeof server !== 'object') continue;

    findings.push(...analyzeEnvBlock(server.env, name, file, 'env'));
    findings.push(...analyzeEnvBlock(server.headers, name, file, 'headers'));
    findings.push(...analyzeLaunch(server, name, file));
    findings.push(...analyzeTransport(server, name, file));
  }

  return findings;
}

export const _internals = { shannon, isPlaceholder, SECRET_PATTERNS };
