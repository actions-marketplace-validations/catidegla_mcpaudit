/**
 * Finds things worth auditing.
 *
 * Two modes. Given a path, walk it for MCP configuration, tool manifests and
 * agent skills. Given no path, look in the well-known locations where clients
 * keep their server lists, which is how you find the servers someone actually
 * has installed rather than the ones a repository declares.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, basename, extname, resolve } from 'node:path';
import { homedir, platform } from 'node:os';

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', 'vendor',
  '.next', '.nuxt', '.venv', 'venv', '__pycache__', '.pytest_cache', 'target',
]);

const CONFIG_NAMES = new Set([
  'claude_desktop_config.json',
  '.mcp.json',
  'mcp.json',
  'mcp_settings.json',
  'cline_mcp_settings.json',
]);

const MAX_BYTES = 4 * 1024 * 1024;

const exists = (p) => stat(p).then(() => true, () => false);

/** Well-known client configuration paths for the current platform. */
export function wellKnownConfigPaths() {
  const home = homedir();
  const os = platform();

  const claudeDesktop =
    os === 'win32'
      ? join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
      : os === 'darwin'
        ? join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
        : join(home, '.config', 'Claude', 'claude_desktop_config.json');

  return [
    claudeDesktop,
    join(home, '.claude.json'),
    join(home, '.cursor', 'mcp.json'),
    join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    join(home, '.vscode', 'mcp.json'),
  ];
}

function isConfigCandidate(name) {
  return CONFIG_NAMES.has(name) || /\.mcp\.json$/i.test(name);
}

/**
 * Does this JSON look like MCP configuration, rather than any other JSON that
 * happens to be named mcp.json?
 */
export function looksLikeMcpConfig(parsed) {
  if (!parsed || typeof parsed !== 'object') return false;
  const servers = parsed.mcpServers ?? parsed.servers ?? parsed.mcp?.servers;
  return Boolean(servers && typeof servers === 'object' && Object.keys(servers).length);
}

/**
 * Pull every name and description pair out of an arbitrary structure. Tool
 * manifests, tools/list responses and plugin descriptors all nest differently,
 * so shape matching beats trying to know every schema.
 */
export function extractDescribedItems(value, path = [], out = []) {
  if (Array.isArray(value)) {
    value.forEach((item, i) => extractDescribedItems(item, [...path, String(i)], out));
    return out;
  }
  if (!value || typeof value !== 'object') return out;

  const name = typeof value.name === 'string' ? value.name : null;

  for (const field of ['description', 'instructions', 'prompt', 'template', 'systemPrompt', 'text', 'title']) {
    const text = value[field];
    if (typeof text === 'string' && text.trim().length >= 8) {
      out.push({ name: name ?? path[path.length - 1] ?? 'unnamed', field, text, path: path.join('.') });
    }
  }

  // Parameter descriptions are metadata too, and are a known injection surface
  // because reviewers read the tool description and stop there.
  if (value.inputSchema?.properties && typeof value.inputSchema.properties === 'object') {
    for (const [param, schema] of Object.entries(value.inputSchema.properties)) {
      if (schema && typeof schema.description === 'string' && schema.description.trim().length >= 8) {
        out.push({
          name: name ? `${name}.${param}` : param,
          field: 'inputSchema.description',
          text: schema.description,
          path: [...path, 'inputSchema', param].join('.'),
        });
      }
    }
  }

  for (const [key, child] of Object.entries(value)) {
    if (key === 'inputSchema') continue;
    if (child && typeof child === 'object') extractDescribedItems(child, [...path, key], out);
  }

  return out;
}

async function readJson(file) {
  const raw = await readFile(file, 'utf8');
  if (raw.length > MAX_BYTES) return null;
  try {
    return { raw, parsed: JSON.parse(raw) };
  } catch {
    return { raw, parsed: null };
  }
}

async function classify(file) {
  const name = basename(file);

  if (name === 'SKILL.md') {
    const raw = await readFile(file, 'utf8');
    return { file, kind: 'skill', raw };
  }

  if (extname(file).toLowerCase() !== '.json') return null;

  const loaded = await readJson(file);
  if (!loaded || loaded.parsed === null) return null;

  if (isConfigCandidate(name) && looksLikeMcpConfig(loaded.parsed)) {
    return { file, kind: 'config', ...loaded };
  }

  // Any JSON carrying described, named items is worth checking for injected
  // metadata even if it is not a config file.
  const items = extractDescribedItems(loaded.parsed);
  if (items.length) return { file, kind: 'manifest', ...loaded, items };

  return null;
}

async function walk(dir, depth, results) {
  if (depth < 0) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const full = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      // Hidden directories are skipped except the ones that hold agent config.
      if (entry.name.startsWith('.') && !['.claude', '.cursor', '.vscode', '.codex', '.gemini', '.agents'].includes(entry.name)) continue;
      await walk(full, depth - 1, results);
      continue;
    }

    if (!entry.isFile()) continue;
    if (entry.name !== 'SKILL.md' && extname(entry.name).toLowerCase() !== '.json') continue;

    try {
      const target = await classify(full);
      if (target) results.push(target);
    } catch {
      // Unreadable or oversized files are skipped rather than failing the run.
    }
  }
}

/**
 * @param {string|null} path  directory or file to scan, null for well-known locations
 * @param {object} options
 * @returns {Promise<Array>} targets
 */
export async function discover(path, { depth = 6 } = {}) {
  const results = [];

  if (!path) {
    for (const candidate of wellKnownConfigPaths()) {
      if (!(await exists(candidate))) continue;
      try {
        const target = await classify(candidate);
        if (target) results.push(target);
      } catch {
        // ignore
      }
    }
    return results;
  }

  const full = resolve(path);
  const info = await stat(full);

  if (info.isFile()) {
    const target = await classify(full);
    if (target) results.push(target);
    return results;
  }

  await walk(full, depth, results);
  return results;
}
