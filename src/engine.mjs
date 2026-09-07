/**
 * Runs the analyzers over discovered targets and reconciles the results.
 *
 * Also owns the baseline. Static analysis catches a server that arrives
 * hostile; the baseline catches one that turns hostile later, which is the
 * variant that matters most for anything installed unpinned from a registry.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { relative } from 'node:path';

import { analyzeConcealment } from './analyzers/concealment.mjs';
import { analyzePoisoning } from './analyzers/poisoning.mjs';
import { analyzeConfig } from './analyzers/config.mjs';
import { owasp } from './owasp.mjs';
import { finding, signal, bySeverity } from './finding.mjs';
import { extractDescribedItems } from './discover.mjs';

export const BASELINE_FILE = '.mcpaudit-baseline.json';

/** Frontmatter plus body, so a SKILL.md is analyzed the same way as a tool. */
function skillItems(raw, file) {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---([\s\S]*)$/);
  const items = [];

  if (match) {
    const description = match[1].match(/^description:\s*([\s\S]*?)(?=\n[a-zA-Z_-]+:|$)/m);
    if (description) items.push({ name: file, field: 'description', text: description[1].trim() });
    items.push({ name: file, field: 'body', text: match[2] });
  } else {
    items.push({ name: file, field: 'body', text: raw });
  }

  return items.filter((i) => i.text && i.text.trim().length >= 8);
}

/**
 * Locate an item in the raw file.
 *
 * Offsets returned by the analyzers are relative to the extracted string, not
 * the file, so reporting them directly would point every JSON finding at line
 * 1 and put GitHub annotations in the wrong place. Searching the raw text for
 * the declaring key gives the real line instead.
 */
function lineOfItem(raw, item) {
  if (!raw) return null;

  const candidates = [
    `"name": ${JSON.stringify(item.name)}`,
    `"name":${JSON.stringify(item.name)}`,
    JSON.stringify(item.name),
  ];

  for (const needle of candidates) {
    const index = raw.indexOf(needle);
    if (index !== -1) return raw.slice(0, index).split('\n').length;
  }
  return null;
}

function analyzeMetadata(items, file, raw = null) {
  const findings = [];

  for (const item of items) {
    const line = lineOfItem(raw, item);
    const location = { file, tool: item.name, field: item.field, ...(line ? { line } : {}) };

    // Drop the intra-string offsets the analyzers attach, keeping the file line.
    const fix = (f) => ({
      ...f,
      location: { ...f.location, ...(line ? { line, column: undefined } : { line: undefined, column: undefined }) },
    });

    findings.push(...analyzeConcealment(item.text, location).map(fix));
    findings.push(...analyzePoisoning(item.text, location).map(fix));
  }

  return findings;
}

/** Stable identity for a finding, used for deduplication and suppression. */
function fingerprint(f) {
  return createHash('sha256')
    .update([f.rule, f.location.file ?? '', f.location.server ?? '', f.location.tool ?? '', f.location.field ?? ''].join('\0'))
    .digest('hex')
    .slice(0, 16);
}

function suppressed(f, ignore) {
  return ignore.some((pattern) => {
    if (pattern === f.rule) return true;
    if (pattern.endsWith('/*') && f.rule.startsWith(pattern.slice(0, -1))) return true;
    if (pattern.includes('@')) {
      const [rule, file] = pattern.split('@');
      return f.rule === rule && (f.location.file ?? '').includes(file);
    }
    return false;
  });
}

/**
 * @param {Array} targets   from discover()
 * @param {object} options  { root, ignore }
 */
export function analyze(targets, { root = process.cwd(), ignore = [] } = {}) {
  const findings = [];

  for (const target of targets) {
    const file = relative(root, target.file) || target.file;

    if (target.kind === 'config') {
      findings.push(...analyzeConfig(target.parsed, file));
      // Configs can also carry injected metadata, for instance a server entry
      // with a description field that the client shows to the model.
      findings.push(...analyzeMetadata(extractDescribedItems(target.parsed), file, target.raw));
      continue;
    }

    if (target.kind === 'manifest') {
      findings.push(...analyzeMetadata(target.items ?? [], file, target.raw));
      continue;
    }

    if (target.kind === 'skill') {
      findings.push(...analyzeMetadata(skillItems(target.raw, file), file));
    }
  }

  const seen = new Set();
  const deduped = [];

  for (const f of findings) {
    const id = fingerprint(f);
    if (seen.has(id)) continue;
    seen.add(id);
    if (suppressed(f, ignore)) continue;
    deduped.push({ ...f, fingerprint: id });
  }

  return deduped.sort(bySeverity);
}

/* ---------------------------------------------------------------- baseline */

function itemsOf(target) {
  if (target.kind === 'skill') return skillItems(target.raw, target.file);
  if (target.kind === 'manifest') return target.items ?? [];
  if (target.kind === 'config') return extractDescribedItems(target.parsed);
  return [];
}

const digest = (text) => createHash('sha256').update(text).digest('hex').slice(0, 32);

/** Snapshot every piece of metadata a model would see. */
export function buildBaseline(targets, { root = process.cwd() } = {}) {
  const entries = {};

  for (const target of targets) {
    const file = relative(root, target.file) || target.file;
    for (const item of itemsOf(target)) {
      entries[`${file}::${item.name}::${item.field}`] = {
        hash: digest(item.text),
        length: item.text.length,
      };
    }
  }

  return {
    version: 1,
    createdAt: new Date().toISOString(),
    entries,
  };
}

/**
 * Compare current metadata against an approved snapshot.
 *
 * A description that changes after approval is the rug pull: the package was
 * reviewed at install, then a later version rewrote what the model is told.
 */
export function verifyBaseline(targets, baseline, { root = process.cwd() } = {}) {
  const current = buildBaseline(targets, { root });
  const findings = [];

  const previous = baseline?.entries ?? {};
  const currentKeys = new Set(Object.keys(current.entries));

  for (const [key, now] of Object.entries(current.entries)) {
    const before = previous[key];
    const [file, tool, field] = key.split('::');

    if (!before) {
      findings.push(
        finding({
          rule: 'baseline/new-metadata',
          owasp: owasp('MCP03'),
          severity: 'medium',
          title: 'Metadata appeared that was not in the approved baseline',
          detail:
            `"${tool}" has a ${field} that did not exist when the baseline was recorded. A new tool or a new ` +
            'parameter description is new instruction text reaching the model, and it has not been reviewed.',
          remedy: 'Read the new metadata, then re-pin with "mcpaudit pin" once you accept it.',
          location: { file, tool, field },
          signals: [
            signal('absent-from-baseline', 2.5, 'no recorded hash for this item'),
            signal('unreviewed-instruction-text', 1.5, `${now.length} characters the model will receive`),
          ],
        })
      );
      continue;
    }

    if (before.hash !== now.hash) {
      const delta = now.length - before.length;
      findings.push(
        finding({
          rule: 'baseline/metadata-changed',
          owasp: owasp('MCP03'),
          severity: 'high',
          title: 'Approved metadata changed after it was pinned',
          detail:
            `The ${field} of "${tool}" no longer matches the approved baseline (${before.length} characters then, ` +
            `${now.length} now, a change of ${delta >= 0 ? '+' : ''}${delta}). This is the rug pull pattern: a server ` +
            'is reviewed at install, then a later version rewrites what the model is told to do with it.',
          remedy: 'Diff the description against the pinned version before using this server again. Pin the package version too.',
          location: { file, tool, field },
          signals: [
            signal('hash-mismatch', 3, 'content differs from the approved snapshot'),
            signal('size-change', Math.abs(delta) > 80 ? 2 : 0.5, `length changed by ${delta} characters`),
          ],
        })
      );
    }
  }

  for (const key of Object.keys(previous)) {
    if (currentKeys.has(key)) continue;
    const [file, tool, field] = key.split('::');
    findings.push(
      finding({
        rule: 'baseline/metadata-removed',
        owasp: owasp('MCP03'),
        severity: 'low',
        title: 'Pinned metadata is no longer present',
        detail: `"${tool}" no longer exposes a ${field} that was in the baseline. Usually a removed tool, occasionally a rename.`,
        remedy: 'Confirm the removal is expected, then re-pin.',
        location: { file, tool, field },
        signals: [signal('missing-from-current', 2, 'present in baseline, absent now')],
      })
    );
  }

  return findings.map((f) => ({ ...f, fingerprint: fingerprint(f) })).sort(bySeverity);
}

export async function readBaseline(file = BASELINE_FILE) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch {
    return null;
  }
}

export async function writeBaseline(baseline, file = BASELINE_FILE) {
  await writeFile(file, `${JSON.stringify(baseline, null, 2)}\n`);
}
