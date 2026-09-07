/**
 * Terminal output.
 *
 * Ordered worst first, evidence shown inline. The evidence lines matter: a
 * security tool that says "possible prompt injection" and stops has moved the
 * work onto the reader rather than doing it.
 */

const useColour = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, s) => (useColour ? `\x1b[${code}m${s}\x1b[0m` : s);

const c = {
  dim: (s) => paint('2', s),
  bold: (s) => paint('1', s),
  red: (s) => paint('31', s),
  brightRed: (s) => paint('91', s),
  yellow: (s) => paint('33', s),
  blue: (s) => paint('34', s),
  green: (s) => paint('32', s),
  grey: (s) => paint('90', s),
};

const BADGE = {
  critical: () => paint('41;97', ' CRITICAL '),
  high: () => paint('31;1', ' HIGH     '),
  medium: () => paint('33', ' MEDIUM   '),
  low: () => paint('90', ' LOW      '),
};

function wrap(text, width, indent) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';

  for (const word of words) {
    if (line && (line + word).length + 1 > width) {
      lines.push(line);
      line = '';
    }
    line += (line ? ' ' : '') + word;
  }
  if (line) lines.push(line);

  return lines.map((l) => indent + l).join('\n');
}

function locationOf(f) {
  const parts = [f.location.file];
  if (f.location.line) parts[0] += `:${f.location.line}`;
  const detail = [f.location.server, f.location.tool, f.location.field].filter(Boolean).join(' / ');
  return detail ? `${parts[0]}  ${c.grey(detail)}` : parts[0];
}

export function renderFindings(findings, { hidden = 0, scanned = 0, width = 96 } = {}) {
  const out = [];
  const w = Math.min(width, (process.stdout.columns ?? 100) - 4);

  if (!findings.length) {
    out.push('');
    out.push(`  ${c.green('No findings.')} ${c.dim(`${scanned} file(s) scanned.`)}`);
    if (hidden) out.push(`  ${c.dim(`${hidden} low confidence observation(s) suppressed. Use --all to see them.`)}`);
    out.push('');
    return out.join('\n');
  }

  out.push('');
  for (const f of findings) {
    out.push(`${BADGE[f.severity]()} ${c.bold(f.title)}`);
    out.push(`  ${locationOf(f)}`);
    out.push(`  ${c.dim(`${f.rule}  ${f.owasp} ${f.owaspTitle}  confidence ${f.confidence} (${f.score})`)}`);
    out.push('');
    out.push(c.grey(wrap(f.detail, w - 4, '  ')));

    if (f.evidence.length) {
      out.push('');
      out.push(`  ${c.dim('Evidence')}`);
      for (const e of f.evidence) {
        out.push(`    ${c.blue('*')} ${c.dim(`${e.signal}:`)} ${e.detail}`);
      }
    }

    if (f.dampeners?.length) {
      out.push(`  ${c.dim('Counter-evidence')}`);
      for (const d of f.dampeners) {
        out.push(`    ${c.dim(`- ${d.signal}: ${d.detail}`)}`);
      }
    }

    if (f.remedy) {
      out.push('');
      out.push(c.green(wrap(`Fix: ${f.remedy}`, w - 4, '  ')));
    }

    out.push('');
    out.push(c.dim('  ' + '-'.repeat(Math.max(20, w - 4))));
    out.push('');
  }

  return out.join('\n');
}

export function renderSummary(findings, { hidden = 0, scanned = 0, elapsedMs = 0 } = {}) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;

  const byOwasp = new Map();
  for (const f of findings) {
    byOwasp.set(f.owasp, (byOwasp.get(f.owasp) ?? 0) + 1);
  }

  const parts = [];
  if (counts.critical) parts.push(c.brightRed(`${counts.critical} critical`));
  if (counts.high) parts.push(c.red(`${counts.high} high`));
  if (counts.medium) parts.push(c.yellow(`${counts.medium} medium`));
  if (counts.low) parts.push(c.grey(`${counts.low} low`));

  const lines = [];
  lines.push(c.bold(parts.length ? `  ${parts.join(c.dim('  |  '))}` : c.green('  Clean')));

  if (byOwasp.size) {
    const owaspLine = [...byOwasp.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([id, n]) => `${id} x${n}`)
      .join('  ');
    lines.push(c.dim(`  ${owaspLine}`));
  }

  lines.push(
    c.dim(`  ${scanned} file(s) in ${elapsedMs}ms` + (hidden ? `, ${hidden} low confidence observation(s) hidden (--all)` : ''))
  );

  return `\n${lines.join('\n')}\n`;
}
