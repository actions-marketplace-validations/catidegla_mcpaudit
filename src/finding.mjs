/**
 * The finding model, and the scoring that decides what gets shown.
 *
 * The design constraint for this tool is false positives. Scanners that flag
 * every occurrence of the word "ignore" in a tool description train people to
 * skip the report, which is worse than not scanning. So no rule reports on a
 * single weak match. A finding is built from independent signals, and the
 * combination decides confidence.
 */

export const SEVERITY = { critical: 4, high: 3, medium: 2, low: 1 };
export const CONFIDENCE = { high: 3, medium: 2, low: 1 };

/** Score thresholds for turning accumulated signal weight into a confidence. */
const HIGH_AT = 6;
const MEDIUM_AT = 3.5;

/**
 * A single piece of evidence. Weight reflects how much this observation moves
 * the needle on its own:
 *
 *   3.0  near-conclusive, essentially never benign (invisible control chars)
 *   2.0  strong, benign explanations exist but are uncommon
 *   1.0  supporting, meaningless alone
 *  -2.0  dampener, an observation that argues the match is legitimate
 */
export function signal(name, weight, detail, extra = {}) {
  return { name, weight, detail, ...extra };
}

export function scoreOf(signals) {
  return signals.reduce((total, s) => total + s.weight, 0);
}

export function confidenceFrom(signals) {
  const score = scoreOf(signals);
  if (score >= HIGH_AT) return 'high';
  if (score >= MEDIUM_AT) return 'medium';
  return 'low';
}

/**
 * @param {object} input
 * @param {string} input.rule        stable rule id, used for suppression
 * @param {string} input.owasp       OWASP MCP category object
 * @param {string} input.severity    impact if real
 * @param {string} input.title       one line, states the defect
 * @param {string} input.detail      what an attacker gains
 * @param {object} input.location    { file, line?, column?, tool?, snippet? }
 * @param {Array}  input.signals     evidence, see signal()
 * @param {string} [input.remedy]    what to do about it
 */
export function finding({ rule, owasp, severity, title, detail, location, signals = [], remedy }) {
  const confidence = confidenceFrom(signals);

  return {
    rule,
    owasp: owasp.id,
    owaspTitle: owasp.title,
    severity,
    confidence,
    score: Number(scoreOf(signals).toFixed(1)),
    title,
    detail,
    remedy: remedy ?? null,
    location,
    evidence: signals
      .filter((s) => s.weight > 0)
      .map((s) => ({ signal: s.name, detail: s.detail })),
    dampeners: signals
      .filter((s) => s.weight < 0)
      .map((s) => ({ signal: s.name, detail: s.detail })),
  };
}

/** Sort worst first: severity, then confidence, then score. */
export function bySeverity(a, b) {
  return (
    SEVERITY[b.severity] - SEVERITY[a.severity] ||
    CONFIDENCE[b.confidence] - CONFIDENCE[a.confidence] ||
    b.score - a.score ||
    a.rule.localeCompare(b.rule)
  );
}

/**
 * Low confidence findings are hidden unless asked for. They are kept in the
 * data rather than dropped, so --all and the JSON report can still show them.
 */
export function visible(findings, { minConfidence = 'medium' } = {}) {
  const floor = CONFIDENCE[minConfidence];
  return findings.filter((f) => CONFIDENCE[f.confidence] >= floor);
}

/** Line and column for an offset, so reports can point at the exact character. */
export function positionOf(text, offset) {
  const before = text.slice(0, offset);
  const line = before.split('\n').length;
  const column = offset - before.lastIndexOf('\n');
  return { line, column };
}
