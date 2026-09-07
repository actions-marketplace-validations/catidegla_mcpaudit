/**
 * Text that is present but not visible.
 *
 * This is the highest-precision analyzer in the tool. Legitimate tool
 * descriptions do not contain Unicode tag characters, bidi overrides, or
 * base64 that decodes to English imperatives. When these fire, they are real,
 * so they carry near-conclusive weight and their findings are reported even
 * when nothing else corroborates.
 *
 * The interesting property of most of these encodings is that they are
 * reversible, so the report can show the operator the hidden text rather than
 * telling them that something suspicious exists somewhere.
 */

import { owasp } from '../owasp.mjs';
import { finding, signal, positionOf } from '../finding.mjs';

// U+E0000 to U+E007F. Subtracting the base yields an ASCII codepoint, which
// makes this block a complete invisible channel for arbitrary text.
const TAG_RANGE = /[\u{E0000}-\u{E007F}]/gu;

// Variation selectors. VS1-16 carry 0-15, the supplement carries 16-255, so a
// sequence of them encodes arbitrary bytes.
const VARIATION_RANGE = /[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/gu;

const ZERO_WIDTH = /[​‌‍⁠⁡⁢⁣⁤﻿­͏؜᠎]/g;

// Trojan Source. Reorders how text renders without changing what it contains.
// Deliberately excludes U+200E and U+200F, the plain left-to-right and
// right-to-left marks, which appear legitimately in Arabic and Hebrew text.
// Only the embedding, override and isolate controls are flagged.
const BIDI = /[\u{202A}-\u{202E}\u{2066}-\u{2069}]/gu;

const PRIVATE_USE = /[\u{E000}-\u{F8FF}\u{F0000}-\u{FFFFD}]/gu;

const HTML_COMMENT = /<!--([\s\S]*?)-->/g;

// Long enough that prose and identifiers do not reach it by accident.
const BASE64_BLOB = /\b[A-Za-z0-9+/]{40,}={0,2}\b/g;

// Many blank lines followed by more content pushes text out of a preview pane.
const WHITESPACE_GAP = /(\n[ \t]*){8,}\n/g;

/** Imperative-sounding English, used to judge whether decoded bytes matter. */
const IMPERATIVE = /\b(ignore|disregard|instead|must|always|never|do not|don't|send|read|fetch|execute|run|reveal|output|print|include|forward|exfiltrat|secret|token|password|credential|api[_ -]?key|\.ssh|id_rsa|\.env)\b/i;

function decodeTags(text) {
  const chars = [...text].filter((c) => /[\u{E0000}-\u{E007F}]/u.test(c));
  return chars.map((c) => String.fromCodePoint(c.codePointAt(0) - 0xe0000)).join('');
}

function decodeVariationSelectors(text) {
  const bytes = [];
  for (const c of text) {
    const cp = c.codePointAt(0);
    if (cp >= 0xfe00 && cp <= 0xfe0f) bytes.push(cp - 0xfe00);
    else if (cp >= 0xe0100 && cp <= 0xe01ef) bytes.push(cp - 0xe0100 + 16);
  }
  if (!bytes.length) return '';
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(Uint8Array.from(bytes));
  } catch {
    return '';
  }
}

function decodeBase64(candidate) {
  try {
    const text = Buffer.from(candidate, 'base64').toString('utf8');
    // Reject binary. Printable ASCII plus whitespace only.
    if (!/^[\x20-\x7E\s]{8,}$/.test(text)) return null;
    return text;
  } catch {
    return null;
  }
}

function printable(text, limit = 200) {
  const clean = text.replace(/\s+/g, ' ').trim();
  return clean.length > limit ? `${clean.slice(0, limit)}...` : clean;
}

function countMatches(text, pattern) {
  pattern.lastIndex = 0;
  return (text.match(pattern) ?? []).length;
}

/**
 * @param {string} text     the content to inspect
 * @param {object} location { file, tool?, field? }
 * @returns {Array} findings
 */
export function analyzeConcealment(text, location) {
  if (!text || typeof text !== 'string') return [];
  const findings = [];

  const at = (pattern) => {
    pattern.lastIndex = 0;
    const m = pattern.exec(text);
    return m ? positionOf(text, m.index) : {};
  };

  // Unicode tag characters. There is no legitimate use of this block in a tool
  // description, so a single occurrence is conclusive.
  const tagCount = countMatches(text, TAG_RANGE);
  if (tagCount) {
    const hidden = decodeTags(text);
    findings.push(
      finding({
        rule: 'concealment/unicode-tags',
        owasp: owasp('MCP03'),
        severity: 'critical',
        title: 'Hidden instructions encoded in Unicode tag characters',
        detail:
          'The text contains characters from the Unicode Tags block (U+E0000 to U+E007F), which render as nothing. ' +
          'They decode directly to ASCII, so this is a complete invisible channel for instructions the operator never sees. ' +
          (hidden ? `The concealed text reads: "${printable(hidden)}"` : ''),
        remedy: 'Treat this server as hostile. Strip the characters and diff what remains against what was reviewed.',
        location: { ...location, ...at(TAG_RANGE) },
        signals: [
          signal('unicode-tag-block', 3, `${tagCount} tag character(s) present`),
          signal('decodes-to-text', hidden ? 3 : 0, hidden ? `decodes to ${hidden.length} characters of readable text` : ''),
          signal('imperative-payload', hidden && IMPERATIVE.test(hidden) ? 2 : 0, 'decoded text contains instruction verbs'),
        ].filter((s) => s.weight !== 0),
      })
    );
  }

  const vsCount = countMatches(text, VARIATION_RANGE);
  if (vsCount >= 4) {
    const hidden = decodeVariationSelectors(text);
    const readable = hidden && /[\x20-\x7E]{6,}/.test(hidden);
    findings.push(
      finding({
        rule: 'concealment/variation-selectors',
        owasp: owasp('MCP03'),
        severity: 'critical',
        title: 'Data smuggled in Unicode variation selectors',
        detail:
          `${vsCount} variation selectors appear in this text. A short run can be legitimate emoji styling, but a long ` +
          'sequence encodes arbitrary bytes invisibly. ' +
          (readable ? `The decoded bytes read: "${printable(hidden)}"` : 'The decoded bytes are not readable text.'),
        remedy: 'Remove the selectors and compare the result against the description that was approved.',
        location: { ...location, ...at(VARIATION_RANGE) },
        signals: [
          signal('variation-selector-run', vsCount >= 16 ? 3 : 2, `${vsCount} selectors in one field`),
          signal('decodes-to-text', readable ? 3 : 0, readable ? 'decoded bytes are printable text' : ''),
          signal('imperative-payload', readable && IMPERATIVE.test(hidden) ? 2 : 0, 'decoded text contains instruction verbs'),
        ].filter((s) => s.weight !== 0),
      })
    );
  }

  const bidiCount = countMatches(text, BIDI);
  if (bidiCount) {
    findings.push(
      finding({
        rule: 'concealment/bidi-override',
        owasp: owasp('MCP03'),
        severity: 'high',
        title: 'Bidirectional control characters change how this text renders',
        detail:
          `${bidiCount} bidi control character(s) present. These reorder displayed text without changing the underlying ` +
          'bytes, so what a reviewer reads and what the model receives can differ. This is the Trojan Source technique.',
        remedy: 'Strip the control characters and re-read the field as raw bytes.',
        location: { ...location, ...at(BIDI) },
        signals: [
          signal('bidi-controls', 3, `${bidiCount} embedding, override or isolate control(s) present`),
          signal('rendering-differs', 3, 'displayed order does not match byte order'),
        ],
      })
    );
  }

  const zwCount = countMatches(text, ZERO_WIDTH);
  if (zwCount >= 3) {
    findings.push(
      finding({
        rule: 'concealment/zero-width',
        owasp: owasp('MCP03'),
        severity: 'medium',
        title: 'Zero-width characters embedded in text',
        detail:
          `${zwCount} zero-width or invisible characters. In quantity these are used to break up keywords so that ` +
          'naive scanners miss them, or to encode a payload in the gaps between visible characters.',
        remedy: 'Normalise the text and confirm the visible content is unchanged.',
        location: { ...location, ...at(ZERO_WIDTH) },
        signals: [
          signal('zero-width-run', zwCount >= 10 ? 3 : 2, `${zwCount} invisible characters`),
          signal('keyword-splitting', /\w[​‌‍﻿]\w/.test(text) ? 2 : 0, 'invisible characters sit inside words'),
        ].filter((s) => s.weight !== 0),
      })
    );
  }

  const puaCount = countMatches(text, PRIVATE_USE);
  if (puaCount >= 2) {
    findings.push(
      finding({
        rule: 'concealment/private-use',
        owasp: owasp('MCP03'),
        severity: 'medium',
        title: 'Private use area characters in text',
        detail:
          `${puaCount} characters from a Unicode private use area. These have no assigned meaning and render ` +
          'differently depending on the font, so they are a way to hide content from a reviewer.',
        remedy: 'Confirm the characters are needed. In a tool description they almost never are.',
        location: { ...location, ...at(PRIVATE_USE) },
        signals: [signal('private-use-area', 2, `${puaCount} characters`), signal('no-legitimate-use', 2, 'private use codepoints in a metadata field')],
      })
    );
  }

  HTML_COMMENT.lastIndex = 0;
  for (const match of text.matchAll(HTML_COMMENT)) {
    const body = match[1] ?? '';
    if (body.trim().length < 12) continue;

    const imperative = IMPERATIVE.test(body);
    findings.push(
      finding({
        rule: 'concealment/html-comment',
        owasp: owasp('MCP06'),
        severity: imperative ? 'high' : 'low',
        title: 'Instructions inside an HTML comment',
        detail:
          'The field contains an HTML comment. Clients that render descriptions as markdown hide the comment from the ' +
          'operator, while the model receives the raw string including the comment body. ' +
          `Content: "${printable(body)}"`,
        remedy: 'Remove the comment, or move its content into the visible description.',
        location: { ...location, ...positionOf(text, match.index) },
        signals: [
          signal('hidden-from-renderer', 2, 'comment body is not displayed in a markdown view'),
          signal('imperative-content', imperative ? 3 : 0, 'comment contains instruction verbs or sensitive paths'),
          signal('short-comment', body.trim().length < 40 && !imperative ? -2 : 0, 'short comment with no instruction verbs, likely a note'),
        ].filter((s) => s.weight !== 0),
      })
    );
  }

  BASE64_BLOB.lastIndex = 0;
  for (const match of text.matchAll(BASE64_BLOB)) {
    const decoded = decodeBase64(match[0]);
    if (!decoded) continue;

    const imperative = IMPERATIVE.test(decoded);
    findings.push(
      finding({
        rule: 'concealment/base64-payload',
        owasp: owasp('MCP06'),
        severity: imperative ? 'high' : 'low',
        title: 'Base64 blob decoding to readable text',
        detail:
          'An encoded string in this field decodes to plain text. Encoding prose serves no functional purpose in a ' +
          `description and is a common way to get past keyword scanning. Decoded: "${printable(decoded)}"`,
        remedy: 'Decode it, read it, and decide whether the plain text belongs in the description at all.',
        location: { ...location, ...positionOf(text, match.index) },
        signals: [
          signal('encoded-prose', 2, `${match[0].length} character blob decodes to readable text`),
          signal('imperative-content', imperative ? 3 : 0, 'decoded text contains instruction verbs or sensitive paths'),
        ].filter((s) => s.weight !== 0),
      })
    );
  }

  WHITESPACE_GAP.lastIndex = 0;
  const gap = WHITESPACE_GAP.exec(text);
  if (gap && text.slice(gap.index + gap[0].length).trim().length > 20) {
    const after = text.slice(gap.index + gap[0].length);
    findings.push(
      finding({
        rule: 'concealment/whitespace-gap',
        owasp: owasp('MCP06'),
        severity: 'medium',
        title: 'Content pushed below a large run of blank lines',
        detail:
          'A long run of blank lines is followed by more text. In a client that truncates or previews descriptions the ' +
          `trailing content is not visible to the operator while still reaching the model. Trailing text: "${printable(after, 120)}"`,
        remedy: 'Collapse the whitespace and review what was below it.',
        location: { ...location, ...positionOf(text, gap.index) },
        signals: [
          signal('large-whitespace-run', 2, 'eight or more consecutive blank lines'),
          signal('content-after-gap', 2, `${after.trim().length} characters follow the gap`),
          signal('imperative-content', IMPERATIVE.test(after) ? 2 : 0, 'trailing content contains instruction verbs'),
        ].filter((s) => s.weight !== 0),
      })
    );
  }

  return findings;
}

export const _internals = { decodeTags, decodeVariationSelectors, decodeBase64 };
