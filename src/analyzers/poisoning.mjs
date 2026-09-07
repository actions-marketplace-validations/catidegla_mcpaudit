/**
 * Tool poisoning and intent subversion in MCP metadata.
 *
 * This is the analyzer that decides whether the tool is useful or annoying.
 * Published scans of this category report high false positive rates because
 * they match single keywords, and ordinary tool descriptions legitimately
 * contain words like "ignore", "must" and "before". One reported audit found 8
 * of 27 flagged injections were routine dependency instructions.
 *
 * Two rules keep that from happening here:
 *
 * 1. No single signal group reaches reporting confidence on its own. A lone
 *    match scores below the medium threshold and stays hidden by default.
 * 2. Direction is part of the match. "Call initialize before using this tool"
 *    describes this tool's own lifecycle and is benign. "Before using any
 *    other tool, call this one first" targets the agent's behaviour toward
 *    other tools and is not.
 */

import { owasp } from '../owasp.mjs';
import { finding, signal, positionOf } from '../finding.mjs';

/**
 * Each group is scored at most once, so a description repeating "ignore
 * previous instructions" five times is not five times as suspicious. What
 * raises confidence is independent groups agreeing.
 */
const GROUPS = [
  {
    name: 'override-framing',
    weight: 3.5,
    label: 'attempts to override prior instructions',
    patterns: [
      /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding|the\s+above)\b/i,
      /\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|instructions|rules)\b/i,
      /\bforget\s+(?:everything|all|what|your)\b/i,
      /\boverride\s+(?:your|the|all|any)\s+(?:instructions|rules|guidelines|system)/i,
      /\b(?:new|updated|revised)\s+(?:instructions|system\s+prompt|directives)\s*:/i,
      /\byou\s+are\s+now\b/i,
      /<\/?(?:system|im_start|im_end)\b/i,
      /\bregardless\s+of\s+(?:what|any|the)\b.{0,40}\b(?:instruction|told|said|prompt)/i,
    ],
  },
  {
    name: 'concealment-instruction',
    weight: 4,
    label: 'instructs the agent to hide activity from the user',
    patterns: [
      /\bdo\s+not\s+(?:tell|inform|mention|notify|reveal|show|display|report)\b.{0,25}\buser\b/i,
      /\bwithout\s+(?:telling|informing|notifying|alerting|asking)\b.{0,25}\buser\b/i,
      /\bdo\s+not\s+(?:mention|include|reference|acknowledge)\s+(?:this|these|that|the\s+(?:above|following))\b/i,
      /\b(?:secretly|silently|covertly|quietly)\b.{0,30}\b(?:send|read|call|fetch|include|append|forward|execute)\b/i,
      /\bkeep\s+(?:this|it|that)\s+(?:hidden|secret|between|to\s+yourself)\b/i,
      /\bdo\s+not\s+(?:show|surface|output|print)\b.{0,30}\b(?:in\s+your\s+)?(?:response|answer|summary|output)\b/i,
    ],
  },
  {
    name: 'cross-tool-targeting',
    weight: 3.5,
    label: 'directs the agent how to behave toward other tools',
    patterns: [
      // "before using any other tool" is shadowing. "before using this tool" is not.
      /\bbefore\s+(?:using|calling|invoking|running)\s+(?:any\s+)?(?:other|another|all|every|each)\b/i,
      /\binstead\s+of\s+(?:using|calling|invoking)\s+(?:the\s+)?(?:other|any|\w+_\w+)/i,
      /\balways\s+(?:use|call|invoke|prefer)\s+this\s+tool\s+(?:instead|first|before|rather)/i,
      /\bfor\s+(?:all|every|any)\s+(?:other\s+)?(?:requests?|queries|tasks?|tools?)\b.{0,30}\buse\s+this\b/i,
      /\b(?:do\s+not|never)\s+(?:use|call|invoke)\s+(?:the\s+)?(?:other|any\s+other)\s+tools?\b/i,
    ],
  },
  {
    name: 'sensitive-target',
    weight: 2.5,
    label: 'references credentials or sensitive paths',
    patterns: [
      /(?:~|\$HOME)?\/?\.ssh\/(?:id_[a-z0-9]+|config|authorized_keys)/i,
      /\bid_(?:rsa|ed25519|ecdsa|dsa)\b/i,
      /\.aws\/credentials\b/i,
      /\/etc\/(?:passwd|shadow)\b/i,
      /\b(?:read|open|load|cat|include|attach)\b.{0,30}\b(?:\.env|environment\s+variables?|secrets?\s+file)\b/i,
      /\b(?:private\s+key|ssh\s+key|api\s+key|access\s+token|refresh\s+token|session\s+cookie)\b.{0,40}\b(?:read|send|include|return|append|forward)\b/i,
      /\b(?:read|send|include|return|append|forward)\b.{0,40}\b(?:private\s+key|ssh\s+key|api\s+key|access\s+token|credentials)\b/i,
      /\bprocess\.env\b.{0,30}\b(?:send|post|fetch|include)\b/i,
    ],
  },
  {
    name: 'exfiltration',
    weight: 3.5,
    label: 'describes sending data to an external destination',
    patterns: [
      /\b(?:send|post|upload|forward|transmit|report|exfiltrat\w*)\b.{0,40}\bto\s+https?:\/\//i,
      /\b(?:send|post|upload|forward|transmit)\b.{0,30}\bto\s+(?:the\s+)?(?:following|this|our|an?\s+external)\s+(?:url|endpoint|server|address|webhook)/i,
      // Deliberately requires a sensitive noun. "Include the search term in the
      // query parameter" is ordinary documentation and must not match.
      /\b(?:include|append|embed|pass)\b.{0,60}\b(?:api[_ -]?key|access\s+token|credential|password|secret|private\s+key|\.env|file\s+contents?|contents?\s+of)\b.{0,60}\b(?:parameter|argument|field|query|url|request|body|header)\b/i,
      /\bcurl\s+(?:-[A-Za-z]+\s+)*https?:\/\//i,
    ],
  },
  {
    name: 'model-addressing',
    weight: 1.5,
    label: 'addresses the model directly rather than describing the tool',
    patterns: [
      /\b(?:as\s+an?\s+ai|as\s+the\s+assistant|you\s+are\s+an?\s+(?:ai|assistant|agent))\b/i,
      /\b(?:the\s+)?(?:assistant|model|agent)\s+(?:must|should|shall|will)\s+(?:always|never|first)\b/i,
      /\byour\s+(?:system\s+prompt|instructions|training|guidelines)\b/i,
      /\bimportant\s*:\s*(?:you|the\s+(?:assistant|model|agent))\b/i,
    ],
  },
  {
    name: 'authority-pressure',
    weight: 1,
    label: 'uses urgency or false authority',
    patterns: [
      /\b(?:mandatory|required\s+by\s+policy|compliance\s+requires|you\s+are\s+obligated)\b/i,
      /\b(?:critical|urgent|important)\s*:\s*(?:always|never|do\s+not|must)\b/i,
      /\bfailure\s+to\s+(?:comply|do\s+so)\b/i,
    ],
  },
];

/**
 * Observations that argue a match is legitimate. Without these the scanner
 * flags ordinary documentation.
 */
const DAMPENERS = [
  {
    name: 'self-scoping',
    weight: -2,
    label: 'the instruction is about this tool, not the agent or other tools',
    patterns: [
      /\bdo\s+not\s+use\s+this\s+tool\s+(?:for|to|when|if|unless)\b/i,
      /\b(?:call|use|run)\s+(?:this|the\s+\w+)\s+tool\s+(?:only\s+)?(?:when|if|after|before\s+using\s+this)\b/i,
      /\bthis\s+tool\s+(?:requires|needs|expects|depends\s+on)\b/i,
      /\brequires?\s+(?:the\s+)?[A-Z][A-Z0-9_]{2,}\s+(?:environment\s+variable|to\s+be\s+set)/,
    ],
  },
  {
    name: 'documentation-context',
    weight: -1.5,
    label: 'the match sits inside example or schema text',
    patterns: [
      /\b(?:for\s+example|e\.g\.|example\s*:|sample\s+(?:request|response|usage))\b/i,
      /\b(?:returns?|responds?\s+with|output\s+format|schema)\s*:/i,
    ],
  },
];

// Only fenced blocks count as documentation. Inline backticks are formatting
// inside a sentence, and the published sidenote attack writes its target path
// as `~/.ssh/id_rsa` mid-instruction, so excluding inline code would blind the
// scanner to the exact case this category is known for.
/**
 * Security documentation has to quote the attacks it teaches people to find.
 * A review checklist that says to watch for "ignore previous instructions"
 * necessarily contains that phrase, and so does this scanner's own skill file.
 *
 * Judged by density rather than any single term, so one keyword cannot spoof
 * it. A poisoned description is trying to look innocuous and will not carry
 * three distinct pieces of security-analysis vocabulary. Note that the
 * concealment analyzer has no dampeners at all, so hidden payloads are still
 * reported regardless of how the surrounding prose reads.
 */
const SECURITY_META = [
  /\bhostile\b/i,
  /\battack(?:er|s|ing)?\b/i,
  /\bmalicious\b/i,
  /\b(?:prompt\s+)?injection\b/i,
  /\bpoisoning\b/i,
  /\bexfiltrat/i,
  /\bvulnerabilit(?:y|ies)\b/i,
  /\bthreat\s+model/i,
  /\bpayload\b/i,
  /\bOWASP\b/,
  /\bCVE-\d/,
  /\bmitigat/i,
  /\bremediat/i,
  /\bscanner\b/i,
  /\bfalse\s+positives?\b/i,
  /\bsecurity\s+(?:review|audit|finding)/i,
  /\buntrusted\s+input\b/i,
  /\btrust\s+boundary\b/i,
];

const SECURITY_META_THRESHOLD = 3;

const FENCE = /```[\s\S]*?```|~~~[\s\S]*?~~~/g;

/** Offsets covered by code fences and inline code, where prose rules do not apply. */
function fencedRanges(text) {
  const ranges = [];
  FENCE.lastIndex = 0;
  for (const m of text.matchAll(FENCE)) ranges.push([m.index, m.index + m[0].length]);
  return ranges;
}

const inRanges = (ranges, index) => ranges.some(([start, end]) => index >= start && index < end);

function matchGroup(group, text, ranges) {
  for (const pattern of group.patterns) {
    pattern.lastIndex = 0;
    const m = pattern.exec(text);
    // A match inside a code fence is documentation, not an instruction.
    if (m && !inRanges(ranges, m.index)) {
      return { index: m.index, excerpt: m[0].slice(0, 120) };
    }
  }
  return null;
}

/**
 * @param {string} text     the metadata to inspect
 * @param {object} location { file, tool?, field? }
 */
export function analyzePoisoning(text, location) {
  if (!text || typeof text !== 'string' || text.trim().length < 8) return [];

  const ranges = fencedRanges(text);
  const signals = [];
  const hits = [];

  for (const group of GROUPS) {
    const hit = matchGroup(group, text, ranges);
    if (!hit) continue;
    hits.push({ group, hit });
    signals.push(signal(group.name, group.weight, `${group.label}: "${hit.excerpt}"`));
  }

  if (!hits.length) return [];

  for (const damp of DAMPENERS) {
    const hit = matchGroup(damp, text, ranges);
    if (hit) signals.push(signal(damp.name, damp.weight, `${damp.label}: "${hit.excerpt}"`));
  }

  const metaHits = SECURITY_META.filter((p) => p.test(text)).length;
  if (metaHits >= SECURITY_META_THRESHOLD) {
    signals.push(
      signal(
        'security-documentation',
        -3,
        `${metaHits} distinct security-analysis terms present, so this reads as documentation about attacks rather than an attack`
      )
    );
  }

  // A description that is mostly instructions aimed at the agent, rather than
  // an explanation of what the tool does, is suspicious in its own right.
  const imperativeLines = text.split('\n').filter((l) => /^\s*(?:you\s+must|always|never|do\s+not|ignore|first,|before\s+)/i.test(l)).length;
  if (imperativeLines >= 3) {
    signals.push(signal('imperative-density', 1.5, `${imperativeLines} lines begin with a directive`));
  }

  const groups = hits.map((h) => h.group.name);
  const primary = hits[0];

  // Severity tracks what the attacker achieves, not how many patterns matched.
  const severe = groups.includes('concealment-instruction') || groups.includes('exfiltration') || groups.includes('sensitive-target');

  return [
    finding({
      rule: 'poisoning/instruction-injection',
      owasp: owasp(groups.includes('cross-tool-targeting') ? 'MCP03' : 'MCP06'),
      severity: severe ? 'critical' : groups.length >= 2 ? 'high' : 'medium',
      title:
        groups.includes('cross-tool-targeting')
          ? 'Tool metadata tries to influence how other tools are used'
          : 'Tool metadata contains instructions aimed at the agent',
      detail:
        `This field reads as instructions to the model rather than a description of what the tool does. ` +
        `${hits.length} independent signal group(s) matched: ${groups.join(', ')}. ` +
        'Metadata is passed to the model verbatim, so anything written here is effectively part of the prompt.',
      remedy:
        'Compare this description against what the server actually does. Anything addressed to the agent rather than ' +
        'describing inputs and outputs should be removed before the server is approved.',
      location: { ...location, ...positionOf(text, primary.hit.index), snippet: primary.hit.excerpt },
      signals,
    }),
  ];
}

export const _internals = { GROUPS, DAMPENERS, fencedRanges };
