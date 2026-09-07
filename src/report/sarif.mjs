/**
 * SARIF 2.1.0 output for GitHub code scanning.
 *
 * Getting this right is what lets findings show up as annotations on a pull
 * request instead of as text in a log nobody opens.
 */

const SEVERITY_TO_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

// GitHub reads security-severity as a CVSS-like number and derives its own
// critical/high/medium/low buckets from it.
const SECURITY_SEVERITY = { critical: '9.0', high: '7.5', medium: '5.0', low: '2.0' };

function ruleDescriptor(finding) {
  return {
    id: finding.rule,
    name: finding.rule.replace(/[/-](\w)/g, (_, c) => c.toUpperCase()),
    shortDescription: { text: finding.title },
    fullDescription: { text: `${finding.owasp} ${finding.owaspTitle}. ${finding.detail}`.slice(0, 1000) },
    help: {
      text: finding.remedy ?? finding.detail,
      markdown: [
        `**${finding.title}**`,
        '',
        finding.detail,
        '',
        finding.remedy ? `**Remediation:** ${finding.remedy}` : '',
        '',
        `Maps to [${finding.owasp} ${finding.owaspTitle}](https://owasp.org/www-project-mcp-top-10/).`,
      ]
        .filter(Boolean)
        .join('\n'),
    },
    defaultConfiguration: { level: SEVERITY_TO_LEVEL[finding.severity] ?? 'warning' },
    properties: {
      tags: ['security', 'mcp', finding.owasp, `confidence-${finding.confidence}`],
      'security-severity': SECURITY_SEVERITY[finding.severity] ?? '5.0',
      precision: finding.confidence === 'high' ? 'high' : finding.confidence === 'medium' ? 'medium' : 'low',
    },
  };
}

function result(finding, ruleIndex) {
  const region = {};
  if (finding.location.line) region.startLine = finding.location.line;
  if (finding.location.column) region.startColumn = finding.location.column;

  const context = [finding.location.server, finding.location.tool, finding.location.field]
    .filter(Boolean)
    .join(' / ');

  const evidence = finding.evidence.map((e) => `${e.signal}: ${e.detail}`).join('; ');

  return {
    ruleId: finding.rule,
    ruleIndex,
    level: SEVERITY_TO_LEVEL[finding.severity] ?? 'warning',
    message: {
      text: [context ? `${context}. ` : '', finding.detail, evidence ? ` Evidence: ${evidence}` : ''].join('').trim(),
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.location.file?.replace(/\\/g, '/') ?? 'unknown', uriBaseId: '%SRCROOT%' },
          ...(Object.keys(region).length ? { region } : {}),
        },
        ...(context ? { logicalLocations: [{ name: context, kind: 'member' }] } : {}),
      },
    ],
    partialFingerprints: { mcpauditFingerprint: finding.fingerprint ?? finding.rule },
    properties: {
      confidence: finding.confidence,
      score: finding.score,
      owasp: finding.owasp,
      ...(finding.dampeners?.length ? { dampeners: finding.dampeners.map((d) => d.signal) } : {}),
    },
  };
}

export function toSarif(findings, { version = '0.0.0' } = {}) {
  const rules = [];
  const ruleIndex = new Map();

  for (const f of findings) {
    if (ruleIndex.has(f.rule)) continue;
    ruleIndex.set(f.rule, rules.length);
    rules.push(ruleDescriptor(f));
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcpaudit',
            version,
            informationUri: 'https://github.com/catidegla/mcpaudit',
            rules,
          },
        },
        results: findings.map((f) => result(f, ruleIndex.get(f.rule))),
        columnKind: 'utf16CodeUnits',
      },
    ],
  };
}
