#!/usr/bin/env node
/**
 * Validates a SARIF file against the official 2.1.0 schema.
 *
 * Kept out of the test suite on purpose: the suite runs with no dependencies
 * installed, and this needs ajv. CI installs it with --no-save for this step
 * alone, so the published package still ships nothing but its own source.
 *
 * Usage: node scripts/validate-sarif.mjs <schema.json> <report.sarif>
 */

import { readFileSync } from 'node:fs';

const [, , schemaPath, dataPath] = process.argv;

if (!schemaPath || !dataPath) {
  console.error('usage: node scripts/validate-sarif.mjs <schema.json> <report.sarif>');
  process.exit(2);
}

let Ajv;
let addFormats;
try {
  ({ default: Ajv } = await import('ajv'));
  ({ default: addFormats } = await import('ajv-formats'));
} catch {
  console.error('ajv is not installed. Run: npm i --no-save ajv ajv-formats');
  process.exit(2);
}

const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
const data = JSON.parse(readFileSync(dataPath, 'utf8'));

/**
 * OASIS publishes the canonical SARIF schema declaring draft-04, which ajv 8
 * does not compile. The document itself uses nothing draft-04 only, so it is
 * safe to read as draft-07, but "safe" is a claim worth enforcing rather than
 * commenting: the only meaningful incompatibility is exclusiveMinimum and
 * exclusiveMaximum, which draft-04 writes as booleans beside minimum/maximum
 * and draft-07 writes as numbers. If either ever appears as a boolean the
 * rewrite would silently change what the schema means, so refuse instead.
 */
function draft04Only(node, path = '') {
  if (Array.isArray(node)) {
    return node.flatMap((item, i) => draft04Only(item, `${path}/${i}`));
  }

  if (node === null || typeof node !== 'object') return [];

  const found = [];

  for (const keyword of ['exclusiveMinimum', 'exclusiveMaximum']) {
    if (typeof node[keyword] === 'boolean') found.push(`${path}/${keyword}`);
  }

  for (const [key, value] of Object.entries(node)) {
    found.push(...draft04Only(value, `${path}/${key}`));
  }

  return found;
}

if (schema.$schema && schema.$schema.includes('draft-04')) {
  const blockers = draft04Only(schema);

  if (blockers.length > 0) {
    console.error(`${schemaPath} uses draft-04 boolean exclusiveMinimum/exclusiveMaximum, so it cannot be read as draft-07:`);
    for (const where of blockers.slice(0, 10)) console.error(`  ${where}`);
    process.exit(2);
  }

  schema.$schema = 'http://json-schema.org/draft-07/schema#';

  // draft-04 spells the schema identifier `id`, draft-07 spells it `$id`, and
  // ajv refuses the old one outright. The SARIF schema carries exactly one, at
  // the root. Anything nested would be a subschema identifier that $refs could
  // be resolving against, so rename only the root and leave the rest alone.
  if (typeof schema.id === 'string' && schema.$id === undefined) {
    schema.$id = schema.id;
    delete schema.id;
  }
}

// strict:false because the published SARIF schema uses keywords ajv considers
// non-standard. That is the schema's business, not ours.
const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: true });
addFormats(ajv);

const validate = ajv.compile(schema);

if (validate(data)) {
  const results = data.runs?.[0]?.results?.length ?? 0;
  const rules = data.runs?.[0]?.tool?.driver?.rules?.length ?? 0;
  console.log(`${dataPath} is valid SARIF 2.1.0 (${results} result(s), ${rules} rule(s))`);
  process.exit(0);
}

console.error(`${validate.errors.length} schema violation(s) in ${dataPath}:`);
for (const error of validate.errors.slice(0, 25)) {
  console.error(`  ${error.instancePath || '/'} ${error.message} ${JSON.stringify(error.params)}`);
}
process.exit(1);
