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
