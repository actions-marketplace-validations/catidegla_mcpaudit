# Vendored schemas

## `sarif-2.1.0.json`

The canonical SARIF 2.1.0 schema, taken verbatim from OASIS:

<https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json>

It is committed here rather than fetched in CI. The validation step used to
`curl` json.schemastore.org on every run, and on 17 September 2026 that copy
lost `message.text` and `physicalLocation.artifactLocation` from its property
lists while still declaring `additionalProperties: false`. Both are required
parts of the format, so every conformant SARIF file failed validation at once
and this repository's CI went red on a commit that never touched the SARIF
writer.

Vendoring it means the check answers a question about this tool's output and
nothing else. Refresh it deliberately, by replacing the file and reading the
diff, rather than inheriting whatever a CDN served that morning.

The file is unmodified. OASIS declares it as JSON Schema draft-04, which ajv 8
will not compile, so `scripts/validate-sarif.mjs` reads it as draft-07 at load
time. That rewrite is only sound because the document uses no draft-04 specific
construct; the script verifies that rather than assuming it, and refuses to run
if a boolean `exclusiveMinimum` or `exclusiveMaximum` ever appears.
