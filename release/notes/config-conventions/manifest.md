# Registry Manifest: configuration conventions

Track: small products (Discovery, Render, Manifest, platform tooling files).

The metadata manifest and the profile descriptor keep their envelope,
`schema_version: registry-manifest/v1` and
`schema_version: registry-manifest-profile/v1`: Registry Manifest is an
exchange model (exception class `exchange-model` to CFG-ENV-1), so neither
file moves to `apiVersion` and `kind`. What changes is how the command line reads
them and how it reports what it finds.

## BREAKING changes

1. **Both files are read by the shared reader, and every finding is
   reported in the shared shape.** `registry-manifest` reads a metadata
   manifest (`validate`, `render`, `publish`, and each fixture
   `validate-profiles` lists) and a profile descriptor through the shared
   Registry Stack YAML reader. A refusal prints one sentence, then every
   finding as `error[code] file:line:col /pointer`, the message, and `next:`
   with the fix, then a summary line, on standard error. It printed the
   first failure as one line, naming a dotted path without a line or column.
   No finding repeats a configured value (CFG-SEC-3). Migration: a script
   that matched the previous line should match the diagnostic code instead
   (table below).
2. **Exit codes follow the shared check contract** (CFG-CHECK-1). `validate`
   and `validate-profiles` exit 0 when nothing is refused, 1 when something
   is (or a warning is reported under `--deny-warnings`), 2 on a usage
   error, and 3 when an input cannot be read. `render` and `publish` exit 1,
   2, or 3 the same way. Every failure exited 1. Migration: treat exit 2 as
   a wrong command line and exit 3 as a missing or unreadable file.
3. **An explicit `null` and `${...}` are refused** in either file, with
   `config.null-value` and `config.substitution-not-allowed` (CFG-SEC-2).
   A `null` was read as an absent optional member, and `${...}` was read as
   literal text. Migration: delete a member written as `null`, and write
   the value itself in place of an expression.
4. **A profile descriptor is a closed model**, as a metadata manifest
   already was. It refuses a key it does not model (`config.unknown-key`),
   where it ignored one; it needs `schema_version`, `profile.id`,
   `profile.version`, `supported_input_artifacts`, `conformance_checks`, and
   `fixtures` (`config.missing-key`), where each defaulted to empty.
   `profile.id` is a local identifier, `upstream_url` a URL, each
   cardinality bound 0 or 1 with `min` at most `max`, a conformance check's
   `severity` `error` or `warning`, and a fixture's `expect` `valid`. A
   fixture path outside the profile's directory is refused. Migration:
   delete `generator_command: null` from each `profile.yaml`, and correct
   each member a diagnostic names.
5. **Each file holds at most 1 MiB** (`yaml.too-large`); the bound was
   64 KiB. A file between the two bounds that was refused is now read.
   Migration: none.

## Other changes

- **The checks.** `registry-manifest validate <metadata.yaml>` is the
  offline check for a metadata manifest, and
  `registry-manifest validate-profiles [profiles-dir]` the offline check for
  a profiles directory, its descriptors, and every fixture they list
  (CFG-CHECK-1). Both take `--format json`, which writes one
  `ManifestCtlReport` document on standard output
  (`products/manifest/examples/ctl-report/validate.json`), and
  `--deny-warnings`. No separate `check` command is added.
- `validate-profiles` warns with `manifest.profile.unlisted-file` about a
  YAML file under the profiles directory that is neither a descriptor nor a
  listed fixture, since no check reads it (CFG-CHECK-2).
- JSON Schemas for the metadata manifest and the profile descriptor are
  generated from the types the command line reads and published under
  `products/manifest/schemas` (CFG-SCHEMA-2). Regenerate them with
  `cargo run -p registry-manifest-cli --features schema --example manifest-schema -- --output products/manifest/schemas`.
  `editors/configure.py manifest <project> --document <file>` maps them to
  the selected document and every `profile.yaml` below the project.
  Registry Manifest has no `init` command, so no file is written with a
  schema modeline.
- The `registry-manifest-core` library adds a `condition` to each
  validation error, with its code and fix; its error text is unchanged and
  still names the dotted field path.

## Diagnostic codes, old to new

A manifest refused by `registry_manifest_core::validate_manifest` reported
`metadata.manifest.validation_failed`. It now reports one code per condition:
`manifest.metadata.duplicate-value`, `unknown-reference`, `missing-member`,
`empty-value`, `invalid-id`, `invalid-url`, `invalid-iri`,
`invalid-vocabulary-prefix`, `invalid-digest`, `policy-hash-mismatch`,
`policy-not-canonicalizable`, `too-many-items`, `unsupported`, and
`invalid-value`.

| Before | Now |
|---|---|
| `metadata.manifest.version_unsupported` | `manifest.metadata.unsupported-version` |
| `metadata.profile.runtime_key_present`, or `metadata.manifest.parse_failed` naming runtime-only keys | `manifest.metadata.runtime-only-key` |
| `metadata.manifest.parse_failed` naming secret-bearing keys | `manifest.metadata.secret-bearing-key` |
| `metadata.manifest.file_not_found` | `manifest.metadata.missing-file` (exit 3) |
| `metadata.manifest.parse_failed`, `metadata.profile.parse_failed`, `metadata.profile.fixture_parse_failed` | `yaml.syntax`, `config.unknown-key`, `yaml.duplicate-key`, or another reader code |
| `metadata.manifest.too_large`, `metadata.profile.too_large` | `yaml.too-large` |
| `metadata.manifest.aliases_unsupported`, `metadata.profile.aliases_unsupported` | `yaml.anchor`, `yaml.alias` |
| `metadata.profile.version_unsupported` | `config.unknown-variant` at `/schema_version` |
| `metadata.profile.id_missing` | `config.missing-key` or `config.invalid-value` at `/profile/id` |
| `metadata.profile.version_missing` | `config.missing-key` or `manifest.profile.empty-value` at `/profile/version` |
| `metadata.profile.supported_input_artifacts_missing`, `conformance_checks_missing`, `fixtures_missing` | `manifest.profile.empty-list` |
| `metadata.profile.id_mismatch` | `manifest.profile.id-mismatch` |
| `metadata.profile.descriptor_missing` | `manifest.profile.no-descriptors` |
| `metadata.profile.directory_read_failed` | `manifest.profile.missing-directory`, `not-a-directory`, or `unreadable` (exit 3) |
| `metadata.profile.fixture_missing` | `manifest.profile.missing-fixture`, or `manifest.profile.unreadable` (exit 3) |
| `metadata.profile.file_not_found` | `manifest.profile.unreadable` (exit 3) |
| `metadata.profile.claim_missing`, `required_concept_missing`, `identifier_missing`, `cardinality_mismatch`, `codelist_mismatch` | `manifest.profile.claim-missing`, `required-concept-missing`, `identifier-missing`, `cardinality-mismatch`, `codelist-mismatch` |
| (new) | `manifest.profile.fixture-path-escapes`, `manifest.profile.invalid-range`, `manifest.profile.unlisted-file` (warning), `manifest.metadata.unreadable`, `manifest.metadata.not-canonicalizable` |

`publish` keeps its `metadata.publish.*` codes.
