# Registry Discovery: configuration conventions

Track: small products (Discovery, Render, Manifest, platform tooling files).

## BREAKING changes
<!-- upgrade: 1=discovery-reader-refusals; 2=discovery-reader-refusals; 3=discovery-reader-refusals; 4=discovery-reader-refusals; 5=discovery-index-rebuild; 6=no-file -->

Each change below refuses a file that was already wrong, or normalizes the
unpromised index. Promised spellings are unchanged in this release; the
section "Respellings held for the stable release" lists them.

1. **`origins.yaml` and mapping files refuse `${...}`** with
   `config.substitution-not-allowed` (CFG-SEC-2). Authored files never
   substituted environment values; the expression was read as literal text.
   Migration: write the value itself in place of the expression.
2. **An unknown, duplicate, or null key in `origins.yaml` or a mapping file
   is refused at its line and column** (`config.unknown-key`,
   `yaml.duplicate-key`, `config.null-value`), with the closest declared
   key when there is one. Migration: remove the key or correct its spelling
   as the diagnostic names.
3. **A repeated `evidenceTypeIds` entry is refused** with
   `config.duplicate-item`. Migration: remove the repeat.
4. **Size bounds follow the shared reader.** Each authored file holds at
   most 1 MiB (a mapping file was allowed 20 MiB), and `catalogUrl` holds at
   most 2048 characters (was 4096). Migration: split an oversized mapping
   into several mapping files; shorten a longer catalog URL.
5. **The index opens with `apiVersion` and `kind`.** `discovery-index.json`
   now begins with
   `apiVersion: id.registrystack.org/formats/discovery/index/v1alpha1` and
   `kind: DiscoveryIndex` in place of
   `schemaVersion: registry-discovery/index/v1alpha1`. `discovery serve` and
   `discoveryctl check --index` refuse an index with the old header with
   `discovery.index.retired-header`. Migration: rebuild the package with
   `discoveryctl package --project <project> --output <new directory>`, then
   copy the printed package digest into `package.expectedDigest` in
   `runtime.yaml` if you pin it, and point `package.root` at the new
   directory.
6. **`discoveryctl check` output.** The human output prints every reader
   diagnostic in the shared shape (`error[code] file:line:col /pointer`,
   the message, then `next:` with the fix) and ends with a summary line
   (`0 errors, 0 warnings in 3 files`). A clean project run still prints
   `valid origins=N mappings=M` as its first line. With `--format json` the
   command writes one report in the shared ctl envelope
   (`apiVersion: id.registrystack.org/formats/discovery/ctl-report/v1alpha1`,
   `kind: DiscoveryCtlReport`). Exit codes: 0 clean, 1 errors (or warnings
   with `--deny-warnings`), 2 usage, 3 could not run. Migration: a script
   that parsed the previous free-text error should read `--format json`
   instead.

## Other changes

- `discoveryctl check --project` reads every YAML file beside
  `origins.yaml` (CFG-CHECK-2): a runtime file is checked as `discovery
  serve` reads it, a file of a foreign kind is refused, and a file with no
  kind is a warning.
- `discoveryctl check --runtime-config FILE` checks one `runtime.yaml` on its
  own, offline (CFG-CHECK-1); `--environment` fills its `${NAME}`
  expressions from the process environment, and without it they are left
  unsubstituted.
- `discoveryctl check --index FILE` checks one index offline exactly as
  `discovery serve` parses the index of a verified package.
- `discovery serve` prints the reader's human diagnostics on standard error
  when it refuses `runtime.yaml`, as well as in its JSON log.
- Out-of-range runtime limits are reported with their position and allowed
  range (`config.out-of-range`); every limit keeps its previous bound.
- The origins, evidence-mapping, and runtime JSON Schemas are generated from
  the reader types by
  `cargo run -p registry-discoveryctl --features schema --example discovery-schema -- --output products/discovery/schemas`
  and held byte-identical by `products/discovery/scripts/check-contracts.sh`.
  Their identifiers move to id.registrystack.org; an editor configuration
  that names a schema by `$id` should use the new value:

  | Schema | Previous `$id` | `$id` now |
  |---|---|---|
  | origins | `https://registrystack.org/discovery/schema/origins-v1alpha1.json` | `https://id.registrystack.org/schemas/discovery/origins/origins.v1alpha1.schema.json` |
  | evidence mapping | `https://registrystack.org/discovery/schema/evidence-mapping-v1alpha1.json` | `https://id.registrystack.org/schemas/discovery/evidence-mapping/evidence-mapping.v1alpha1.schema.json` |
  | runtime | `https://registrystack.org/discovery/schema/runtime-v1alpha1.json` | `https://id.registrystack.org/schemas/discovery/runtime/runtime.v1alpha1.schema.json` |
  | index | (published with this release) | `https://id.registrystack.org/schemas/discovery/index/index.v1alpha1.schema.json` |

  The schema files keep their paths under `products/discovery/schemas/`, so
  `editors/configure.py` needs no change.

## Diagnostic codes, old to new

Before this release no Discovery configuration diagnostic carried a code:
`discoveryctl check` printed one of two sentences, and startup printed one
sentence per failure. The runtime file's shared loader codes (`config.*`)
are unchanged.

| Before (message, no code) | Code now |
|---|---|
| `the Discovery authoring project could not be read` | `discovery.project.unreadable`, `discovery.project.missing-file`, `discovery.project.not-a-directory`, `discovery.project.not-a-regular-file` |
| `the Discovery authoring project is invalid` (origins) | `discovery.origins.origin-count`, `discovery.origins.invalid-origin-id`, `discovery.origins.duplicate-origin-id`, `discovery.origins.catalog-url-not-allowed`, `discovery.origins.duplicate-catalog-url` |
| `the Discovery authoring project is invalid` (mappings) | `discovery.mapping.invalid-identifier`, `discovery.mapping.alternative-count`, `discovery.mapping.duplicate-evidence-type-list`, `discovery.mapping.evidence-type-count` |
| `the Discovery authoring project is invalid` (project) | `discovery.project.mapping-count`, `discovery.project.unexpected-mapping-entry`, `discovery.project.duplicate-mapping-id`, `discovery.project.duplicate-requirement`, `discovery.project.foreign-kind`, `discovery.project.unread-file` |
| `the Discovery authoring project is invalid` (YAML shape) | the reader's `yaml.*` and `config.*` codes, for example `yaml.duplicate-key`, `yaml.anchor`, `config.unknown-key`, `config.null-value`, `config.missing-key`, `config.duplicate-item`, `config.substitution-not-allowed` |
| `the Discovery runtime configuration is invalid` | `config.out-of-range` for a limit; `discovery.runtime.relative-package-root`, `discovery.runtime.invalid-package-digest`, `discovery.runtime.invalid-package` for the package block |
| `the Discovery package file discovery-index.json is invalid` | `discovery.index.invalid`, `discovery.index.not-canonical`, `discovery.index.bound-exceeded`, `discovery.index.retired-header` |
| `the Discovery package contains a retired Relay service` | `discovery.index.retired-service-kind` |
| clap usage error (free text) | `discovery.usage.invalid-arguments` |
| (index file checks, new) | `discovery.index.unreadable`, `discovery.index.not-a-regular-file` |

## Respellings held for the stable release (WP11)

These promised spellings stay as they are now; the stable release moves them
and refuses the old spelling with a diagnostic naming the new one.

| Format | Now | Stable release |
|---|---|---|
| `origins.yaml` | `schemaVersion: registry-discovery/origins/v1alpha1` | `apiVersion: id.registrystack.org/formats/discovery/origins/v1alpha1`, `kind: DiscoveryOrigins` |
| mapping files | `schemaVersion: registry-discovery/evidence-mapping/v1alpha1` | `apiVersion: id.registrystack.org/formats/discovery/evidence-mapping/v1alpha1`, `kind: DiscoveryEvidenceMapping` |
| `runtime.yaml` | `apiVersion: registry.registrystack.org/discovery-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1` |
| `runtime.yaml` | `limits.requestTimeoutSeconds` | `limits.requestTimeoutMilliseconds` |
| `runtime.yaml` | `limits.shutdownTimeoutSeconds` | `limits.shutdownGraceMilliseconds` |
