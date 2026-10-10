# Registry Discovery: configuration conventions

Track: small products (Discovery, Render, Manifest, platform tooling files).

## BREAKING changes

Each change below refuses a file that was already wrong, or normalizes the
unpromised index. The promised spellings that change are listed in the
section "Stable move".

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
   most 2048 characters (was 4096). A mapping above 1 MiB is not supported in
   this release, and it cannot be split: one requirement and jurisdiction
   pair is mapped by one file only, so a second file is refused with
   `discovery.project.duplicate-requirement`. Migration: shorten the
   identifiers or remove alternatives until the file is under 1 MiB; shorten
   a longer catalog URL.
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

## Protocol words

1. **The Node and Python bindings spell their error kinds in kebab-case.**
   `DiscoveryClientError.kind` and the `problem` member (`problem` in both
   bindings) follow the spelling the Discovery server already writes in its
   problem types. The Rust client and the Discovery runtime are unchanged.
   Migration: compare against the new words.

   | Member | Before | Now |
   |---|---|---|
   | `kind` | `no_matching_service` | `no-matching-service` |
   | `kind` | `ambiguous_selection` | `ambiguous-selection` |
   | `kind` | `no_matching_alternative` | `no-matching-alternative` |
   | `kind` | `ambiguous_alternative` | `ambiguous-alternative` |
   | `kind` | `capability_mismatch` | `capability-mismatch` |
   | `kind` | `local_acceptance_refused` | `local-acceptance-refused` |
   | `kind` | `selection_changed` | `selection-changed` |
   | `problem` | `invalid_request` | `invalid-request` |
   | `problem` | `not_found` | `not-found` |
   | `problem` | `result_bound_exceeded` | `result-bound-exceeded` |

2. **The transport word for an oversized response is `response-too-large`.**
   `transportKind` in Node.js and `transport_kind` in Python carry the word
   the shared HTTP primitives give a transport failure, which respell
   `response_too_large` in this release. The other transport words
   (`connect`, `timeout`, `exchange`) are unchanged. Migration: compare
   against the new word.

## Stable move

The changes below move promised spellings to the form the configuration
conventions give them. Each old spelling is refused with a diagnostic that
names its replacement; no release reads both.

### BREAKING: `runtime.yaml` names its format in `apiVersion`

The runtime file declares
`apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1`
(CFG-ENV-2). `discovery` and `discoveryctl check --runtime-config` refuse
`registry.registrystack.org/discovery-runtime/v1alpha1` as
`config.retired-api-version` at `/apiVersion`, and the message names the
replacement. `kind: DiscoveryRuntimeConfig` and every other member are
unchanged.

Migration: in every `runtime.yaml`, replace the `apiVersion` line with
`apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1`.

### BREAKING: the `runtime.yaml` timeouts are written in milliseconds

`limits.requestTimeoutSeconds` is `listener.requestTimeoutMilliseconds`:
the time allowed for one inbound request sits with the listener it
bounds, as in every Registry Stack runtime (CFG-NAME-5).
`limits.shutdownTimeoutSeconds` is `limits.shutdownGraceMilliseconds`.
Each takes an integer from 1000 to 300000, the same range as before in
the new unit, and both stay required. `discovery` and
`discoveryctl check --runtime-config` refuse each old key as
`config.removed-key` at its own position, and the message names the
replacement.

Migration, in every `runtime.yaml`:

1. Remove `requestTimeoutSeconds` from `limits` and add
   `requestTimeoutMilliseconds` under `listener`, with the value multiplied
   by 1000 (`10` becomes `10000`).
2. Under `limits`, rename `shutdownTimeoutSeconds` to
   `shutdownGraceMilliseconds` and multiply its value by 1000.

A value left in seconds is below the floor and is refused as
`config.out-of-range`.

### BREAKING: `origins.yaml` and mapping files open with `apiVersion` and `kind`

Both authored files carry the envelope every Registry Stack file carries
(CFG-ENV-1) in place of `schemaVersion`:

| File | Header |
|---|---|
| `origins.yaml` | `apiVersion: id.registrystack.org/formats/discovery/origins/v1alpha1`, `kind: DiscoveryOrigins` |
| `mappings/*.yaml` | `apiVersion: id.registrystack.org/formats/discovery/evidence-mapping/v1alpha1`, `kind: DiscoveryEvidenceMapping` |

`discoveryctl check` and `discoveryctl package` refuse a file that still
writes `schemaVersion` as `config.missing-envelope` with
`config.removed-key` at `/schemaVersion`, and the second message names the
two lines to write. A file of one kind where the other is expected is
refused as `config.wrong-kind` at `/kind`, and an `apiVersion` the reader
does not know as `config.unsupported-api-version` at `/apiVersion`. Every
other member is unchanged, and so is the packaged index: the header of an
authored file never reaches it, so no package is rebuilt and no
`package.expectedDigest` is repinned for this change alone.

Migration: in `origins.yaml` and in every file under `mappings/`, replace
the `schemaVersion` line with the two header lines of the table.
