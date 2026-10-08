# Configuration conventions: Base Registry Engine

## BReg authored formats

This section covers the formats an adopter and an operator write for the
Base Registry Engine: `registry.yaml`, `module.yaml`, `runtime.yaml`, and the
package a `bregctl package` run seals around them.

### BREAKING: the shared reader reads `registry.yaml` and `module.yaml`

`bregctl`, the package builder, and `breg` read a project and its modules
through the shared Registry Stack reader. A file that was already outside the
documented grammar is now refused, and every refusal carries a code, a JSON
Pointer path, a line, a column, and the edit that fixes it.

| A file that writes | is refused as | Migrate by |
|---|---|---|
| `null`, `~`, or a key with no value, anywhere but a comparison literal | `config.null-value` | Deleting the key; an optional member is written by leaving it out. |
| an unquoted number where text is expected, such as `version: 1` or `version: 1.5` under `registry`, in a module, or in a module lock | `config.expected-string` | Quoting the value: `version: "1"`. A dotted version such as `0.1.0` is already text. |
| an unquoted value that looks like a number but is not a plain decimal: a leading zero (`0123`), a bare point (`.5`, `5.`), a base prefix (`0x1F`, `0o17`, `0b101`), `.inf`, or `.nan` | `yaml.ambiguous-number` | Quoting the value when it is text, or writing the plain decimal when it is a number. |
| a YAML anchor (`&name`), alias (`*name`), merge key (`<<`), or tag (`!tag`) | `yaml.anchor`, `yaml.alias`, `yaml.merge-key`, `yaml.tag` | Writing the shared value out in full at every place that used the alias. |
| `${NAME}`, `${NAME:-default}`, or `${NAME:?message}` in a value | `config.substitution-not-allowed` (was `source.environment_expression`) | Writing the literal value; a project and a module are reviewed artifacts, and only `runtime.yaml` takes environment values. |

A duplicate key, an unknown key, and a value of the wrong kind were already
refused; they are now reported with the reader's codes (`yaml.duplicate-key`,
`config.unknown-key`, `config.missing-key`, `config.invalid-type`) instead of
`source.yaml.invalid`, every unknown key in a file is reported rather than the
first, and an unknown key names the closest accepted key when one is near.
A tool that matched `source.yaml.invalid` or `source.environment_expression`
in `bregctl --format json` output must match the reader codes instead.

The members that take one of several forms are read as the shared reader's
unions, and the forms each accepts are unchanged: an entity constraint and a
partial unique `when` predicate (named by `kind`), a statistical dataset's
`period` (named by `kind`) and its `validity` (`temporal` or a mapping), a
change-request evidence selector (named by `source`), a change request's
`review` (`mode: none`, or `authority` with `policyId`), and a manifest
projection text (a string, or a mapping from language tag to text). A problem
inside the chosen form is reported at its own member: an unknown `kind` as
`config.unknown-variant` at `kind`, a missing member as `config.missing-key`,
and a `review` that mixes `mode` with `authority` or `policyId` as
`config.invalid-value` at the review.

A comparison literal is a record value, and `null` is one: an action
requirement's `equals`, a change-request predicate's `equals`, and a value
under a hook condition's `afterEquals` or `beforeEquals` still accept `null`,
and it still means "the stored value is null". A list or a mapping written
there was refused when the project compiled, as `action.requires.value_invalid`,
`change_request.preconditions.predicate_value_invalid`, or
`source.shape.invalid`; the reader now refuses it as `config.invalid-type` at
the literal, and the published schemas type the literal as `DataLiteral`.

A package rederives its project from the `source/registry.yaml` and module
files it seals, at `bregctl package` and every time `breg` or `bregctl` loads
it. A package whose sealed sources carry one of the shapes above no longer
loads. Correct the source project, rebuild the package with `bregctl package
--baseline-package <deployed package>`, and apply it before starting the
upgraded runtime.

### The published schemas describe what the reader accepts

The project, module, and runtime JSON Schemas are generated from the same
types the reader decodes, and now say what it refuses:

- No member admits `null` and none declares `default: null`, except a
  comparison literal (`$defs/DataLiteral`), where `null` is a record value.
  An optional member is written by leaving it out. A file the schema now
  refuses for a `null` was already refused by the reader.
- The project schema states `apiVersion: registry.registrystack.org/v1alpha1`
  and `kind: RegistryProject` as constants, the values the compiler already
  required.
- A structured field's or action input's `schema` member, which holds the
  adopter's own JSON Schema, carries `x-registry-foreign: json-schema-2020-12`.
- The project schema is published as
  `https://id.registrystack.org/schemas/breg/project/project.v1alpha1.schema.json`
  and the module schema as
  `https://id.registrystack.org/schemas/breg/module/module.v1alpha1.schema.json`,
  where they were under `schemas/breg/authoring/`. The earlier identifiers
  stay resolvable as deprecated. An editor mapping by file path, such as the
  one `editors/configure.py` writes, needs no change; a tool that names the
  schema by its `$id` should name the new one.

### BREAKING: project URLs and module digests are typed by the shared reader

The reader types the URL members of `registry.yaml` as `Url` (an absolute
`http` or `https` URL with a host, no user information, and at most 2048
characters) and a module lock's `digest` as `Digest` (`sha256:` followed by
64 lowercase hex digits). The published project schema references
`$defs/Url` and `$defs/Digest` at the same members. A value that was refused
when the project compiled is now refused when it is read, and a value that
was only required to be non-empty is now refused unless it is a URL.

| A file that writes | was | is refused as | Migrate by |
|---|---|---|---|
| a module lock `digest` that is not `sha256:` and 64 lowercase hex digits | refused at compile as `module.lock.digest_invalid` | `config.invalid-value` at `/modules/<index>/digest` | Deleting the `digest` member and running `bregctl project lock`, which writes the canonical digest. |
| a `manifestProjection.catalog.baseUrl` or `dataServices[].endpointUrl` that is not an absolute `http` or `https` URL | accepted when not empty; refused at compile when empty as `manifest_projection.catalog.base_url.empty` or `manifest_projection.data_service.endpoint_url_empty` | `config.invalid-value` at the member | Writing the absolute URL the catalog or service is published at, such as `https://registry.example/`. |
| a `manifestProjection.distributions[].accessUrl` or `downloadUrl` that is not an absolute `http` or `https` URL | accepted | `config.invalid-value` at the member | Writing the absolute URL, or deleting the optional member. |
| an access profile `taskGrant.sourceIssuer` that is not an absolute `http` or `https` URL, such as `urn:casework:issuer` | refused at compile as `access_profile.task_grant.invalid` | `config.invalid-value` at `/accessProfiles/<index>/taskGrant/sourceIssuer` | Writing the Casework task authority's issuer as Casework states it, an `https` URL. An `http` issuer is still refused at compile, as `breg.access-profile.task-grant-invalid`. |

A URL with user information (`https://user@host/`) was accepted in every
manifest member above and is now refused: the catalog is public, and a
credential has no place in it. A package whose sealed project carries one of
these values no longer loads; correct the source project and rebuild the
package as described above.

### BREAKING: integer bounds in `registry.yaml` and `module.yaml` are refused when read

Every integer member of the project and module formats now states its
minimum and maximum in the published schemas, and the reader refuses a value
outside them when it reads the file, at the member, rather than the compiler
refusing it later at the enclosing object. No value that compiled before is
refused now; what changes is the code and the path a tool matching
`bregctl --format json` output sees.

| A file that writes | was refused at compile as | is refused at read as |
|---|---|---|
| a string field `maxLength` of 0, or a `minLength` above 1000000 | `field.string.bounds_invalid` at the field | `config.out-of-range` at `maxLength` or `minLength` |
| a string field `maxLength` from 1000001 to 10000000 | `field.string.bounds_invalid` | `config.invalid-value` at the field, which names `text` for longer values; above 10000000, `config.out-of-range` at `maxLength` |
| a text field `maxLength` of 0 or above 10000000 | `field.text.bound_invalid` | `config.out-of-range` at `maxLength` |
| a decimal field `precision` or `scale` above 38 | `field.decimal.bounds_invalid` | `config.out-of-range` at the member |
| a decimal field `precision` of 0 | `field.decimal.bounds_invalid` | `config.invalid-value` at the field |
| a CRS84 point field `precision` from 10 to 38 | `field.crs84_point.bounds_invalid` | `config.invalid-value` at the field; above 38, `config.out-of-range` at `precision` |
| a structured field `maxBytes` of 0 or above 1048576 | `field.structured.schema_invalid` | `config.out-of-range` at `maxBytes` |
| an entity `batch.maximumItems` of 0 or above 100, or `batch.maximumBytes` of 0 or above 2097152 | `entity.batch.bounds_invalid` at the batch | `config.out-of-range` at the member |
| an attachment slot `maximumBytes` of 0 or above 16777216 | `attachment.maximum_bytes.bounds_invalid` | `config.out-of-range` at `maximumBytes` |
| a statistical dataset `disclosure.minimumCount` or `roundingBase` below 2 or above 9007199254740991 | `statistical_dataset.disclosure.minimum_count`, `minimum_count_exceeded`, `rounding_base`, or `rounding_base_exceeded` | `config.out-of-range` at the member |
| an action evidence `maximumObservationAgeSeconds` of 0 or above 300 | `action.evidence.capability.invalid` | `config.out-of-range` at the member |

The compile-time codes, under their `breg.*` names below, stay for the
conditions the reader cannot decide alone: a string `minLength` above its `maxLength`, a decimal `scale` above
its `precision` or bounds that do not fit them, a CRS84 bounding box, a
structured field's schema, and a statistical dataset with no `disclosure`.
A change-request or action-requirement `atLeast` or `atMost`, and an integer
constraint's `minimum` and `maximum`, state the signed 64-bit range in the
schema, the range the reader already enforced.

### BREAKING: a list that is a set refuses a repeated item

A list member of `registry.yaml` and `module.yaml` whose order carries no
meaning is a set. The reader used to collapse a repeated item silently; it now
refuses the repeat as `config.duplicate-item` at the repeated item, naming the
index of the first occurrence. The published schemas already declared these
lists `uniqueItems: true`. To migrate, delete the repeated item: the file then means
what it meant before. The members are:

- an access profile's `requesterClients`, `requiredScopes`, and
  `requiredPurposes`, at project level and on an entity;
- a permission's or an entity access profile's `operations`,
  `readableFields`, `readableRequestFields`, `writableFields`,
  `filterableFields`, `sortableFields`, and `submitterTargets`, and a
  permission's `results`;
- a read path's `readableFields`, `filterableFields`, and `sortableFields`;
- a task grant permission's `operations`;
- an entity's `accessRequirements.requiredScopes` and
  `accessRequirements.allowedPurposes`;
- an entity's `accessLog.trustedIntermediaries` and
  `changeControl.requiredFor`;
- an action effect's and a change-request effect's `clear`;
- a hook's `projection`, and its `when` condition's `changed`,
  `transitions`, and `toStates`.

### BREAKING: `runtime.yaml` is decoded by the shared reader

`breg` and every `bregctl` command that takes `--runtime-config` decode
`runtime.yaml` through the shared runtime loader rather than a second
product-side pass. Every problem in the file is reported in one run, each
with its code, JSON Pointer path, line, column, and fix, and an unknown key
names the closest accepted key. The platform blocks (`package`,
`authentication.oidc`, `audit`) are read the same way, so two unknown keys
inside one of them are both reported.

`breg` that refuses its runtime file prints one sentence, `breg did not
start: its runtime configuration was refused.`, then the reader's
diagnostics in the human shape on stderr, each naming the file path the
operator gave. The JSON operational log on stdout still carries only the
closed refusal class, with no path and no value. `bregctl doctor`, `diff`,
`verify`, `plan`, `apply`, `status`, and the retention commands report every
reader diagnostic, with the reader's code and path unchanged and the fix
appended to the message.

| Was refused as | Is refused as | Migrate by |
|---|---|---|
| `runtime_config.document` | the reader's code for the cause: `config.unknown-key`, `config.missing-key`, `config.invalid-type`, `config.invalid-value`, `config.unknown-variant`, `config.null-value`, `config.expected-string`, `config.expected-integer`, `config.expected-boolean`, `config.out-of-range`, a `yaml.*` code, or `platform.runtime-config.canonical-form` | Matching the reader codes in tooling that read `bregctl --format json`. |
| `runtime_config.governed_member` (a registry-project member such as `entities` or `webhooks` in `runtime.yaml`) | `config.unknown-key` | Moving the member to the registry project, where it belongs, and deleting it from `runtime.yaml`. |
| `runtime_config.env_expansion` | `config.substitution`, which names the variable to set | Setting the named variable, or writing a `${NAME:-fallback}`. |
| `runtime_config.substitution_in_reference` | `config.substitution-not-allowed`, at the reference or provider setting | Writing the reference or provider setting as plain text. |
| `runtime_config.bounds` | `platform.runtime-config.size` | Keeping the file at most 1 MiB. |
| `runtime_config.unsafe_file` | `platform.runtime-config.unsafe-file` or `platform.runtime-config.path` | Giving the absolute path of a regular file with no symbolic link in it. |
| `runtime_config.unavailable` | `platform.runtime-config.unavailable` | Making the file exist and readable by the runtime user. |
| `runtime_config.invalid_api_version`, `runtime_config.invalid_kind` | `config.unsupported-api-version`, `config.wrong-kind`, or `config.missing-envelope` when the member is absent | Writing `apiVersion: registry.registrystack.org/breg-runtime/v1alpha1` and `kind: BRegRuntimeConfig`. |
| `runtime_config.invalid_listener`, `runtime_config.invalid_metrics_listener` for a `bind` that is not a numeric socket address | `config.invalid-value` at `/listener/bind` or `/metricsListener/bind` | Writing a numeric `address:port`, such as `127.0.0.1:8080`. A numeric address that is public, unspecified, or on port 0 is still refused as before. |
| `runtime_config.invalid_audit` for an `audit.hashKeyRef` that is not a secret reference | `config.invalid-value` at `/audit/hashKeyRef` | Writing `secret:file/NAME` or `secret:env/NAME`. |
| `runtime_config.invalid_database` for `database.url`, `database.password`, or `database.plaintext` | `config.removed-key`, naming `database.runtimeUrlRef` and `database.migrationUrlRef` | Deleting the member; the connection URL, password included, is named by secret reference in `database.runtimeUrlRef` and `database.migrationUrlRef`. |
| `runtime_config.invalid_database`, `runtime_config.invalid_cursor`, `runtime_config.invalid_binding`, or the block's own refusal (event destination, attachment storage or verification, field encryption, Evidence provider, task-grant status) for a `*Ref` member that is not a secret reference | `config.invalid-value` at the member, such as `/database/runtimeUrlRef` or `/eventDestinations/<id>/hmacSha256KeyRef` | Writing `secret:file/NAME` or `secret:env/NAME`. A reference that names a provider `secretProviders` does not enable is still refused with the block's own code. |
| `runtime_config.invalid_listener` for a `listener.publicOrigin`, `runtime_config.invalid_binding` for an Evidence provider `baseUrl`, or the task-grant configuration refusal at startup for a `taskGrantStatus` `baseUrl` or `sourceIssuer`, that is not an absolute `http` or `https` URL with a host and no user information | `config.invalid-value` at the member | Writing an absolute URL such as `https://registry.example`. `publicOrigin` and both `baseUrl` members are still `https`, with `http` only for a loopback host. |
| a task-grant status `sourceIssuer` that is not an `http` or `https` URL, such as `urn:casework:issuer`, which was accepted | `config.invalid-value` at `/taskGrantStatus/<index>/sourceIssuer` | Writing the Casework task authority's issuer as Casework states it, an `https` URL. |
| `authentication.oidc.assertionIssuers: {}`, which applied no assertion-issuer rule | `config.invalid-value` at `/authentication/oidc/assertionIssuers` | Deleting the member: omitting it applies no assertion-issuer rule. |

In `bregctl --format json` output, a reader refusal was reported under the
command's prefix (`doctor` as `startup.runtime_config.document`, `diff` as
`diff.runtime_config.document`); the reader codes above are reported
unprefixed. A refusal the runtime decides itself after the file is read is
reported as its `breg.runtime.*` code, also unprefixed (see the code table
below), and the two whose path was `/`, `runtime_config.invalid_binding` and
`runtime_config.secret`, now report the root pointer `""`.

The runtime file may be up to 1 MiB, the shared bound every product's runtime
file carries (CFG-YAML-6), where it was 64 KiB. No reason was recorded for the
lower bound, and the file carries no inline documents. The separate bound on
the document after `${...}` substitution is gone: a substituted value is held
to the bound of the member it fills, and the environment is operator-held, as
the file is.

### BREAKING: integer bounds in `runtime.yaml` are refused when read

Every integer member of `runtime.yaml` is read with the minimum and maximum
the published runtime schema already stated, so a value outside them is
refused when the file is read, as `config.out-of-range` at the member, rather
than after decoding under the enclosing block's code. No value that was
accepted before is refused now; what changes is the code and the path a tool
matching `bregctl --format json` output sees.

| A file that writes | was refused as | is refused as |
|---|---|---|
| `database.pool.maxSize` of 0 or above 128, or a pool `waitTimeoutMilliseconds`, `createTimeoutMilliseconds`, or `recycleTimeoutMilliseconds` of 0 or above 60000 | `runtime_config.invalid_bounds` at `/operationalTimeouts` | `config.out-of-range` at the member |
| an `operationalTimeouts` member outside its range: `httpRequestMilliseconds` 1 to 60000, `shutdownGraceMilliseconds` and `migrationLockMilliseconds` 1 to 300000, `recordLockMilliseconds` 1 to 30000, `migrationStatementMilliseconds` 1 to 3600000 | `runtime_config.invalid_bounds` | `config.out-of-range` at the member |
| `cursor.maxAgeSeconds`, `eventDelivery.payloadRetentionDays`, or `idempotency.receiptRetentionDays` of 0 or above 86400, 30, or 365 | `runtime_config.invalid_bounds` | `config.out-of-range` at the member |
| `authentication.oidc.maxTokenLifetimeSeconds` of 0 or above 7200, or a `jwksCache` member outside its range | `runtime_config.invalid_bounds`, or `runtime_config.invalid_oidc` for `maxDocumentBytes` | `config.out-of-range` at the member |
| `authentication.oidc.leewayMilliseconds` above 300000 | `runtime_config.invalid_oidc_leeway` | `config.out-of-range` at the member; a value that is not a whole number of seconds is refused as `breg.runtime.invalid-oidc-leeway` |
| `audit.rotateBytes` below 1048576 or above 4294967295, or `audit.retainDays` of 0 or above 36500 | `runtime_config.invalid_audit` at `/audit` | `config.out-of-range` at the member |
| `wasmExecution.maxModuleBytes` outside 1024 to 5242880, or `maxGuestMemoryBytes` outside 1048576 to 1073741824 | `runtime_config.invalid_wasm_execution` at `/wasmExecution` | `config.out-of-range` at the member |
| a review authority `recoveryDays` of 0 or above 3650 | `runtime_config.invalid_binding` at `""` | `config.out-of-range` at `/reviewAuthorities/<id>/recoveryDays` |
| an event destination `deliveryCeilings.attemptTimeoutMilliseconds` outside 100 to 5000, or `maximumAttempts` outside 1 to 5 | `runtime_config.invalid_event_destination` at `/eventDestinations` | `config.out-of-range` at the member |
| `attachmentStorage.timeoutMilliseconds` or `attachmentVerification.timeoutMilliseconds` outside 100 to 60000 | `runtime_config.invalid_attachment_storage` or `runtime_config.invalid_attachment_verification` | `config.out-of-range` at the member |
| a Transit `fieldEncryption.provider.timeoutMilliseconds` of 0 or above 30000 | `runtime_config.invalid_field_encryption` at `/fieldEncryption` | `config.out-of-range` at the member |

`attachmentStorage`, `attachmentVerification`, and `fieldEncryption.provider`
are read as the shared reader's tagged unions: `kind` still names the form and
the accepted spellings are unchanged, and every problem inside the chosen form
is now reported at its own member, line, and column rather than at the block.

### BREAKING: `bregctl check` reports in the shared diagnostic shape

`bregctl check` reads `registry.yaml` and every `module.yaml` through the
shared reader and reports what it finds in the diagnostic shape every
Registry Stack check command shares (CFG-DIAG-1, CFG-DIAG-2). The human
report leads with one sentence saying whether the check passed or what
refused it, prints each diagnostic as `severity[code] file:line:column path`
followed by its message and a `next:` line, and closes with
`N errors, M warnings in K files`. A refusal is still printed on stderr.

| Was | Is | Migrate by |
|---|---|---|
| a JSON report with advisories under `findings[]`, each without `severity` | every error and warning under `diagnostics[]`, each with `severity` | Reading `diagnostics[]` and selecting `severity: warning` where a script read `findings[]`. `ok`, `command`, `profile`, `revision`, `registryRevision`, and, for `--package`, `packageDigest` are unchanged. |
| a diagnostic `path` such as `entities[id=record].accessProfiles[id=operator].rowBoundaries` | a JSON Pointer into the file that holds the member, such as `/accessProfiles/0/permissions/1/rowBoundaries`, with `source` naming the file, line, and column | Matching on `code` and `source.file` rather than on the path text. |
| a `suggestedAction` such as `run_schema_test` | a sentence naming the fix | Showing the sentence to the reader; a script that branched on the identifier branches on `code` instead. |
| a finding, reported as `finding` | a `warning` | Matching `warning` where a script matched `finding`. |
| `bregctl check --deny-findings` | `bregctl check --deny-warnings`, refusing with exit 1 when the check reports any warning | Renaming the flag in every pipeline. |
| exit 1 when the project directory, a package file, or the runtime file could not be read | exit 3, with `breg.source.project-invalid`, `breg.package.refused`, or `platform.runtime-config.unavailable` | Treating exit 3 as "the check could not run" and exit 1 as "the check refused the project". |
| a module diagnostic naming `RegistryProject` as its `artifact` | `BRegModule` | Matching `BRegModule` for a diagnostic inside a `module.yaml`. |
| a refused package reported as `the package was refused` at the path `package` | a message naming the cause, such as `the shared package envelope is invalid`, with `source` naming the package directory | Reading the message and the code; the code still names the class of refusal. |

`bregctl check --runtime-config FILE` also reads a `runtime.yaml` the way
`breg` reads it at startup, with no package, database, network endpoint, or
secret provider, and prints the reader's diagnostics unchanged. Without
`--environment`, each `${NAME}` expression is checked by its syntax and
position only; with it, the expressions are filled from the process
environment, and a filled value is never repeated in a diagnostic.

### BREAKING: the package format is named `id.registrystack.org/formats/breg/package/v2`

The `package.json` a `bregctl package` run writes declares the package format
by its registered identifier and a kind (CFG-ENV-1, CFG-ENV-2). The rest of
the file, its canonical JSON, and the `SHA256SUMS` digest rules are
unchanged.

| Was | Is |
|---|---|
| `"apiVersion": "registry.registrystack.org/package/v2"` with no `kind` | `"apiVersion": "id.registrystack.org/formats/breg/package/v2"` and `"kind": "BRegPackage"` |

A package carrying the retired header is read only as the predecessor of an
upgrade: the deployed package named by `--baseline-package`, and the active
package a runtime file names to `bregctl plan`, `apply`, `reconcile`, and the
field-encryption commands. Everywhere else it is refused:

- `breg` refuses to start with "the Registry package carries the retired
  apiVersion registry.registrystack.org/package/v2" and the rebuild steps
  below.
- `bregctl check --package` reports `config.retired-api-version`.
- `bregctl verify` and `bregctl migration explain` report
  `verify.package.retired_api_version` and
  `migration.explain.package.retired_api_version`, and
  `bregctl diff --package` reports `diff.baseline.retired_api_version`;
  `bregctl diff PROJECT --runtime-config RUNTIME` still compares a project
  with the deployed package the runtime file names.
- `bregctl data validate`, `import`, and `export` report
  `data.<command>.package.refused` with the `correct_package_build` action.

Upgrade each deployed registry with this release's `bregctl`, then start
this release's `breg`:

1. Run `bregctl test PROJECT --baseline-package DEPLOYED ...` and
   `bregctl package PROJECT --test-receipt RECEIPT --output BUILD
   --baseline-package DEPLOYED` on the unchanged project, where `DEPLOYED` is
   the active package directory. The rebuild carries the current header.
2. Run `bregctl plan --runtime-config RUNTIME --package BUILD/package`, then
   `bregctl apply` with the same arguments. The runtime file still names the
   active package. The rebuild changes no schema; `apply` activates it and
   records it in the migration ledger as a `metadata_only` activation whose
   predecessor is the deployed package digest.
3. Point `package.root` and `package.expectedDigest` in `runtime.yaml` at the
   rebuild and start `breg`.

The same upgrade may carry a project change: the rebuild then follows the
ordinary successor path, with `--reviewed-migrations` where the change needs
review. `test` rebuilds the deployed registry from its packaged sources with
this release's compiler; when the stricter reader refuses those sources, it
reports `migration.rehearsal.baseline_unavailable`.

### BREAKING: a statistical dataset's period is tagged by `type`

Statistical datasets are experimental, so their members follow the
conventions now (CFG-ID-7, CFG-ID-1) rather than at the stable move.

| Was | Is |
|---|---|
| `period: {kind: flow, ...}` | `period: {type: flow, ...}` |
| `period: {kind: stock, ...}` | `period: {type: stock, ...}` |
| a dataset `id` outside `^[a-z][a-z0-9_-]{0,63}$` refused by the compiler as `breg.identifier.invalid` | refused when the project is read, as `config.invalid-value` at `statisticalDatasets[N].id` |

A period that still writes `kind` is refused with `config.removed-key` at
`period.kind`, whose fix names `type`, beside `config.missing-key` for the
absent `type`. The identifier grammar is unchanged, so a dataset id the
compiler accepted is still accepted.

To migrate, rename the member in each `statisticalDatasets[].period` of
`registry.yaml`:

```sh
perl -pi -e 's/^(\s+)kind: (flow|stock)$/$1type: $2/' registry.yaml
```

then review the diff: the expression also renames any other `kind: flow` or
`kind: stock` line in the file. Rebuild and promote the project as usual.
`bregctl test` rebuilds a deployed registry from its packaged sources with
this release's reader, so a deployed package whose project still writes
`kind` cannot be rehearsed and reports
`migration.rehearsal.baseline_unavailable`.

### BREAKING: configuration diagnostic codes are named `breg.<area>.<condition>`

Every code the Base Registry Engine reports for a problem in
`registry.yaml`, a `module.yaml`, `runtime.yaml`, or a package is named
`breg.<area>.<condition>` in lowercase kebab segments (CFG-DIAG-3), in
`bregctl check`, `bregctl package`, `bregctl explain`, `bregctl test`, every
other command that compiles a project, and `breg` at startup. Each
condition keeps its meaning, its path, and its message; only the code
changes. The shared reader's own `config.*`, `yaml.*`, and `platform.*` codes
are unchanged.

A rule the runtime decides about `runtime.yaml` after reading it was reported
under each command's prefix, such as `startup.runtime_config.invalid_listener`
from `bregctl doctor` or `verify.runtime_config.invalid_listener` from
`bregctl verify`. Every command now reports it as its `breg.runtime.*` code,
with no command prefix and with its fix after the message. `bregctl check`
reported a package it refused as `check.package.<cause>`; it now reports
`breg.package.<cause>`.

Codes that name a `bregctl` operation or a usage error rather than a
problem in a file are unchanged: `apply.*`, `history.*`, `test.*`,
`status.*`, `init.*`, `migration.*`, `data.*`, `import.*`, `webhook.*`,
`artifact.*`, `field_encryption.*`, `bregctl doctor`'s `startup.*`,
`<command>.runtime_config.path_invalid`,
`import_authority.runtime_config.invalid`,
`instance_claim.runtime_config.invalid`, `package.baseline.*`,
`package.build.refused`, `package.identity.refused`,
`package.output.refused`, `package.test_receipt.*`, `diff.baseline.*`,
`module.consent.*`, `module.lock.concurrent_change`,
`module.lock.render_failed`, `module.lock.write_failed`, and the
`bregctl explain` usage codes. HTTP problem codes and the runtime's request
error codes are unchanged too, including `action.handler.entrypoint`,
`action.handler.execution`, and `change_request.planner.entrypoint` as a
running handler or planner reports them; the compile-time refusals that
shared those spellings are renamed in the table.

To migrate, replace each code below wherever a script, a CI step, an alert, or
a dashboard matches `bregctl --format json` output or `breg` startup output.
The rule is mechanical: `breg.`, the first segment in kebab case, `.`, and the
remaining segments joined by `-` in kebab case, so
`access_profile.task_grant.invalid` becomes
`breg.access-profile.task-grant-invalid`. `runtime_config.<cause>`, reported
with any command prefix, becomes `breg.runtime.<cause>` in kebab case. The
five `check.package.*` codes named the command rather than the area; they
become `breg.package.*`, and `check.package.package_refused` becomes
`breg.package.refused`.

| Was | Is |
|---|---|
| `access.action.no_required_scope` | `breg.access.action-no-required-scope` |
| `access.consent.ungated_client` | `breg.access.consent-ungated-client` |
| `access.membership.active_type` | `breg.access.membership-active-type` |
| `access.membership.authentication` | `breg.access.membership-authentication` |
| `access.membership.duplicate` | `breg.access.membership-duplicate` |
| `access.membership.entity_unknown` | `breg.access.membership-entity-unknown` |
| `access.membership.key_type` | `breg.access.membership-key-type` |
| `access.membership.limit` | `breg.access.membership-limit` |
| `access.membership.principal_encrypted` | `breg.access.membership-principal-encrypted` |
| `access.membership.principal_type` | `breg.access.membership-principal-type` |
| `access.membership.read_only` | `breg.access.membership-read-only` |
| `access.membership.read_path_target` | `breg.access.membership-read-path-target` |
| `access.membership.request_unsupported` | `breg.access.membership-request-unsupported` |
| `access.membership.source_recursive` | `breg.access.membership-source-recursive` |
| `access.membership.source_row_requirement` | `breg.access.membership-source-row-requirement` |
| `access.membership.spatial_unsupported` | `breg.access.membership-spatial-unsupported` |
| `access.profile.anonymous_collection` | `breg.access.profile-anonymous-collection` |
| `access.profile.create_required_field_not_writable` | `breg.access.profile-create-required-field-not-writable` |
| `access.profile.data_export` | `breg.access.profile-data-export` |
| `access.profile.higher_classification` | `breg.access.profile-higher-classification` |
| `access.profile.no_required_scope` | `breg.access.profile-no-required-scope` |
| `access.profile.no_writable_fields` | `breg.access.profile-no-writable-fields` |
| `access.profile.related_disclosure` | `breg.access.profile-related-disclosure` |
| `access.profile.revision_history` | `breg.access.profile-revision-history` |
| `access.profile.row_boundary_not_writable` | `breg.access.profile-row-boundary-not-writable` |
| `access.profile.snapshot_history` | `breg.access.profile-snapshot-history` |
| `access.profile.unrestricted_collection` | `breg.access.profile-unrestricted-collection` |
| `access.profile.unrestricted_rows` | `breg.access.profile-unrestricted-rows` |
| `access.profile.writable_row_boundary` | `breg.access.profile-writable-row-boundary` |
| `access.requirements.authentication` | `breg.access.requirements-authentication` |
| `access.requirements.empty` | `breg.access.requirements-empty` |
| `access.requirements.empty_value` | `breg.access.requirements-empty-value` |
| `access.requirements.purpose_widened` | `breg.access.requirements-purpose-widened` |
| `access.requirements.read_path.row_boundary_unsupported` | `breg.access.requirements-read-path-row-boundary-unsupported` |
| `access.requirements.row_boundary.invalid` | `breg.access.requirements-row-boundary-invalid` |
| `access.requirements.row_boundary_missing` | `breg.access.requirements-row-boundary-missing` |
| `access.requirements.scope_missing` | `breg.access.requirements-scope-missing` |
| `access.target.unrestricted_rows` | `breg.access.target-unrestricted-rows` |
| `access_log.anonymous_read_forbidden` | `breg.access-log.anonymous-read-forbidden` |
| `access_log.exemption.delay_invalid` | `breg.access-log.exemption-delay-invalid` |
| `access_log.exemption.profile_invalid` | `breg.access-log.exemption-profile-invalid` |
| `access_log.exemption.reason_invalid` | `breg.access-log.exemption-reason-invalid` |
| `access_log.exemptions.too_many` | `breg.access-log.exemptions-too-many` |
| `access_log.retention_days.invalid` | `breg.access-log.retention-days-invalid` |
| `access_log.subject_field.invalid` | `breg.access-log.subject-field-invalid` |
| `access_log.trusted_intermediaries.too_many` | `breg.access-log.trusted-intermediaries-too-many` |
| `access_log.trusted_intermediary.invalid` | `breg.access-log.trusted-intermediary-invalid` |
| `access_profile.actor_client.binding_required` | `breg.access-profile.actor-client-binding-required` |
| `access_profile.anonymous.claim_requirements_forbidden` | `breg.access-profile.anonymous-claim-requirements-forbidden` |
| `access_profile.anonymous.mutation_forbidden` | `breg.access-profile.anonymous-mutation-forbidden` |
| `access_profile.batch.underlying_operation_required` | `breg.access-profile.batch-underlying-operation-required` |
| `access_profile.claim_value.invalid` | `breg.access-profile.claim-value-invalid` |
| `access_profile.count.unavailable` | `breg.access-profile.count-unavailable` |
| `access_profile.data_export.invalid` | `breg.access-profile.data-export-invalid` |
| `access_profile.default.invalid` | `breg.access-profile.default-invalid` |
| `access_profile.field.unknown` | `breg.access-profile.field-unknown` |
| `access_profile.id.duplicate` | `breg.access-profile.id-duplicate` |
| `access_profile.lookup.claim_mapping_invalid` | `breg.access-profile.lookup-claim-mapping-invalid` |
| `access_profile.lookup.claim_mapping_unavailable` | `breg.access-profile.lookup-claim-mapping-unavailable` |
| `access_profile.lookup.duplicate` | `breg.access-profile.lookup-duplicate` |
| `access_profile.lookup.operation_required` | `breg.access-profile.lookup-operation-required` |
| `access_profile.lookup.selector_unknown` | `breg.access-profile.lookup-selector-unknown` |
| `access_profile.operation.unavailable` | `breg.access-profile.operation-unavailable` |
| `access_profile.operations.empty` | `breg.access-profile.operations-empty` |
| `access_profile.permission.action_fields_forbidden` | `breg.access-profile.permission-action-fields-forbidden` |
| `access_profile.permission.duplicate` | `breg.access-profile.permission-duplicate` |
| `access_profile.permission.entity_unknown` | `breg.access-profile.permission-entity-unknown` |
| `access_profile.permission.target_exclusive` | `breg.access-profile.permission-target-exclusive` |
| `access_profile.permission.target_missing` | `breg.access-profile.permission-target-missing` |
| `access_profile.principal_claim.forbidden` | `breg.access-profile.principal-claim-forbidden` |
| `access_profile.principal_claim.required` | `breg.access-profile.principal-claim-required` |
| `access_profile.processing.encrypted` | `breg.access-profile.processing-encrypted` |
| `access_profile.processing.wider_than_read` | `breg.access-profile.processing-wider-than-read` |
| `access_profile.project_entity_local.forbidden` | `breg.access-profile.project-entity-local-forbidden` |
| `access_profile.provenance_fields.invalid` | `breg.access-profile.provenance-fields-invalid` |
| `access_profile.public.processing_non_public` | `breg.access-profile.public-processing-non-public` |
| `access_profile.read_path.count_without_fields` | `breg.access-profile.read-path-count-without-fields` |
| `access_profile.read_path.duplicate` | `breg.access-profile.read-path-duplicate` |
| `access_profile.read_path.field_unknown` | `breg.access-profile.read-path-field-unknown` |
| `access_profile.read_path.processing.wider_than_read` | `breg.access-profile.read-path-processing-wider-than-read` |
| `access_profile.read_path.readable_fields_empty` | `breg.access-profile.read-path-readable-fields-empty` |
| `access_profile.read_path.self_target` | `breg.access-profile.read-path-self-target` |
| `access_profile.read_path.unknown` | `breg.access-profile.read-path-unknown` |
| `access_profile.request_fields.invalid` | `breg.access-profile.request-fields-invalid` |
| `access_profile.request_visibility.invalid` | `breg.access-profile.request-visibility-invalid` |
| `access_profile.requester_client.invalid` | `breg.access-profile.requester-client-invalid` |
| `access_profile.row_boundary.encrypted` | `breg.access-profile.row-boundary-encrypted` |
| `access_profile.row_boundary.invalid` | `breg.access-profile.row-boundary-invalid` |
| `access_profile.row_boundary.type_unsupported` | `breg.access-profile.row-boundary-type-unsupported` |
| `access_profile.snapshot.anonymous_forbidden` | `breg.access-profile.snapshot-anonymous-forbidden` |
| `access_profile.spatial_queries.bbox.geometry_not_readable` | `breg.access-profile.spatial-queries-bbox-geometry-not-readable` |
| `access_profile.spatial_queries.bbox.geometry_required` | `breg.access-profile.spatial-queries-bbox-geometry-required` |
| `access_profile.spatial_queries.bbox.list_required` | `breg.access-profile.spatial-queries-bbox-list-required` |
| `access_profile.spatial_queries.bbox.maximum_latitude_span_degrees.invalid` | `breg.access-profile.spatial-queries-bbox-maximum-latitude-span-degrees-invalid` |
| `access_profile.spatial_queries.bbox.maximum_longitude_span_degrees.invalid` | `breg.access-profile.spatial-queries-bbox-maximum-longitude-span-degrees-invalid` |
| `access_profile.spatial_queries.empty` | `breg.access-profile.spatial-queries-empty` |
| `access_profile.standing_agent.action_forbidden` | `breg.access-profile.standing-agent-action-forbidden` |
| `access_profile.standing_agent.direct_mutation_forbidden` | `breg.access-profile.standing-agent-direct-mutation-forbidden` |
| `access_profile.standing_agent.operation_forbidden` | `breg.access-profile.standing-agent-operation-forbidden` |
| `access_profile.task_grant.binding_required` | `breg.access-profile.task-grant-binding-required` |
| `access_profile.task_grant.direct_mutation_forbidden` | `breg.access-profile.task-grant-direct-mutation-forbidden` |
| `access_profile.task_grant.invalid` | `breg.access-profile.task-grant-invalid` |
| `access_profile.task_grant.module_forbidden` | `breg.access-profile.task-grant-module-forbidden` |
| `access_profile.task_grant.operation_forbidden` | `breg.access-profile.task-grant-operation-forbidden` |
| `action.bounds.field_mutations` | `breg.action.bounds-field-mutations` |
| `action.bounds.snapshot_bytes` | `breg.action.bounds-snapshot-bytes` |
| `action.bounds.snapshot_unknown` | `breg.action.bounds-snapshot-unknown` |
| `action.bounds.targets` | `breg.action.bounds-targets` |
| `action.effect.clear_on_create` | `breg.action.effect-clear-on-create` |
| `action.effect.clear_required` | `breg.action.effect-clear-required` |
| `action.effect.controlled_target` | `breg.action.effect-controlled-target` |
| `action.effect.create_id_required` | `breg.action.effect-create-id-required` |
| `action.effect.create_required_field_missing` | `breg.action.effect-create-required-field-missing` |
| `action.effect.dependency_cycle` | `breg.action.effect-dependency-cycle` |
| `action.effect.empty` | `breg.action.effect-empty` |
| `action.effect.field_unknown` | `breg.action.effect-field-unknown` |
| `action.effect.id_duplicate` | `breg.action.effect-id-duplicate` |
| `action.effect.operation.unavailable` | `breg.action.effect-operation-unavailable` |
| `action.effect.operation.unsupported` | `breg.action.effect-operation-unsupported` |
| `action.effect.overlapping_write` | `breg.action.effect-overlapping-write` |
| `action.effect.request_target` | `breg.action.effect-request-target` |
| `action.effect.target.input_unknown` | `breg.action.effect-target-input-unknown` |
| `action.effect.target.invalid` | `breg.action.effect-target-invalid` |
| `action.effect.target.reference_required` | `breg.action.effect-target-reference-required` |
| `action.effect.target.unknown` | `breg.action.effect-target-unknown` |
| `action.effect.value.effect_unknown` | `breg.action.effect-value-effect-unknown` |
| `action.effect.value.input_unknown` | `breg.action.effect-value-input-unknown` |
| `action.effect.value.invalid` | `breg.action.effect-value-invalid` |
| `action.effect.value.type_mismatch` | `breg.action.effect-value-type-mismatch` |
| `action.effect.value_nullable` | `breg.action.effect-value-nullable` |
| `action.effect.value_reference_mismatch` | `breg.action.effect-value-reference-mismatch` |
| `action.effect.value_reference_required` | `breg.action.effect-value-reference-required` |
| `action.evidence.capability.invalid` | `breg.action.evidence-capability-invalid` |
| `action.evidence.ceiling.invalid` | `breg.action.evidence-ceiling-invalid` |
| `action.evidence.contract.invalid` | `breg.action.evidence-contract-invalid` |
| `action.evidence.module.unsupported` | `breg.action.evidence-module-unsupported` |
| `action.evidence.provider.unknown` | `breg.action.evidence-provider-unknown` |
| `action.handler.abi_invalid` | `breg.action.handler-abi-invalid` |
| `action.handler.classification_ceiling` | `breg.action.handler-classification-ceiling` |
| `action.handler.create_fields_incomplete` | `breg.action.handler-create-fields-incomplete` |
| `action.handler.entrypoint` | `breg.action.handler-entrypoint` |
| `action.handler.execution` | `breg.action.handler-execution` |
| `action.handler.field_duplicate` | `breg.action.handler-field-duplicate` |
| `action.handler.field_unknown` | `breg.action.handler-field-unknown` |
| `action.handler.fields_empty` | `breg.action.handler-fields-empty` |
| `action.handler.helper_contract` | `breg.action.handler-helper-contract` |
| `action.handler.input.string_bound` | `breg.action.handler-input-string-bound` |
| `action.handler.input.type_unsupported` | `breg.action.handler-input-type-unsupported` |
| `action.handler.inputs_bound` | `breg.action.handler-inputs-bound` |
| `action.handler.kind.unsupported` | `breg.action.handler-kind-unsupported` |
| `action.handler.module_asset_missing` | `breg.action.handler-module-asset-missing` |
| `action.handler.module_bound` | `breg.action.handler-module-bound` |
| `action.handler.module_export_missing` | `breg.action.handler-module-export-missing` |
| `action.handler.module_export_type` | `breg.action.handler-module-export-type` |
| `action.handler.module_export_unexpected` | `breg.action.handler-module-export-unexpected` |
| `action.handler.module_import_unsupported` | `breg.action.handler-module-import-unsupported` |
| `action.handler.module_invalid` | `breg.action.handler-module-invalid` |
| `action.handler.module_source_invalid` | `breg.action.handler-module-source-invalid` |
| `action.handler.modules_bound` | `breg.action.handler-modules-bound` |
| `action.handler.parse` | `breg.action.handler-parse` |
| `action.handler.reference_required` | `breg.action.handler-reference-required` |
| `action.handler.reference_source_missing` | `breg.action.handler-reference-source-missing` |
| `action.handler.refusal_bound` | `breg.action.handler-refusal-bound` |
| `action.handler.refusal_invalid` | `breg.action.handler-refusal-invalid` |
| `action.handler.slot_duplicate` | `breg.action.handler-slot-duplicate` |
| `action.handler.slots_bound` | `breg.action.handler-slots-bound` |
| `action.handler.source_bound` | `breg.action.handler-source-bound` |
| `action.handler.source_encoding` | `breg.action.handler-source-encoding` |
| `action.handler.source_invalid` | `breg.action.handler-source-invalid` |
| `action.handler.source_missing` | `breg.action.handler-source-missing` |
| `action.handler.target_required` | `breg.action.handler-target-required` |
| `action.handler.wasm_abi_unsupported` | `breg.action.handler-wasm-abi-unsupported` |
| `action.handler.wasm_build_unsupported` | `breg.action.handler-wasm-build-unsupported` |
| `action.handler.writes_empty` | `breg.action.handler-writes-empty` |
| `action.id.duplicate` | `breg.action.id-duplicate` |
| `action.implementation.exclusive` | `breg.action.implementation-exclusive` |
| `action.input.api_name.duplicate` | `breg.action.input-api-name-duplicate` |
| `action.input.api_name.invalid` | `breg.action.input-api-name-invalid` |
| `action.input.crs84_point.bounds_invalid` | `breg.action.input-crs84-point-bounds-invalid` |
| `action.input.decimal.bounds_invalid` | `breg.action.input-decimal-bounds-invalid` |
| `action.input.id.duplicate` | `breg.action.input-id-duplicate` |
| `action.input.id.reserved` | `breg.action.input-id-reserved` |
| `action.input.reference.target_invalid` | `breg.action.input-reference-target-invalid` |
| `action.input.reference.target_unknown` | `breg.action.input-reference-target-unknown` |
| `action.input.string.bounds_invalid` | `breg.action.input-string-bounds-invalid` |
| `action.input.structured.schema_invalid` | `breg.action.input-structured-schema-invalid` |
| `action.input.text.bound_invalid` | `breg.action.input-text-bound-invalid` |
| `action.input.vocabulary.unknown` | `breg.action.input-vocabulary-unknown` |
| `action.input.vocabulary.values_invalid` | `breg.action.input-vocabulary-values-invalid` |
| `action.inputs.empty` | `breg.action.inputs-empty` |
| `action.permission.action_unknown` | `breg.action.permission-action-unknown` |
| `action.permission.anonymous_forbidden` | `breg.action.permission-anonymous-forbidden` |
| `action.permission.duplicate` | `breg.action.permission-duplicate` |
| `action.permission.entity_fields_forbidden` | `breg.action.permission-entity-fields-forbidden` |
| `action.permission.exclusive` | `breg.action.permission-exclusive` |
| `action.permission.missing` | `breg.action.permission-missing` |
| `action.permission.operation.invalid` | `breg.action.permission-operation-invalid` |
| `action.permission.result_unknown` | `breg.action.permission-result-unknown` |
| `action.permission.row_boundary_field_unknown` | `breg.action.permission-row-boundary-field-unknown` |
| `action.permission.row_boundary_invalid` | `breg.action.permission-row-boundary-invalid` |
| `action.permission.row_boundary_type_unsupported` | `breg.action.permission-row-boundary-type-unsupported` |
| `action.permission.target.duplicate` | `breg.action.permission-target-duplicate` |
| `action.permission.target_unknown` | `breg.action.permission-target-unknown` |
| `action.permission.targets.incomplete` | `breg.action.permission-targets-incomplete` |
| `action.permission.targets.unused` | `breg.action.permission-targets-unused` |
| `action.requires.bounds` | `breg.action.requires-bounds` |
| `action.requires.duplicate` | `breg.action.requires-duplicate` |
| `action.requires.field_encrypted` | `breg.action.requires-field-encrypted` |
| `action.requires.field_unknown` | `breg.action.requires-field-unknown` |
| `action.requires.input_unknown` | `breg.action.requires-input-unknown` |
| `action.requires.reference_required` | `breg.action.requires-reference-required` |
| `action.requires.value_invalid` | `breg.action.requires-value-invalid` |
| `action.route_access.default_multiple` | `breg.action.route-access-default-multiple` |
| `artifact.canonicalization_failed` | `breg.artifact.canonicalization-failed` |
| `attachment.access.authentication_required` | `breg.attachment.access-authentication-required` |
| `attachment.access.processing_unsupported` | `breg.attachment.access-processing-unsupported` |
| `attachment.content_type.duplicate` | `breg.attachment.content-type-duplicate` |
| `attachment.content_type.invalid` | `breg.attachment.content-type-invalid` |
| `attachment.content_types.bounds_invalid` | `breg.attachment.content-types-bounds-invalid` |
| `attachment.entity.not_request` | `breg.attachment.entity-not-request` |
| `attachment.id.collision` | `breg.attachment.id-collision` |
| `attachment.id.duplicate` | `breg.attachment.id-duplicate` |
| `attachment.maximum_bytes.bounds_invalid` | `breg.attachment.maximum-bytes-bounds-invalid` |
| `attachment.slots.bounds_invalid` | `breg.attachment.slots-bounds-invalid` |
| `change_control.direct_write_grant` | `breg.change-control.direct-write-grant` |
| `change_control.operation.unsupported` | `breg.change-control.operation-unsupported` |
| `change_control.required_for.empty` | `breg.change-control.required-for-empty` |
| `change_request.apply_target.operation_required` | `breg.change-request.apply-target-operation-required` |
| `change_request.apply_target.unknown` | `breg.change-request.apply-target-unknown` |
| `change_request.apply_targets.incomplete` | `breg.change-request.apply-targets-incomplete` |
| `change_request.bounds.field_mutations` | `breg.change-request.bounds-field-mutations` |
| `change_request.bounds.snapshot_bytes` | `breg.change-request.bounds-snapshot-bytes` |
| `change_request.bounds.snapshot_unknown` | `breg.change-request.bounds-snapshot-unknown` |
| `change_request.bounds.targets` | `breg.change-request.bounds-targets` |
| `change_request.change_control_conflict` | `breg.change-request.change-control-conflict` |
| `change_request.effect.clear_on_create` | `breg.change-request.effect-clear-on-create` |
| `change_request.effect.clear_required` | `breg.change-request.effect-clear-required` |
| `change_request.effect.create_id_required` | `breg.change-request.effect-create-id-required` |
| `change_request.effect.dependency_cycle` | `breg.change-request.effect-dependency-cycle` |
| `change_request.effect.empty` | `breg.change-request.effect-empty` |
| `change_request.effect.field_encrypted` | `breg.change-request.effect-field-encrypted` |
| `change_request.effect.field_unknown` | `breg.change-request.effect-field-unknown` |
| `change_request.effect.id_duplicate` | `breg.change-request.effect-id-duplicate` |
| `change_request.effect.nested_request_target` | `breg.change-request.effect-nested-request-target` |
| `change_request.effect.operation_unavailable` | `breg.change-request.effect-operation-unavailable` |
| `change_request.effect.operation_unsupported` | `breg.change-request.effect-operation-unsupported` |
| `change_request.effect.overlapping_write` | `breg.change-request.effect-overlapping-write` |
| `change_request.effect.target.invalid` | `breg.change-request.effect-target-invalid` |
| `change_request.effect.target_field_type` | `breg.change-request.effect-target-field-type` |
| `change_request.effect.target_field_unknown` | `breg.change-request.effect-target-field-unknown` |
| `change_request.effect.target_unknown` | `breg.change-request.effect-target-unknown` |
| `change_request.effect.uncontrolled_target` | `breg.change-request.effect-uncontrolled-target` |
| `change_request.effect.value.invalid` | `breg.change-request.effect-value-invalid` |
| `change_request.effect.value_effect_unknown` | `breg.change-request.effect-value-effect-unknown` |
| `change_request.effect.value_field_encrypted` | `breg.change-request.effect-value-field-encrypted` |
| `change_request.effect.value_field_unknown` | `breg.change-request.effect-value-field-unknown` |
| `change_request.effect.value_nullable` | `breg.change-request.effect-value-nullable` |
| `change_request.effect.value_reference_mismatch` | `breg.change-request.effect-value-reference-mismatch` |
| `change_request.effect.value_reference_required` | `breg.change-request.effect-value-reference-required` |
| `change_request.effect.value_type_mismatch` | `breg.change-request.effect-value-type-mismatch` |
| `change_request.field.api_name_reserved` | `breg.change-request.field-api-name-reserved` |
| `change_request.mutation_mode.invalid` | `breg.change-request.mutation-mode-invalid` |
| `change_request.on_approved.executor_forbidden` | `breg.change-request.on-approved-executor-forbidden` |
| `change_request.on_approved.executor_required` | `breg.change-request.on-approved-executor-required` |
| `change_request.permission.row_boundary_field_unknown` | `breg.change-request.permission-row-boundary-field-unknown` |
| `change_request.permission.row_boundary_invalid` | `breg.change-request.permission-row-boundary-invalid` |
| `change_request.permission.row_boundary_type_unsupported` | `breg.change-request.permission-row-boundary-type-unsupported` |
| `change_request.plan.exclusive` | `breg.change-request.plan-exclusive` |
| `change_request.planner.abi_invalid` | `breg.change-request.planner-abi-invalid` |
| `change_request.planner.asset_undeclared` | `breg.change-request.planner-asset-undeclared` |
| `change_request.planner.classification_ceiling` | `breg.change-request.planner-classification-ceiling` |
| `change_request.planner.create_fields_incomplete` | `breg.change-request.planner-create-fields-incomplete` |
| `change_request.planner.entrypoint` | `breg.change-request.planner-entrypoint` |
| `change_request.planner.kind_unsupported` | `breg.change-request.planner-kind-unsupported` |
| `change_request.planner.request_field_duplicate` | `breg.change-request.planner-request-field-duplicate` |
| `change_request.planner.request_field_encrypted` | `breg.change-request.planner-request-field-encrypted` |
| `change_request.planner.request_field_unknown` | `breg.change-request.planner-request-field-unknown` |
| `change_request.planner.snapshot_ceiling` | `breg.change-request.planner-snapshot-ceiling` |
| `change_request.planner.source_bound` | `breg.change-request.planner-source-bound` |
| `change_request.planner.source_encoding` | `breg.change-request.planner-source-encoding` |
| `change_request.planner.source_invalid` | `breg.change-request.planner-source-invalid` |
| `change_request.planner.source_missing` | `breg.change-request.planner-source-missing` |
| `change_request.planner.write_ceiling` | `breg.change-request.planner-write-ceiling` |
| `change_request.planner.write_duplicate` | `breg.change-request.planner-write-duplicate` |
| `change_request.planner.write_entity_unknown` | `breg.change-request.planner-write-entity-unknown` |
| `change_request.planner.write_field_duplicate` | `breg.change-request.planner-write-field-duplicate` |
| `change_request.planner.write_field_encrypted` | `breg.change-request.planner-write-field-encrypted` |
| `change_request.planner.write_field_unknown` | `breg.change-request.planner-write-field-unknown` |
| `change_request.planner.write_fields_empty` | `breg.change-request.planner-write-fields-empty` |
| `change_request.planner.write_operation_invalid` | `breg.change-request.planner-write-operation-invalid` |
| `change_request.planner.write_reference_type` | `breg.change-request.planner-write-reference-type` |
| `change_request.planner.write_reference_undeclared` | `breg.change-request.planner-write-reference-undeclared` |
| `change_request.planner.write_reference_unknown` | `breg.change-request.planner-write-reference-unknown` |
| `change_request.planner.write_target_invalid` | `breg.change-request.planner-write-target-invalid` |
| `change_request.planner.writes_empty` | `breg.change-request.planner-writes-empty` |
| `change_request.preconditions.bounds` | `breg.change-request.preconditions-bounds` |
| `change_request.preconditions.evidence_duplicate` | `breg.change-request.preconditions-evidence-duplicate` |
| `change_request.preconditions.evidence_invalid` | `breg.change-request.preconditions-evidence-invalid` |
| `change_request.preconditions.evidence_requirement_encrypted` | `breg.change-request.preconditions-evidence-requirement-encrypted` |
| `change_request.preconditions.evidence_requirement_invalid` | `breg.change-request.preconditions-evidence-requirement-invalid` |
| `change_request.preconditions.predicate_current_date_invalid` | `breg.change-request.preconditions-predicate-current-date-invalid` |
| `change_request.preconditions.predicate_duplicate` | `breg.change-request.preconditions-predicate-duplicate` |
| `change_request.preconditions.predicate_field_encrypted` | `breg.change-request.preconditions-predicate-field-encrypted` |
| `change_request.preconditions.predicate_field_invalid` | `breg.change-request.preconditions-predicate-field-invalid` |
| `change_request.preconditions.predicate_field_unknown` | `breg.change-request.preconditions-predicate-field-unknown` |
| `change_request.preconditions.predicate_numeric_invalid` | `breg.change-request.preconditions-predicate-numeric-invalid` |
| `change_request.preconditions.predicate_operator_invalid` | `breg.change-request.preconditions-predicate-operator-invalid` |
| `change_request.preconditions.predicate_request_field_encrypted` | `breg.change-request.preconditions-predicate-request-field-encrypted` |
| `change_request.preconditions.predicate_request_field_invalid` | `breg.change-request.preconditions-predicate-request-field-invalid` |
| `change_request.preconditions.predicate_value_invalid` | `breg.change-request.preconditions-predicate-value-invalid` |
| `change_request.preconditions.selector_binding_invalid` | `breg.change-request.preconditions-selector-binding-invalid` |
| `change_request.preconditions.selector_field_encrypted` | `breg.change-request.preconditions-selector-field-encrypted` |
| `change_request.preconditions.selector_fields_invalid` | `breg.change-request.preconditions-selector-fields-invalid` |
| `change_request.preconditions.target_duplicate` | `breg.change-request.preconditions-target-duplicate` |
| `change_request.preconditions.target_effect_collision` | `breg.change-request.preconditions-target-effect-collision` |
| `change_request.preconditions.target_empty` | `breg.change-request.preconditions-target-empty` |
| `change_request.preconditions.target_entity_unknown` | `breg.change-request.preconditions-target-entity-unknown` |
| `change_request.preconditions.target_field_unknown` | `breg.change-request.preconditions-target-field-unknown` |
| `change_request.preconditions.target_fields_exceeded` | `breg.change-request.preconditions-target-fields-exceeded` |
| `change_request.preconditions.target_reference_invalid` | `breg.change-request.preconditions-target-reference-invalid` |
| `change_request.presence.anonymous_claim_boundary` | `breg.change-request.presence-anonymous-claim-boundary` |
| `change_request.presence.anonymous_non_public` | `breg.change-request.presence-anonymous-non-public` |
| `change_request.presence.request_type_unknown` | `breg.change-request.presence-request-type-unknown` |
| `change_request.presence.target_unaffected` | `breg.change-request.presence-target-unaffected` |
| `change_request.submit_operation.missing` | `breg.change-request.submit-operation-missing` |
| `change_request.submitter_targets.invalid` | `breg.change-request.submitter-targets-invalid` |
| `change_request.tombstone_forbidden` | `breg.change-request.tombstone-forbidden` |
| `check.package.binding_refused` | `breg.package.binding-refused` |
| `check.package.integrity_refused` | `breg.package.integrity-refused` |
| `check.package.package_refused` | `breg.package.refused` |
| `check.package.path_refused` | `breg.package.path-refused` |
| `check.package.permissions_refused` | `breg.package.permissions-refused` |
| `consent.feed.claim` | `breg.consent.feed-claim` |
| `consent.issuer.declared` | `breg.consent.issuer-declared` |
| `consent.issuer.self_binding` | `breg.consent.issuer-self-binding` |
| `consent.record.direct_write` | `breg.consent.record-direct-write` |
| `consent.record.fields` | `breg.consent.record-fields` |
| `consent.record.leaf` | `breg.consent.record-leaf` |
| `consent.record.max_duration` | `breg.consent.record-max-duration` |
| `consent.record.mutation_mode` | `breg.consent.record-mutation-mode` |
| `consent.record.plaintext` | `breg.consent.record-plaintext` |
| `consent.record.values` | `breg.consent.record-values` |
| `consent.require.anonymous` | `breg.consent.require-anonymous` |
| `consent.require.clients` | `breg.consent.require-clients` |
| `consent.require.evidence_source_unsupported` | `breg.consent.require-evidence-source-unsupported` |
| `consent.require.export_unsupported` | `breg.consent.require-export-unsupported` |
| `consent.require.key` | `breg.consent.require-key` |
| `consent.require.purpose` | `breg.consent.require-purpose` |
| `consent.require.read_only` | `breg.consent.require-read-only` |
| `consent.require.read_path_target` | `breg.consent.require-read-path-target` |
| `consent.require.spatial_unsupported` | `breg.consent.require-spatial-unsupported` |
| `consent.require.unused` | `breg.consent.require-unused` |
| `consent.vocabulary.reserved` | `breg.consent.vocabulary-reserved` |
| `constraint.compare.type_mismatch` | `breg.constraint.compare-type-mismatch` |
| `constraint.field.encrypted` | `breg.constraint.field-encrypted` |
| `constraint.field.unknown` | `breg.constraint.field-unknown` |
| `constraint.fields.duplicate` | `breg.constraint.fields-duplicate` |
| `constraint.id.duplicate` | `breg.constraint.id-duplicate` |
| `constraint.range.invalid` | `breg.constraint.range-invalid` |
| `constraint.temporal.roles_invalid` | `breg.constraint.temporal-roles-invalid` |
| `constraint.temporal.scope_nullable` | `breg.constraint.temporal-scope-nullable` |
| `constraint.temporal.scope_type_unsupported` | `breg.constraint.temporal-scope-type-unsupported` |
| `constraint.unique.when.contradiction` | `breg.constraint.unique-when-contradiction` |
| `constraint.unique.when.duplicate` | `breg.constraint.unique-when-duplicate` |
| `constraint.unique.when.empty` | `breg.constraint.unique-when-empty` |
| `constraint.unique.when.field_unknown` | `breg.constraint.unique-when-field-unknown` |
| `constraint.unique.when.field_unsupported` | `breg.constraint.unique-when-field-unsupported` |
| `constraint.unique.when.literal_invalid` | `breg.constraint.unique-when-literal-invalid` |
| `constraint.unique.when.null_invalid` | `breg.constraint.unique-when-null-invalid` |
| `constraint.vocabulary.invalid` | `breg.constraint.vocabulary-invalid` |
| `derived.execution.unsupported` | `breg.derived.execution-unsupported` |
| `derived.fields.empty` | `breg.derived.fields-empty` |
| `derived.id.duplicate` | `breg.derived.id-duplicate` |
| `derived.key.invalid` | `breg.derived.key-invalid` |
| `derived.sql.asset_missing` | `breg.derived.sql-asset-missing` |
| `derived.sql.encrypted_column` | `breg.derived.sql-encrypted-column` |
| `derived.sql.invalid` | `breg.derived.sql-invalid` |
| `derived.sql_path.invalid` | `breg.derived.sql-path-invalid` |
| `entity.batch.bounds_invalid` | `breg.entity.batch-bounds-invalid` |
| `entity.batch.required` | `breg.entity.batch-required` |
| `entity.encrypted_fields.too_many` | `breg.entity.encrypted-fields-too-many` |
| `entity.id.duplicate` | `breg.entity.id-duplicate` |
| `entity.list.unindexed_filter` | `breg.entity.list-unindexed-filter` |
| `entity.list.unindexed_sort` | `breg.entity.list-unindexed-sort` |
| `entity.route.duplicate` | `breg.entity.route-duplicate` |
| `entity.sql_name.duplicate` | `breg.entity.sql-name-duplicate` |
| `entity.tombstone.create_only` | `breg.entity.tombstone-create-only` |
| `event.delivery.required` | `breg.event.delivery-required` |
| `event.id.duplicate` | `breg.event.id-duplicate` |
| `event.id.registry_duplicate` | `breg.event.id-registry-duplicate` |
| `event.projection.empty` | `breg.event.projection-empty` |
| `event.projection.encrypted` | `breg.event.projection-encrypted` |
| `event.projection.field_unknown` | `breg.event.projection-field-unknown` |
| `event.trigger.request_lifecycle_requires_change_request` | `breg.event.trigger-request-lifecycle-requires-change-request` |
| `event.trigger.unavailable` | `breg.event.trigger-unavailable` |
| `event.webhook.destination.invalid` | `breg.event.webhook-destination-invalid` |
| `event.webhook.projection_too_large` | `breg.event.webhook-projection-too-large` |
| `event.when.empty` | `breg.event.when-empty` |
| `event.when.encrypted` | `breg.event.when-encrypted` |
| `event.when.field_unknown` | `breg.event.when-field-unknown` |
| `event.when.request_lifecycle_state_unknown` | `breg.event.when-request-lifecycle-state-unknown` |
| `event.when.request_lifecycle_transition_unknown` | `breg.event.when-request-lifecycle-transition-unknown` |
| `event.when.trigger_incompatible` | `breg.event.when-trigger-incompatible` |
| `event.when.value_invalid` | `breg.event.when-value-invalid` |
| `evidence_source.refused` | `breg.evidence-source.refused` |
| `extension.access_profile.duplicate` | `breg.extension.access-profile-duplicate` |
| `extension.access_requirements.replace_forbidden` | `breg.extension.access-requirements-replace-forbidden` |
| `extension.change_control.duplicate` | `breg.extension.change-control-duplicate` |
| `extension.change_request.duplicate` | `breg.extension.change-request-duplicate` |
| `extension.constraint.duplicate` | `breg.extension.constraint-duplicate` |
| `extension.derived.duplicate` | `breg.extension.derived-duplicate` |
| `extension.entity.unknown` | `breg.extension.entity-unknown` |
| `extension.event.duplicate` | `breg.extension.event-duplicate` |
| `extension.field.duplicate` | `breg.extension.field-duplicate` |
| `extension.geojson.conflict` | `breg.extension.geojson-conflict` |
| `extension.index.duplicate` | `breg.extension.index-duplicate` |
| `extension.read_path.duplicate` | `breg.extension.read-path-duplicate` |
| `extension.selector_profile.duplicate` | `breg.extension.selector-profile-duplicate` |
| `field.api_name.duplicate` | `breg.field.api-name-duplicate` |
| `field.api_name.invalid` | `breg.field.api-name-invalid` |
| `field.crs84_point.bounds_invalid` | `breg.field.crs84-point-bounds-invalid` |
| `field.decimal.bounds_invalid` | `breg.field.decimal-bounds-invalid` |
| `field.encrypted.classification_invalid` | `breg.field.encrypted-classification-invalid` |
| `field.encrypted.lookup_normalization_too_long` | `breg.field.encrypted-lookup-normalization-too-long` |
| `field.encrypted.lookup_type_unsupported` | `breg.field.encrypted-lookup-type-unsupported` |
| `field.encrypted.pattern_refused` | `breg.field.encrypted-pattern-refused` |
| `field.encrypted.size_bound_exceeds_seal_limit` | `breg.field.encrypted-size-bound-exceeds-seal-limit` |
| `field.encrypted.type_unsupported` | `breg.field.encrypted-type-unsupported` |
| `field.encrypted.valid_time_refused` | `breg.field.encrypted-valid-time-refused` |
| `field.id.duplicate` | `breg.field.id-duplicate` |
| `field.id.reserved` | `breg.field.id-reserved` |
| `field.pattern.bounds_invalid` | `breg.field.pattern-bounds-invalid` |
| `field.pattern.existing_rows_invalid` | `breg.field.pattern-existing-rows-invalid` |
| `field.pattern.syntax_invalid` | `breg.field.pattern-syntax-invalid` |
| `field.pattern.type_unsupported` | `breg.field.pattern-type-unsupported` |
| `field.pattern.unverified_offline` | `breg.field.pattern-unverified-offline` |
| `field.reference.target_unknown` | `breg.field.reference-target-unknown` |
| `field.sql_name.duplicate` | `breg.field.sql-name-duplicate` |
| `field.string.bounds_invalid` | `breg.field.string-bounds-invalid` |
| `field.structured.schema_invalid` | `breg.field.structured-schema-invalid` |
| `field.text.bound_invalid` | `breg.field.text-bound-invalid` |
| `field.valid_time.end_must_allow_open` | `breg.field.valid-time-end-must-allow-open` |
| `field.valid_time.role_duplicate` | `breg.field.valid-time-role-duplicate` |
| `field.valid_time.start_required` | `breg.field.valid-time-start-required` |
| `field.valid_time.type_invalid` | `breg.field.valid-time-type-invalid` |
| `field.valid_time.type_mismatch` | `breg.field.valid-time-type-mismatch` |
| `field.vocabulary.unknown` | `breg.field.vocabulary-unknown` |
| `field.vocabulary.values_invalid` | `breg.field.vocabulary-values-invalid` |
| `geojson.geometry_field.type_unsupported` | `breg.geojson.geometry-field-type-unsupported` |
| `geojson.geometry_field.unknown` | `breg.geojson.geometry-field-unknown` |
| `hook.handler.abi.unsupported` | `breg.hook.handler-abi-unsupported` |
| `hook.handler.entrypoint` | `breg.hook.handler-entrypoint` |
| `hook.handler.kind.unsupported` | `breg.hook.handler-kind-unsupported` |
| `hook.handler.module_asset_missing` | `breg.hook.handler-module-asset-missing` |
| `hook.handler.module_bound` | `breg.hook.handler-module-bound` |
| `hook.handler.module_invalid` | `breg.hook.handler-module-invalid` |
| `hook.handler.parse` | `breg.hook.handler-parse` |
| `hook.handler.source_bound` | `breg.hook.handler-source-bound` |
| `hook.handler.source_encoding` | `breg.hook.handler-source-encoding` |
| `hook.handler.source_missing` | `breg.hook.handler-source-missing` |
| `hook.handler.wasm_build_unsupported` | `breg.hook.handler-wasm-build-unsupported` |
| `hook.phase.unsupported` | `breg.hook.phase-unsupported` |
| `identifier.invalid` | `breg.identifier.invalid` |
| `import.batch.redundant` | `breg.import.batch-redundant` |
| `import.batch_bounds.required` | `breg.import.batch-bounds-required` |
| `import.principal.required` | `breg.import.principal-required` |
| `index.fields.encrypted` | `breg.index.fields-encrypted` |
| `index.fields.invalid` | `breg.index.fields-invalid` |
| `index.id.duplicate` | `breg.index.id-duplicate` |
| `manifest_projection.canonicalization_failed` | `breg.manifest-projection.canonicalization-failed` |
| `manifest_projection.catalog.base_url.empty` | `breg.manifest-projection.catalog-base-url-empty` |
| `manifest_projection.catalog.publisher.id_empty` | `breg.manifest-projection.catalog-publisher-id-empty` |
| `manifest_projection.catalog.publisher.name_empty` | `breg.manifest-projection.catalog-publisher-name-empty` |
| `manifest_projection.data_service.dataset_dangling` | `breg.manifest-projection.data-service-dataset-dangling` |
| `manifest_projection.data_service.dataset_duplicate` | `breg.manifest-projection.data-service-dataset-duplicate` |
| `manifest_projection.data_service.datasets_empty` | `breg.manifest-projection.data-service-datasets-empty` |
| `manifest_projection.data_service.duplicate` | `breg.manifest-projection.data-service-duplicate` |
| `manifest_projection.data_service.endpoint_url_empty` | `breg.manifest-projection.data-service-endpoint-url-empty` |
| `manifest_projection.data_services.empty` | `breg.manifest-projection.data-services-empty` |
| `manifest_projection.dataset.access_profile_ambiguous` | `breg.manifest-projection.dataset-access-profile-ambiguous` |
| `manifest_projection.dataset.access_profile_unknown` | `breg.manifest-projection.dataset-access-profile-unknown` |
| `manifest_projection.dataset.duplicate` | `breg.manifest-projection.dataset-duplicate` |
| `manifest_projection.dataset.entities_empty` | `breg.manifest-projection.dataset-entities-empty` |
| `manifest_projection.dataset.owner_empty` | `breg.manifest-projection.dataset-owner-empty` |
| `manifest_projection.datasets.empty` | `breg.manifest-projection.datasets-empty` |
| `manifest_projection.distribution.access_service_dangling` | `breg.manifest-projection.distribution-access-service-dangling` |
| `manifest_projection.distribution.dataset_dangling` | `breg.manifest-projection.distribution-dataset-dangling` |
| `manifest_projection.distribution.duplicate` | `breg.manifest-projection.distribution-duplicate` |
| `manifest_projection.distribution.location_missing` | `breg.manifest-projection.distribution-location-missing` |
| `manifest_projection.distribution.service_coverage` | `breg.manifest-projection.distribution-service-coverage` |
| `manifest_projection.entity.dataset_dangling` | `breg.manifest-projection.entity-dataset-dangling` |
| `manifest_projection.entity.duplicate` | `breg.manifest-projection.entity-duplicate` |
| `manifest_projection.entity.not_visible` | `breg.manifest-projection.entity-not-visible` |
| `manifest_projection.entity.primary_dataset_required` | `breg.manifest-projection.entity-primary-dataset-required` |
| `manifest_projection.field.duplicate` | `breg.manifest-projection.field-duplicate` |
| `manifest_projection.field.metadata_kind` | `breg.manifest-projection.field-metadata-kind` |
| `manifest_projection.field.not_representable` | `breg.manifest-projection.field-not-representable` |
| `manifest_projection.field.not_visible` | `breg.manifest-projection.field-not-visible` |
| `manifest_projection.identifier.invalid` | `breg.manifest-projection.identifier-invalid` |
| `manifest_projection.invalid` | `breg.manifest-projection.invalid` |
| `manifest_projection.missing` | `breg.manifest-projection.missing` |
| `manifest_projection.text.empty` | `breg.manifest-projection.text-empty` |
| `manifest_projection.vocabulary.concept_invalid` | `breg.manifest-projection.vocabulary-concept-invalid` |
| `manifest_projection.vocabulary.duplicate` | `breg.manifest-projection.vocabulary-duplicate` |
| `manifest_projection.vocabulary.not_visible` | `breg.manifest-projection.vocabulary-not-visible` |
| `metadata_inventory.inconsistent` | `breg.metadata-inventory.inconsistent` |
| `module.asset.duplicate` | `breg.module.asset-duplicate` |
| `module.asset.invalid` | `breg.module.asset-invalid` |
| `module.dependency.cycle` | `breg.module.dependency-cycle` |
| `module.dependency.duplicate` | `breg.module.dependency-duplicate` |
| `module.dependency.unknown` | `breg.module.dependency-unknown` |
| `module.id.duplicate` | `breg.module.id-duplicate` |
| `module.lock.digest_invalid` | `breg.module.lock-digest-invalid` |
| `module.lock.digest_mismatch` | `breg.module.lock-digest-mismatch` |
| `module.lock.digest_missing` | `breg.module.lock-digest-missing` |
| `module.lock.digest_required` | `breg.module.lock-digest-required` |
| `module.lock.duplicate` | `breg.module.lock-duplicate` |
| `module.lock.missing` | `breg.module.lock-missing` |
| `module.lock.source_missing` | `breg.module.lock-source-missing` |
| `module.lock.stale` | `breg.module.lock-stale` |
| `module.lock.version_mismatch` | `breg.module.lock-version-mismatch` |
| `module.source.missing` | `breg.module.source-missing` |
| `module.source.required` | `breg.module.source-required` |
| `package.identity.missing` | `breg.package.identity-missing` |
| `package.identity.required` | `breg.package.identity-required` |
| `package.source_revision.empty` | `breg.package.source-revision-empty` |
| `physical_name.collision` | `breg.physical-name.collision` |
| `project.api_version.unsupported` | `breg.project.api-version-unsupported` |
| `project.default_language.invalid` | `breg.project.default-language-invalid` |
| `project.kind.unsupported` | `breg.project.kind-unsupported` |
| `project.version.empty` | `breg.project.version-empty` |
| `query.filter.field_type_unsupported` | `breg.query.filter-field-type-unsupported` |
| `query.sort.field_type_unsupported` | `breg.query.sort-field-type-unsupported` |
| `query.temporal.field_not_readable` | `breg.query.temporal-field-not-readable` |
| `query.temporal.public_processing_non_public` | `breg.query.temporal-public-processing-non-public` |
| `read_path.cycle` | `breg.read-path.cycle` |
| `read_path.id.duplicate` | `breg.read-path.id-duplicate` |
| `read_path.references.ambiguous` | `breg.read-path.references-ambiguous` |
| `read_path.route.duplicate` | `breg.read-path.route-duplicate` |
| `read_path.target.self` | `breg.read-path.target-self` |
| `read_path.target.unknown` | `breg.read-path.target-unknown` |
| `read_path.through.unknown` | `breg.read-path.through-unknown` |
| `recipients.client_unique` | `breg.recipients.client-unique` |
| `recipients.group_members` | `breg.recipients.group-members` |
| `recipients.id` | `breg.recipients.id` |
| `recipients.set_bound` | `breg.recipients.set-bound` |
| `registry.canonical_base_iri.required` | `breg.registry.canonical-base-iri-required` |
| `runtime_config.environment_identity_conflict` | `breg.runtime.environment-identity-conflict` |
| `runtime_config.invalid_attachment_storage` | `breg.runtime.invalid-attachment-storage` |
| `runtime_config.invalid_attachment_verification` | `breg.runtime.invalid-attachment-verification` |
| `runtime_config.invalid_audit` | `breg.runtime.invalid-audit` |
| `runtime_config.invalid_binding` | `breg.runtime.invalid-binding` |
| `runtime_config.invalid_bounds` | `breg.runtime.invalid-bounds` |
| `runtime_config.invalid_cursor` | `breg.runtime.invalid-cursor` |
| `runtime_config.invalid_database` | `breg.runtime.invalid-database` |
| `runtime_config.invalid_event_destination` | `breg.runtime.invalid-event-destination` |
| `runtime_config.invalid_field_encryption` | `breg.runtime.invalid-field-encryption` |
| `runtime_config.invalid_instance_id` | `breg.runtime.invalid-instance-id` |
| `runtime_config.invalid_listener` | `breg.runtime.invalid-listener` |
| `runtime_config.invalid_metrics_listener` | `breg.runtime.invalid-metrics-listener` |
| `runtime_config.invalid_oidc` | `breg.runtime.invalid-oidc` |
| `runtime_config.invalid_oidc_leeway` | `breg.runtime.invalid-oidc-leeway` |
| `runtime_config.invalid_package` | `breg.runtime.invalid-package` |
| `runtime_config.invalid_secret_provider` | `breg.runtime.invalid-secret-provider` |
| `runtime_config.invalid_wasm_execution` | `breg.runtime.invalid-wasm-execution` |
| `runtime_config.package_root_unavailable` | `breg.runtime.package-root-unavailable` |
| `runtime_config.secret` | `breg.runtime.secret` |
| `runtime_config.secret_provider_root_unavailable` | `breg.runtime.secret-provider-root-unavailable` |
| `runtime_config.unsafe_package_root` | `breg.runtime.unsafe-package-root` |
| `runtime_config.unsafe_secret_provider_root` | `breg.runtime.unsafe-secret-provider-root` |
| `selector_profile.encrypted_lookup_required` | `breg.selector-profile.encrypted-lookup-required` |
| `selector_profile.field_type_unsupported` | `breg.selector-profile.field-type-unsupported` |
| `selector_profile.fields.duplicate` | `breg.selector-profile.fields-duplicate` |
| `selector_profile.fields.invalid` | `breg.selector-profile.fields-invalid` |
| `selector_profile.fields.unknown` | `breg.selector-profile.fields-unknown` |
| `selector_profile.id.duplicate` | `breg.selector-profile.id-duplicate` |
| `source.evidence_contract.missing` | `breg.source.evidence-contract-missing` |
| `source.evidence_contract.path_unsafe` | `breg.source.evidence-contract-path-unsafe` |
| `source.file.bounds` | `breg.source.file-bounds` |
| `source.file.invalid` | `breg.source.file-invalid` |
| `source.file.unreadable` | `breg.source.file-unreadable` |
| `source.fixture_journeys.missing` | `breg.source.fixture-journeys-missing` |
| `source.invalid` | `breg.source.invalid` |
| `source.json.invalid` | `breg.source.json-invalid` |
| `source.module.id_mismatch` | `breg.source.module-id-mismatch` |
| `source.module.missing` | `breg.source.module-missing` |
| `source.module_asset.bounds` | `breg.source.module-asset-bounds` |
| `source.module_asset.duplicate` | `breg.source.module-asset-duplicate` |
| `source.module_asset.missing` | `breg.source.module-asset-missing` |
| `source.module_asset.path_unsafe` | `breg.source.module-asset-path-unsafe` |
| `source.modules.invalid` | `breg.source.modules-invalid` |
| `source.modules.unlocked` | `breg.source.modules-unlocked` |
| `source.modules.unreadable` | `breg.source.modules-unreadable` |
| `source.planner_asset.bounds` | `breg.source.planner-asset-bounds` |
| `source.planner_asset.missing` | `breg.source.planner-asset-missing` |
| `source.planner_asset.path_unsafe` | `breg.source.planner-asset-path-unsafe` |
| `source.project.invalid` | `breg.source.project-invalid` |
| `source.project.missing` | `breg.source.project-missing` |
| `source.project.path_unsafe` | `breg.source.project-path-unsafe` |
| `source.shape.invalid` | `breg.source.shape-invalid` |
| `source.wasm_module.bounds` | `breg.source.wasm-module-bounds` |
| `source.wasm_module.missing` | `breg.source.wasm-module-missing` |
| `source.wasm_module.path_unsafe` | `breg.source.wasm-module-path-unsafe` |
| `statistical_dataset.cells.exceeded` | `breg.statistical-dataset.cells-exceeded` |
| `statistical_dataset.count_grant.consent` | `breg.statistical-dataset.count-grant-consent` |
| `statistical_dataset.count_grant.count_required` | `breg.statistical-dataset.count-grant-count-required` |
| `statistical_dataset.count_grant.field_not_filterable` | `breg.statistical-dataset.count-grant-field-not-filterable` |
| `statistical_dataset.count_grant.list_required` | `breg.statistical-dataset.count-grant-list-required` |
| `statistical_dataset.count_grant.missing` | `breg.statistical-dataset.count-grant-missing` |
| `statistical_dataset.dimension.code_reserved` | `breg.statistical-dataset.dimension-code-reserved` |
| `statistical_dataset.dimension.duplicate` | `breg.statistical-dataset.dimension-duplicate` |
| `statistical_dataset.dimension.reserved` | `breg.statistical-dataset.dimension-reserved` |
| `statistical_dataset.dimension.type` | `breg.statistical-dataset.dimension-type` |
| `statistical_dataset.disclosure.minimum_count` | `breg.statistical-dataset.disclosure-minimum-count` |
| `statistical_dataset.disclosure.minimum_count_exceeded` | `breg.statistical-dataset.disclosure-minimum-count-exceeded` |
| `statistical_dataset.disclosure.missing` | `breg.statistical-dataset.disclosure-missing` |
| `statistical_dataset.disclosure.rounding_base` | `breg.statistical-dataset.disclosure-rounding-base` |
| `statistical_dataset.disclosure.rounding_base_exceeded` | `breg.statistical-dataset.disclosure-rounding-base-exceeded` |
| `statistical_dataset.document.exceeded` | `breg.statistical-dataset.document-exceeded` |
| `statistical_dataset.field.encrypted` | `breg.statistical-dataset.field-encrypted` |
| `statistical_dataset.field.unknown` | `breg.statistical-dataset.field-unknown` |
| `statistical_dataset.grants.empty` | `breg.statistical-dataset.grants-empty` |
| `statistical_dataset.id.duplicate` | `breg.statistical-dataset.id-duplicate` |
| `statistical_dataset.period.field_type` | `breg.statistical-dataset.period-field-type` |
| `statistical_dataset.period.first_period` | `breg.statistical-dataset.period-first-period` |
| `statistical_dataset.period.temporal_missing` | `breg.statistical-dataset.period-temporal-missing` |
| `statistical_dataset.population.field_unknown` | `breg.statistical-dataset.population-field-unknown` |
| `statistical_dataset.population.invalid` | `breg.statistical-dataset.population-invalid` |
| `statistical_dataset.profile.anonymous` | `breg.statistical-dataset.profile-anonymous` |
| `statistical_dataset.profile.duplicate` | `breg.statistical-dataset.profile-duplicate` |
| `statistical_dataset.profile.unknown` | `breg.statistical-dataset.profile-unknown` |
| `statistical_dataset.publisher.caller_dependent` | `breg.statistical-dataset.publisher-caller-dependent` |
| `statistical_dataset.publisher.dependency_grant_missing` | `breg.statistical-dataset.publisher-dependency-grant-missing` |
| `statistical_dataset.publisher.dependency_read_required` | `breg.statistical-dataset.publisher-dependency-read-required` |
| `statistical_dataset.publisher.entity_row_boundary` | `breg.statistical-dataset.publisher-entity-row-boundary` |
| `statistical_dataset.releases.readers_empty` | `breg.statistical-dataset.releases-readers-empty` |
| `statistical_dataset.unit.unknown` | `breg.statistical-dataset.unit-unknown` |
| `temporal.field.unknown` | `breg.temporal.field-unknown` |
| `temporal.role.conflict` | `breg.temporal.role-conflict` |
| `temporal.scope_fields.deprecated_mismatch` | `breg.temporal.scope-fields-deprecated-mismatch` |
| `vocabulary.id.duplicate` | `breg.vocabulary.id-duplicate` |
| `vocabulary.values.invalid` | `breg.vocabulary.values-invalid` |

## BReg tool and output formats

This section covers the files `bregctl` reads and writes beside a registry
project: the fixture journeys, the schema-test credentials and receipt, the
development client and state files, the example scenarios, the data import
and export checkpoints, the migration descriptor and rehearsal receipt, the
backup binding, the model selection, the Evidence source export, and the
`--format json` reports and `explain` outputs. None of them is a promised
format; each now carries a Registry Stack header, is read by the shared
reader, and is refused with the reader's codes and positions.

### BREAKING: fixture journeys version 1 (`tests/journeys.yaml`)

`bregctl test`, `bregctl package`, `bregctl dev`, and every fixture runner
read the journeys file through the shared reader. Migrate a file with these
edits:

| Old | New |
|---|---|
| `apiVersion: registry.registrystack.org/breg-journeys/v1` | `apiVersion: id.registrystack.org/formats/breg/journeys/v1` and, on the next line, `kind: BRegJourneys` |
| `operation: <form>` in a request or a batch item | `type: <form>`, in kebab case: `read-path`, `target-conditions`, `submit-request`, `revise-request`, `cancel-request`, `apply-request` (the one-word forms `import`, `create`, `get`, `list`, `query`, `lookup`, `patch`, `batch`, `invoke` are unchanged) |
| `recordRef`, `etagRef`, `proposalVersionRef`, `effectDigestRef` in a request | `recordCapture`, `etagCapture`, `proposalVersionCapture`, `effectDigestCapture` |
| `conditionRef` in a request precondition | `conditionCapture` |
| `{recordRef: <capture>}` inside request data | `{recordCapture: <capture>}` |
| a YAML anchor (`&claims`) and its aliases (`*claims`) | the shared mapping written out in full at every step that used the alias |

A file with the old header and no `kind` is refused with
`config.missing-envelope`, whose fix names the new header. Once the header
is current, every old key is refused with `config.removed-key` at its
position, naming its replacement, and the old header written beside `kind:
BRegJourneys` is refused with `config.retired-api-version`. Unknown keys
were already refused, first one only; every one is now reported
(`config.unknown-key`), with the closest accepted key. The reader also
refuses what the previous parser let through: `null` for an optional member
(`config.null-value`; leave the member out), an ambiguous number such as
`status: 0200` (`yaml.ambiguous-number`; write `200`), and a repeated entry
in `scopes` or a request's `select`, which was silently collapsed
(`config.duplicate-item`; delete the repeat).

`bregctl test` and `bregctl package` print a refused journeys file as one
sentence (`bregctl test refused the fixture journeys.`) followed by the
reader's diagnostics, each with its code, file, line, column, JSON Pointer
path, and fix; with `--format json` the report's `diagnostics` carry the
reader's shape (`source: {file, line, column}`) unchanged. A tool that
matched `test.journeys.refused` or a `path` of `tests/journeys.yaml` in that
output must match the reader codes and read `source.file` instead.

### BREAKING: the record marker in example inputs is `recordCapture`

The `bregctl dev` example runner and the fixture runner share one logical
record marker. An example input (`examples/inputs/*.json`) that names a
record an earlier step captured writes `{"recordCapture": "<capture>"}`
where it wrote `{"recordRef": "<capture>"}`. The old marker is refused with
a message naming the new one. Migrate each input file by renaming the key;
the capture name is unchanged.

### BREAKING: schema-test receipt version 2 header

`bregctl test` writes `schema-test-receipt.json` with `"apiVersion":
"id.registrystack.org/formats/breg/schema-test-receipt/v2"` and `"kind":
"BRegSchemaTestReceipt"`; the members and their canonical layout are
unchanged. `bregctl package` reads the receipt through the shared reader, so
a receipt written by an earlier `bregctl` is refused: its old kind,
`SchemaTestReceipt`, is refused with `config.wrong-kind`, and the old header
beside the current kind with `config.retired-api-version`. Run `bregctl test`
again with this `bregctl` to write a current receipt; never edit the file by
hand.

The refusal is printed as one sentence (`bregctl package refused the
schema-test receipt.`) followed by the reader's diagnostics, each naming the
receipt file in `source.file`. Two product codes replace the single
`package.test_receipt.invalid` diagnostic for a malformed receipt:
`breg.receipt.not-canonical` (the bytes are not the canonical JSON `bregctl
test` writes) and `breg.receipt.too-large` (the receipt is over 64 KiB). An
unknown member is refused with `config.unknown-key` at its position.

### BREAKING: schema-test credentials version 1 header

`bregctl test --credentials` reads the credentials file through the shared
reader. Migrate a file by replacing its first two lines:

| Old | New |
|---|---|
| `apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1` | `apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1` |
| `kind: SchemaTestCredentials` | `kind: BRegSchemaTestCredentials` |

The bindings are unchanged. A file with the old kind is refused with
`config.wrong-kind`, and the old header beside the current kind with
`config.retired-api-version`, naming the current header.

Every refusal of the file's content is now printed as one sentence
(`bregctl test refused the schema-test credentials.`) followed by the
reader's diagnostics, each naming the credentials file as given in
`source.file` with its line and column. Every unknown key is reported, not
only the first. The single `test.credentials.refused` diagnostic remains for
a file that cannot be read; the content refusals carry these codes instead:

| Condition | Old | New |
|---|---|---|
| unknown, missing, or malformed member, or a `tokenRef` that is not `secret:env/NAME` or `secret:file/name` | `test.credentials.refused` | the reader's `config.*` and `yaml.*` codes |
| a binding names a journey the packaged suite does not declare | `test.credentials.refused` | `breg.credentials.unknown-journey` |
| a step is bound twice | `test.credentials.refused` | `breg.credentials.duplicate-binding` |
| a referenced secret cannot be resolved, or is not UTF-8 | `test.credentials.refused` | `breg.credentials.unresolved-secret` |
| a step is left unbound, or a binding does not suit its step | `test.credentials.refused` | `breg.credentials.incomplete-bindings` |

The diagnostics name the credentials file and the journey and step ids;
they never repeat a token, a secret reference, or a secret name.

### BREAKING: data checkpoint and import state headers

`bregctl data import` and `bregctl data export` read their checkpoints, and
`bregctl data import` its `.state` sidecar, through the shared reader. Each
file now carries a header of its own:

| File | Old header | New header |
|---|---|---|
| import checkpoint | `registry.registrystack.org/v1alpha1`, `RegistryDataImportCheckpoint` | `id.registrystack.org/formats/breg/data-import-checkpoint/v1alpha1`, `BRegDataImportCheckpoint` |
| export checkpoint | `registry.registrystack.org/v1alpha1`, `RegistryDataExportCheckpoint` | `id.registrystack.org/formats/breg/data-export-checkpoint/v1alpha1`, `BRegDataExportCheckpoint` |
| import `.state` sidecar | `registry.registrystack.org/bregctl-data/v2`, `BRegctlDataImportState` | `id.registrystack.org/formats/breg/data-import-state/v2`, `BRegDataImportState` |

The members, the bindings each file holds, and the resume rules are
unchanged. A file an earlier `bregctl` wrote is refused before any network
use: its old kind with `config.wrong-kind`, and the old header beside the
current kind with `config.retired-api-version`. Finish an import or export
that is in flight with the `bregctl` that started it before upgrading. If
that is no longer possible, an export restarts: remove the output and its
checkpoint and export again. An import restarts under a fresh checkpoint
path with only the lines its run did not commit (the run's `committedItems`
says how many did); never edit the files to carry them across.

A refused file is printed as one sentence (`bregctl data import refused the
data import checkpoint.`, `bregctl data import refused the data import
state.`, or `bregctl data export refused the data export checkpoint.`)
followed by the reader's diagnostics, each naming the file as given in
`source.file` with its line, column, and member. Every unknown member is
reported, with `config.unknown-key`. `data.import.checkpoint.refused` and
`data.export.checkpoint.refused` remain for a file that cannot be read and
for a checkpoint whose bindings no longer match the run, the package, or
the output.

The export checkpoint leaves `nextCursor` out when there is no cursor; it
wrote `"nextCursor": null`, which the shared reader refuses
(`config.null-value`).

### BREAKING: model selection header

`bregctl init --from publicschema` reads a selection (`--selection`, a
shipped `--starter`, and the echo it writes to `model/selection.yaml`)
through the shared reader. Migrate a selection by replacing its first two
lines:

| Old | New |
|---|---|
| `apiVersion: registry.registrystack.org/breg-model-selection/v1alpha1` | `apiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1` |
| `kind: ModelSelection` | `kind: BRegModelSelection` |

The members are unchanged. A selection with the old kind is refused with
`config.wrong-kind`, and the old header beside the current kind with
`config.retired-api-version`, naming the current header. A refused
selection is printed as one sentence (`bregctl init refused the model
selection.`) followed by the reader's diagnostics, each naming the file as
given in `source.file` with its line, column, and member; nothing is
written. Every unknown key is reported, not only the first.

| Condition | Old | New |
|---|---|---|
| the document does not parse, or has an unknown, missing, or malformed member | `init.selection.invalid` | the reader's `config.*` and `yaml.*` codes |
| another `apiVersion` or `kind` | `init.selection.kind` | `config.wrong-kind`, `config.retired-api-version`, or `config.unsupported-api-version` |
| an empty document | `init.selection.size` | `config.missing-envelope` |

`init.selection.size` remains for a `--selection` file over 256 KiB, and
`init.selection.unreadable` for one that cannot be read.
