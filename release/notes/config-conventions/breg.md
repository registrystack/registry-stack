# Configuration conventions: Base Registry Engine

## BReg authored formats

This section covers the formats an adopter and an operator write for the
Base Registry Engine: `registry.yaml`, `module.yaml`, `runtime.yaml`, and the
package a `bregctl package` run seals around them.

### BREAKING: the shared reader reads `registry.yaml` and `module.yaml`
<!-- upgrade: breg-project-reader-refusals -->

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
<!-- upgrade: breg-project-reader-refusals -->

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
<!-- upgrade: already-wrong -->

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
<!-- upgrade: breg-delete-repeated-items -->

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
<!-- upgrade: breg-runtime-refused-forms -->

`breg` and every `bregctl` command that takes `--runtime-config` decode
`runtime.yaml` through the shared runtime loader rather than a second
product-side pass. Every problem the run finds in a pass is reported (the passes are described in
the "Read a diagnostic" section of the Configuration files reference; fix them and run again), each
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

### The runtime `database` block takes a trusted root and a test-only plaintext switch

`database` in `runtime.yaml` embeds the shared database block, so it also
accepts two optional members. This is additive; no existing file changes
meaning.

- `trustedRootCertificateRef` is a secret reference to PEM root certificates.
  When it is set, the runtime and the migration connection trust every
  certificate in that file in place of the platform roots; hostname and
  certificate validation stay on. A secret that holds no PEM certificate is
  refused when the connection is configured, as `breg.runtime.invalid-database`.
- `testOnlyPlaintext` is refused outside the project's test builds as
  `breg.runtime.plaintext-database` at `/database/testOnlyPlaintext`. Remove
  it; a deployment reaches PostgreSQL over TLS.

A malformed secret reference in `database.runtimeUrlRef`,
`database.migrationUrlRef`, or `database.trustedRootCertificateRef` is now
refused as `breg.runtime.invalid-database` at `/database`, where the reader
reported `config.invalid-value` at the member. The fix is the same: write the
member as `secret:file/<name>` or `secret:env/<NAME>`.

### BREAKING: integer bounds in `runtime.yaml` are refused when read
<!-- upgrade: already-wrong -->

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
the accepted spellings are unchanged, and every problem the decoding pass finds inside the chosen form
is now reported at its own member, line, and column rather than at the block.

### BREAKING: `bregctl check` reports in the shared diagnostic shape
<!-- upgrade: no-file -->

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

Without `--environment`, the check reads the rest of the file with a
placeholder in place of each expression. A member that takes a URL, a URI, or
an absolute path takes a placeholder of that form, so an expression there does
not hide a refusal elsewhere in the file. Where a rule needs the value an
expression stands for, the check cannot decide it: it stops there and reports
the warning `platform.runtime-config.check-incomplete` at that block instead
of passing, and the rules after it were not checked. The warning exits 0, or 1
under `--deny-warnings`; run the check again with `--environment` to have
every rule decided.

### BREAKING: the package format is named `id.registrystack.org/formats/breg/package/v2`
<!-- upgrade: breg-rebuild-package -->

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
<!-- upgrade: breg-statistical-period -->

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
`bregctl test` rebuilds a deployed registry from its packaged sources, and
reads the period of a deployed package with the tag the earlier release
wrote, so a deployed package whose project still writes `kind` is rehearsed
as the baseline it is.

### BREAKING: configuration diagnostic codes are named `breg.<area>.<condition>`
<!-- upgrade: no-file -->

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
| `access.requirements.empty` | `breg.access.requirements-empty` |
| `access.requirements.empty_value` | `breg.access.requirements-empty-value` |
| `access.requirements.purpose_widened` | `breg.access.requirements-purpose-widened` |
| `access.requirements.read_path.row_boundary_unsupported` | `breg.access.requirements-read-path-row-boundary-unsupported` |
| `access.requirements.row_boundary.invalid` | `breg.access.requirements-row-boundary-invalid` |
| `access.requirements.row_boundary_missing` | `breg.access.requirements-row-boundary-missing` |
| `access.requirements.scope_missing` | `breg.access.requirements-scope-missing` |
| `access.target.unrestricted_rows` | `breg.access.target-unrestricted-rows` |
| `access_log.exemption.delay_invalid` | `breg.access-log.exemption-delay-invalid` |
| `access_log.exemption.profile_invalid` | `breg.access-log.exemption-profile-invalid` |
| `access_log.exemption.reason_invalid` | `breg.access-log.exemption-reason-invalid` |
| `access_log.exemptions.too_many` | `breg.access-log.exemptions-too-many` |
| `access_log.retention_days.invalid` | `breg.access-log.retention-days-invalid` |
| `access_log.subject_field.invalid` | `breg.access-log.subject-field-invalid` |
| `access_log.trusted_intermediaries.too_many` | `breg.access-log.trusted-intermediaries-too-many` |
| `access_log.trusted_intermediary.invalid` | `breg.access-log.trusted-intermediary-invalid` |
| `access_profile.actor_client.binding_required` | `breg.access-profile.actor-client-binding-required` |
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
| `access_profile.principal_claim.required` | `breg.access-profile.principal-claim-required` |
| `access_profile.processing.encrypted` | `breg.access-profile.processing-encrypted` |
| `access_profile.processing.wider_than_read` | `breg.access-profile.processing-wider-than-read` |
| `access_profile.project_entity_local.forbidden` | `breg.access-profile.project-entity-local-forbidden` |
| `access_profile.provenance_fields.invalid` | `breg.access-profile.provenance-fields-invalid` |
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
| `statistical_dataset.profile.duplicate` | `breg.statistical-dataset.profile-duplicate` |
| `statistical_dataset.publisher.caller_dependent` | `breg.statistical-dataset.publisher-caller-dependent` |
| `statistical_dataset.publisher.dependency_grant_missing` | `breg.statistical-dataset.publisher-dependency-grant-missing` |
| `statistical_dataset.publisher.dependency_read_required` | `breg.statistical-dataset.publisher-dependency-read-required` |
| `statistical_dataset.publisher.entity_row_boundary` | `breg.statistical-dataset.publisher-entity-row-boundary` |
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
backup binding, the model selection, and the Evidence source export, which
are unpromised formats, and the promised `explain` outputs. Each unpromised
file now carries a Registry Stack header, is read by the shared reader, and
is refused with the reader's codes and positions.

### BREAKING: fixture journeys version 1 (`tests/journeys.yaml`)
<!-- upgrade: breg-journeys -->

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
| a YAML anchor (`&claims`) and its aliases (`*claims`) | the shared mapping written out in full at every step that used the alias; the `breg-journeys` step does this |

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
<!-- upgrade: breg-example-inputs -->

The `bregctl dev` example runner and the fixture runner share one logical
record marker. An example input (`examples/inputs/*.json`) that names a
record an earlier step captured writes `{"recordCapture": "<capture>"}`
where it wrote `{"recordRef": "<capture>"}`. The old marker is refused with
a message naming the new one. Migrate each input file by renaming the key;
the capture name is unchanged.

### BREAKING: schema-test receipt version 2 header
<!-- upgrade: breg-schema-test-receipt -->

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
<!-- upgrade: breg-schema-test-credentials -->

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
<!-- upgrade: breg-data-checkpoints -->

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
<!-- upgrade: breg-model-selection -->

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

### BREAKING: development clients header and secret references (`dev-clients.yaml`)
<!-- upgrade: breg-dev-clients -->

`bregctl dev start` reads `dev-clients.yaml`, or the `--clients-file` it
names, through the shared reader. Every member that named a secret file now
holds a secret reference, and the file declares the providers that resolve
them. Migrate a file with these edits:

| Old | New |
|---|---|
| `version: 1` | `apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1` and, on the next line, `kind: BRegDevClients` |
| `clients[].assertionKeyInputFile` | `clients[].assertionKeyRef` |
| `eventDestinations.<id>.hmacKeyFile` | `eventDestinations.<id>.hmacSha256KeyRef` |
| `evidenceProviders.<id>.tokenFile` | `evidenceProviders.<id>.tokenRef` |
| `evidenceProviders.<id>.trustedJwksFile` | `evidenceProviders.<id>.trustedJwksRef` |
| `evidenceProviders.<id>.caBundleFile` | `evidenceProviders.<id>.caBundleRef` |
| `evidenceProviders.<id>.privateKeyJwt.privateKeyFile` | `evidenceProviders.<id>.privateKeyJwt.privateKeyRef` |
| `reviewAuthorities.<id>.completionTokenFile` | `reviewAuthorities.<id>.completionTokenRef` |
| `issuer.interactiveApplications[].clientSecretFile` | `issuer.interactiveApplications[].clientSecretRef` |
| `issuer.syntheticUsers[].passwordFile` | `issuer.syntheticUsers[].passwordRef` |
| `clients[].clientIdFile` and `clients[].assertionKeyFile` | removed; after the session starts, run `bregctl dev export-client <project> --client <id> --client-id-file <file> --assertion-key-file <file>` |
| a member set to `null`, such as `caBundleFile: null` or `audience: null` | the member left out |

Each `*Ref` member holds `secret:file/<name>` or `secret:env/<NAME>`. Move
each file a `*File` member named into one owner-only directory and declare it
as the file provider's absolute root, or declare the environment provider and
name a variable of the `bregctl dev start` process:

```yaml
secretProviders:
  file: {root: /absolute/owner-only/dev-secrets}
  environment: {}
```

A referenced file must be a regular file you own, with mode 0400 or 0600 and
a single link, directly below the root; a referenced value must be non-empty,
contain no NUL byte, and fit its member's limit. `bregctl dev` no longer writes
a credential outside `.breg/dev`: `export-client` is the one way a client pair
leaves the session.

A file with `version: 1` and no header is refused with
`config.missing-envelope`, whose fix names the header. Once the header is
current, every old member is refused with `config.removed-key` at its
position, naming its replacement, and every unknown member with
`config.unknown-key`, not only the first. The refusal is printed as one
sentence (`bregctl dev refused the development clients.`) followed by the
reader's diagnostics; with `--format json` the report's `diagnostics` carry
the reader's shape (`source: {file, line, column}`) unchanged. A reference
that cannot be resolved is refused by member name with its fix; the refusal
never repeats the value, the file name, or the variable name. The reader also
refuses a `null` member (`config.null-value`) and a document over 1 MiB.

A session an earlier `bregctl` started retained its clients in the old shape,
and this `bregctl` refuses every command that reads them (`retained clients
are invalid`), naming this fix. Before upgrading, run `bregctl dev stop
--remove <project>` with the earlier `bregctl`, then remove
`<project>/.breg/dev`, migrate `dev-clients.yaml`, and start again. The next start creates an empty database and fresh client keys;
export a client again where another tool holds its pair.

### BREAKING: example scenarios header (`examples/scenarios.json`)
<!-- upgrade: breg-example-scenarios -->

`bregctl examples list` and `bregctl examples run` read the catalogue
through the shared reader. Migrate a catalogue by replacing its version
member with the header:

| Old | New |
|---|---|
| `"version": 1` | `"apiVersion": "id.registrystack.org/formats/breg/example-scenarios/v1alpha1"` and `"kind": "BRegExampleScenarios"` |

Scenario and step identifiers, and the `entity`, `client`, `accessProfile`,
`input`, `capture`, `record`, `action`, and `result` names, are local
identifiers: they start with a lowercase letter and use lowercase letters,
digits, hyphens, and underscores, up to 64 characters. A name that starts
with a digit, which the previous parser accepted for everything but
`action` and `result`, is refused; rename it, and the input keys and
captures that use it.

A catalogue with `version` and no header is refused with
`config.missing-envelope`, whose fix names the header, and `version` beside
the header with `config.removed-key`. The refusal is printed as one sentence
(`bregctl examples refused the example scenarios.`) followed by every
diagnostic with its position; with `--format json` the report's
`diagnostics` carry the reader's shape unchanged. Retained example attempts
bind the catalogue's digest, so an attempt started before the migration is
not resumed; start a new one with `--new-attempt`.

| Condition | Old | New |
|---|---|---|
| the document does not parse, or has an unknown, missing, malformed, or repeated member | `examples.failed` | the reader's `config.*` and `yaml.*` codes, including `config.duplicate-id` for a repeated scenario or step id |
| fewer than 1 or more than 32 scenarios | `examples.failed` | `breg.examples.scenario-count` |
| fewer than 1 or more than 100 steps in a scenario | `examples.failed` | `breg.examples.step-count` |
| an empty description, or one over 1024 bytes | `examples.failed` | `breg.examples.description-length` |
| an input outside `examples/` | `examples.failed` | `breg.examples.input-path` |
| a step missing a member its operation needs, or carrying one it does not | `examples.failed` | `breg.examples.step-members` |
| a population scenario that submits or applies | `examples.failed` | `breg.examples.population-operation` |
| `first-record` or `reviewed-change` without its fixed steps | `examples.failed` | `breg.examples.fixed-scenario` |

`examples.failed` remains for every refusal that is not about the
catalogue.

### BREAKING: development session state header (`.breg/dev/state.json`)
<!-- upgrade: breg-dev-session-reset -->

`bregctl dev` writes its session state with
`apiVersion: id.registrystack.org/formats/breg/dev-state/v1alpha1` and
`kind: BRegDevState` in place of `version: 2`, leaves out a member that has
no value instead of writing `null`, and reads the file back through the
shared reader. The list of completed seeds is refused when it names a seed
twice. Only `bregctl` writes this file, so there is nothing to edit: state an
earlier `bregctl` wrote is refused unchanged (`retained dev state is
invalid`), and the refusal names the fix. Before upgrading, run `bregctl dev
stop --remove <project>` with the earlier `bregctl`, then remove
`<project>/.breg/dev` and start again, the same step the development clients
migration takes. A script that reads `state.json` finds `containerId`,
`webhookPort`, and the other optional members absent, not `null`, until they
have a value.

### BREAKING: source preparation record and journal headers (`.breg/dev/source-prepared-<client>.json`, `.breg/dev/source-transition.json`)
<!-- upgrade: breg-dev-session-reset -->

`bregctl dev prepare-source` writes the record that repeats an identical
request with `apiVersion:
id.registrystack.org/formats/breg/dev-prepared-source/v1alpha1` and `kind:
BRegDevPreparedSource`, and the journal that recovers an interrupted apply
with `apiVersion:
id.registrystack.org/formats/breg/dev-source-transition/v1alpha1` and `kind:
BRegDevSourceTransition`. Both are read back through the shared reader. The
record keeps the printed report as its exact JSON text, so a repeated request
prints the same report, and the journal keeps the authoring files it restores
as their text rather than as arrays of bytes. A journal larger than the shared
reader's 1 MiB document bound is refused before anything is written, naming
the fix (`source transition exceeds the 1 MiB retained journal bound`); the
bound was 4 MiB. Only `bregctl` writes these files, so there is nothing to
edit: a record or journal an earlier `bregctl` wrote is refused unchanged
(`retained source preparation is invalid`), and the refusal names the fix.
Finish or recover any source preparation with the earlier `bregctl` before
upgrading; otherwise run `bregctl dev stop --remove <project>`, remove
`<project>/.breg/dev`, and start again.

### BREAKING: reviewed migration documents and the backup binding (`descriptor.json`, `rehearsal.json`, the `--backup` binding)
<!-- upgrade: breg-reviewed-migrations -->

`bregctl test`, `bregctl package`, `bregctl plan`, `bregctl apply`, and the
runtime's package load read a reviewed migration's descriptor and rehearsal
receipt, and `plan` and `apply` read each backup binding, through the shared
reader. Each document starts with its header and uses the convention's
spellings; it no longer has to be canonical JSON bytes, so reformat it
freely. The receipt's `planDigest` is the SHA-256 of the descriptor's
RFC 8785 canonical JSON, header included, so a reformatted descriptor keeps
its rehearsal while any member change still breaks it. SQL, assertion, and
fixture files stay bound by their exact bytes.

Migrate the descriptor (`modules/<module>/migrations/<id>/descriptor.json`):

| Old | New |
|---|---|
| no header | `"apiVersion": "id.registrystack.org/formats/breg/migration-descriptor/v1alpha1"` and `"kind": "BRegMigrationDescriptor"` |
| `lockTimeoutMs`, `statementTimeoutMs` | `lockTimeoutMilliseconds`, `statementTimeoutMilliseconds` |
| `steps[].kind` with `transactional_sql`, `chunked_backfill`, or `field_encryption_backfill` | `steps[].type` with `transactional-sql`, `chunked-backfill`, or `field-encryption-backfill` |
| `steps[].sql_path` | `steps[].sqlPath` |
| `steps[].affected_rows` with `min` and `max` | `steps[].affectedRows` with `minimum` and `maximum` |
| `steps[].entity_id` | `steps[].entity` |
| `steps[].cursor: record_id_uuid_array` | `steps[].cursor: record-id-uuid-array` |
| `steps[].chunk_size`, `steps[].max_total_rows` | `steps[].chunkSize`, `steps[].maximumTotalRows` |
| `steps[].lock_timeout_ms`, `steps[].statement_timeout_ms` | `steps[].lockTimeoutMilliseconds`, `steps[].statementTimeoutMilliseconds` |
| `steps[].exact_affected_rows` | `steps[].exactAffectedRows` |
| `steps[].objects[].entityId`, `steps[].objects[].memberId` | `steps[].objects[].entity`, `steps[].objects[].member` |

`id`, `changeClass`, `covers` (with each change's `code` and `target` as
`diff --format json` reports them), `recovery`, `history`, the assertion
lists, and the two paths keep their spelling.

Migrate the rehearsal receipt (`rehearsal.json`) and recompute its
`planDigest` over the migrated descriptor, since the header and the renamed
members change it (`jq -jcS . descriptor.json | shasum -a 256` computes it
for a descriptor of ASCII text and integers):

| Old | New |
|---|---|
| no header | `"apiVersion": "id.registrystack.org/formats/breg/migration-rehearsal-receipt/v1alpha1"` and `"kind": "BRegMigrationRehearsalReceipt"` |
| `planSha256` | `planDigest` |
| `sqlSha256` and `assertionSha256`, items `{path, sha256}` | `sqlDigests` and `assertionDigests`, items `{path, digest}` |
| `fixtureInventory[].sha256` | `fixtureInventory[].digest` |
| `rowAssertions[].stepId` | `rowAssertions[].step` |
| `proofs` | removed; delete it |

Migrate each backup binding:

| Old | New |
|---|---|
| no header | `"apiVersion": "id.registrystack.org/formats/breg/backup-binding/v1alpha1"` and `"kind": "BRegBackupBinding"` |
| `databaseId` | `database` |
| `sha256` | `digest` |
| `byteLength` | `sizeBytes` |
| `maxAgeSeconds` | `maximumAgeSeconds` |

A document without its header is refused with `config.missing-envelope`,
whose fix names the header, and once the header is current every previous
spelling is refused with `config.removed-key` at its position, naming its
replacement. `bregctl` prints one sentence naming the document (`bregctl
test refused the reviewed migration descriptor.`, `... the migration
rehearsal receipt.`, or `bregctl apply refused the backup binding.`)
followed by every diagnostic with its file, line, column, and key; with
`--format json` the report's `diagnostics` carry the reader's shape
unchanged. No diagnostic repeats a digest, path, or count it was given.

| Condition | Old | New |
|---|---|---|
| a descriptor that does not parse, repeats a key, lacks its header, or has an unknown, missing, or malformed member | `migration.review.descriptor_refused` | the reader's `config.*` and `yaml.*` codes |
| a receipt that does not parse or has an unknown, missing, or malformed member, including a malformed digest | `migration.review.evidence_refused` or `migration.review.refused` | the reader's codes, a malformed digest as `config.invalid-value` at its key |
| a receipt carrying `proofs` | `migration.review.receipt_proofs_retired` | `config.removed-key` at `/proofs` |
| a backup binding that does not parse or has an unknown, missing, or malformed member | `apply.backup_evidence.refused` | the reader's codes |

`migration.review.descriptor_refused`, `migration.review.evidence_refused`,
and `apply.backup_evidence.refused` remain for a document that reads but
fails a semantic check, such as a cover the candidate does not make, a
receipt that does not bind this candidate, or a backup that is too old.

A package carrying a reviewed migration that an earlier `bregctl` built
holds its documents in the old spelling, and the runtime refuses to load it
after the upgrade; the previous release still loaded a package whose receipt
carried `proofs`, and this one does not. Migrate the reviewed directory as
above, then run `bregctl test` and `bregctl package` with
`--reviewed-migrations` again to rebuild the package before upgrading the
runtime. The activation ledger keeps
its own record of each backup it accepted and is unchanged.

### BREAKING: Evidence source export manifest header (`source-export.json`)
<!-- upgrade: breg-evidence-source-export -->

`bregctl generate evidence-source` writes `source-export.json` with an
`apiVersion` and `kind` header first and a `digest` for each artifact, and
`evidencectl source import`, `source diff`, `source update`, and `source add`
read it through the shared configuration reader. An export written by an
earlier `bregctl` is refused; generate it again with this release's `bregctl
generate evidence-source`. A producer that writes its own export migrates its
manifest:

| Old | New |
|---|---|
| `"formatVersion": 1` | `"apiVersion": "id.registrystack.org/formats/breg/evidence-source-export/v1alpha1"` and `"kind": "BRegEvidenceSourceExport"` |
| `artifacts[].sha256`, 64 lowercase hex digits | `artifacts[].digest`, written `sha256:` followed by the same 64 digits |

`sourceId`, `provenance`, and `artifacts[].path` keep their spelling and
bounds. A manifest without its header is refused with
`config.missing-envelope`, whose fix names the header; with the header, a
remaining `formatVersion` or `sha256` is refused with `config.removed-key` at
its position, naming its replacement. `evidencectl` prints one sentence
(`evidencectl source import refused the Evidence source export manifest.`)
followed by every diagnostic with its file, line, column, and key; with
`--format json` the refusal report's `diagnostics` carry the reader's shape
unchanged and the command exits 1. The checks that follow decoding, such as
the artifact digests, bounds, and the single `sources/<sourceId>.yaml`, keep
their messages.

The source-import baseline (`.evidence/source-imports/state.json`) records
each accepted manifest in its own unchanged shape, so a project that already
imported an export keeps its baseline; only the next import, diff, or update
needs a regenerated export.

### BREAKING: a substitution expression is refused in a file `bregctl` reads as written
<!-- upgrade: breg-tool-file-substitution -->

Substitution (`${NAME}`, `${NAME:-fallback}`, `${NAME:?message}`) applies to
the runtime configuration only. The fixture journeys, the schema-test
credentials, the model selection, the development clients, the example
scenarios, the migration descriptor, and the backup binding are read as
written: a `${...}` expression in any key or string value of them is refused
with `config.substitution-not-allowed` at its position, where an earlier
`bregctl` kept it as literal text. Text that is not an expression, such as a
lone `${`, is still accepted. Migrate a file by writing the value itself in
place of the expression; in the schema-test credentials and the development
clients, name a secret with a secret reference (`secret:file/<name>` or
`secret:env/<NAME>`) instead. The diagnostic names the key, never the
expression or a variable's value.

### `bregctl check --file`: an offline check for each tool file

`bregctl check --file <FILE>` checks one tool file on its own, choosing the
format by the file's `kind`: the fixture journeys (with `PROJECT`, against
that project's routes), the schema-test credentials or receipt, a data
checkpoint or import state, a migration descriptor, rehearsal receipt, or
backup binding, a model selection, or a development clients, example
scenarios, session state, or source preparation file. It reads no secret,
database, or network. It prints the diagnostics in the human form, or with
`--format json` the report's `diagnostics` list, and exits 0 when the file
passes, 1 when it is refused or, with `--deny-warnings`, when it carries a
warning, 2 for a usage error, and 3 when the file cannot be read.

### BREAKING: `bregctl check PROJECT` reads the journeys and the development clients
<!-- upgrade: breg-project-check-tool-files -->

`bregctl check PROJECT` reads the tool files a project holds beside its
sources: `dev-clients.yaml` when the project has one, and every `.yaml` and
`.yml` file directly under `tests/`. Each is identified by its `kind` and
checked as `bregctl check --file` checks it, with the same diagnostics, and
the journeys are held to the project the check compiled. When the project
itself is refused, these files are still read, and the journeys are checked
on their own. An earlier `bregctl check PROJECT` read `registry.yaml` and the
modules only, so it passed a project whose journeys `bregctl test` would
refuse.

What a project meets:

- The count that closes the report includes these files. The project
  `bregctl init` writes reports `in 4 files` where it reported `in 2 files`.
- A check that passed exits 1 when a journey no longer fits the project, for
  example one that calls an access profile the project no longer declares or
  claims a purpose the profile no longer requires, or when the development
  clients file is refused. Correct the file as its diagnostic says.
- A YAML file directly under `tests/` whose `kind` is not a Base Registry
  Engine tool file's is refused with `config.wrong-kind`, or with
  `config.missing-envelope` when it has none. Move such a file out of
  `tests/`.
- A directory under `tests/` is not read, and the check says so with the
  warning `breg.check.unread-directory`, which `--deny-warnings` refuses.
  Move the journeys it holds up into `tests/`.
- A `tests` that is not a directory, or is a symbolic link, is refused with
  `breg.check.directory-unreadable`.

YAML elsewhere in the project directory, such as a runtime file kept beside
`registry.yaml`, is not read by the project check.

### Published JSON Schemas for the tool files

The fixture journeys, schema-test credentials, model selection, development
clients, example scenarios, and backup binding each publish a JSON Schema
generated from the types `bregctl` decodes, under
`products/breg/generated/tools/`. Each identifier names the format and its
version, for example
`https://id.registrystack.org/schemas/breg/journeys/journeys.v1.schema.json`.
`editors/configure.py` maps the YAML formats (`tests/journeys.yaml`,
`credentials.yaml`, `model/selection.yaml`, `dev-clients.yaml`) and the JSON
formats (`*-binding.json`, `examples/scenarios.json`) for editors; a JSON
format goes through `json.schemas` in VS Code and the `json-language-server`
settings in Zed. The schema is an editing aid: `bregctl check --file` remains
the check, and it also refuses what a schema cannot express, such as a
journey that names a route its project does not declare.

### `bregctl check --format json` carries `status`; `dev grant` carries `diagnostics`

Both changes add a member; no existing member moves or changes meaning.

- The `bregctl check --format json` report opens with `ok`, `command`, and
  `status`, the head the other Registry Stack ctl reports share. `status` is
  `complete` (exit 0), `domain-refusal` (exit 1), or `operational-failure`
  (exit 3). `apiVersion` and `kind` follow when the format moves to stable.
- The `bregctl dev grant` JSON report carries `diagnostics`, always an empty
  list on success, like every other report.

### BREAKING: development clients identifiers, URLs, and exchange mapping (`dev-clients.yaml`)
<!-- upgrade: breg-dev-clients-types -->

The development clients schema states the reader's types, so the reader now
decodes these members through the shared types and refuses a value they
refuse, with the reader's code, path, and fix:

- `clients[].id`, `seed[].id`, `issuer.exchangeIssuers[].id`, and
  `issuer.interactiveApplications[].id`, and the keys of `eventDestinations`,
  `evidenceProviders`, `reviewAuthorities`, `reviewExecutors`, and
  `issuer.clientResources`, are local identifiers: a lowercase letter, then up
  to 63 lowercase letters, digits, `_`, or `-`. An identifier that starts with
  a digit is refused.
- `issuer.exchangeIssuers[].issuer` and `evidenceProviders.*.baseUrl` are
  absolute `http` or `https` URLs with a host and no user information.
  Migration: write the issuer as its URL, not a URN.
- The keys of `clients[].claims`, `issuer.exchangeIssuers[].tokenAttributes`,
  and `issuer.syntheticUsers[].attributes` are non-empty text without control
  characters.
- `issuer.exchangeIssuers[].mapping` is spelled `institutional-grant` or
  `first-party`. Migration: replace `institutional_grant` with
  `institutional-grant` and `first_party` with `first-party`; the old
  spellings are refused.

### BREAKING: `explain` output schema identifiers
<!-- upgrade: no-file -->

The nine `bregctl explain` output schemas under
`products/breg/contracts/explain/` take their identifiers from the Registry
Stack identifier catalog. A consumer that resolves these schemas by `$id`, or
pins the old identifiers, replaces each with its new one:

| `kind` | Old `$id` | New `$id` |
|---|---|---|
| `AccessExplanation` | `https://registrystack.org/breg-explain/v1alpha3/AccessExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/access-explanation/access-explanation.v1alpha4.schema.json` |
| `AccessPreview` | `https://registrystack.org/breg-explain/v1alpha3/AccessPreview.schema.json` | `https://id.registrystack.org/schemas/breg/access-preview/access-preview.v1alpha4.schema.json` |
| `ActionsExplanation` | `https://registrystack.org/breg-explain/v1alpha3/ActionsExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/actions-explanation/actions-explanation.v1alpha4.schema.json` |
| `ChangeRequestsExplanation` | `https://registrystack.org/breg-explain/v1alpha3/ChangeRequestsExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/change-requests-explanation/change-requests-explanation.v1alpha4.schema.json` |
| `EventsExplanation` | `https://registrystack.org/breg-explain/v1alpha3/EventsExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/events-explanation/events-explanation.v1alpha4.schema.json` |
| `LifecycleExplanation` | `https://registrystack.org/breg-explain/v1alpha3/LifecycleExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/lifecycle-explanation/lifecycle-explanation.v1alpha4.schema.json` |
| `ModelExplanation` | `https://registrystack.org/breg-explain/v1alpha3/ModelExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/model-explanation/model-explanation.v1alpha4.schema.json` |
| `QueriesExplanation` | `https://registrystack.org/breg-explain/v1alpha3/QueriesExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/queries-explanation/queries-explanation.v1alpha4.schema.json` |
| `RoutesExplanation` | `https://registrystack.org/breg-explain/v1alpha3/RoutesExplanation.schema.json` | `https://id.registrystack.org/schemas/breg/routes-explanation/routes-explanation.v1alpha4.schema.json` |

The schemas also state what `bregctl` already writes. Every integer has a
minimum and a maximum: the range of the Rust type `bregctl` writes, or 0 to
9007199254740991, the largest integer JSON carries exactly, where that type
is wider. Lists that are sets declare `uniqueItems`, a module digest is
`sha256:` followed by 64 lowercase hex digits, the request lifecycle pin
refuses a member the lifecycle does not declare, and
`requests[].fields[].schema` is marked as an embedded JSON Schema. The
`apiVersion` moves from `registry.registrystack.org/breg-explain/v1alpha3` to
`registry.registrystack.org/breg-explain/v1alpha4` for the reasons the
"BReg access" section gives.

## BReg access

A registry serves authenticated callers only. Every change in this section
is security-sensitive: it removes the configuration and the runtime paths
that admitted a caller without a verified token.

### BREAKING: anonymous access profiles are removed
<!-- upgrade: breg-remove-anonymous, breg-module-relock -->

`anonymous` is refused wherever an access profile was written, with
`true` or `false`, as `config.removed-key` when the file is read. The
diagnostic names the fix: delete the member and give the profile the
`principalClaim` and `requiredScopes` its callers' tokens carry.

| File | Refused member |
|---|---|
| `registry.yaml` | `/accessProfiles/*/anonymous` |
| `registry.yaml` | `/entities/*/accessProfiles/*/anonymous` |
| `module.yaml` | `/entities/*/accessProfiles/*/anonymous` |
| `module.yaml` | `/extendEntities/*/accessProfiles/*/anonymous` |

Every route except `/health`, `/healthz`, `/ready`, and the review
completion receiver now refuses a request without a verified bearer token
with `401 authentication.refused` before any access profile, query, or
record is read. That covers the record, revision, action, change-request,
attachment, statistics, ingestion, access log, and GIS routes, the discovery
surfaces (`/openapi.json`, `/v1/registry`, and the published JSON Schemas),
and a path the registry does not declare. A request without a token used to
reach the route, where an anonymous profile could serve it or the route
answered `404 resource.not_found`. A presented and rejected token keeps its
`401`, and a verified token that does not satisfy the profile keeps its
concealed `404`. The OpenAPI document drops the unauthenticated security
alternative: each operation lists `bearerAuth` only.

Such a refusal names no principal, so it is counted in the
`breg_http_requests_total` `client_error` series and never journaled. The
`breg_anonymous_refusals_total` counter is removed with its nine `reason`
values; move an alert on it to the `client_error` rate of the record routes.

A `tests/journeys.yaml` step that writes `claims: {}` now has to carry the
claims its profile requires, and the schema-test credentials file refuses
`type: anonymous` as `config.unknown-variant`: bind every step with
`type: bearer` and a `tokenRef`.

`bregctl explain` reports `registry.registrystack.org/breg-explain/v1alpha4`.
An immediate-action permission in `ActionsExplanation` has no `anonymous`
member, and `claimContractError` in `AccessExplanation` no longer takes
`anonymous_profile_carries_authority`. A consumer that pins `v1alpha3`
moves to the `v1alpha4` schemas and stops reading the member.

The compiled model changes, so a project's compiled revision changes while
its tables, its action fingerprints, and its change-request contract
fingerprints do not: a proposal submitted under the earlier release does not
ask for a rebase when the successor's request type did not change. A package
an earlier release built reads as a predecessor when every profile in it was
authenticated. A predecessor that granted unauthenticated access is refused
when `bregctl test` or `bregctl package` reads it through
`--baseline-package`, because a successor planned over it would keep row
policies that admit a caller without a principal.

A predecessor package is also read with the access spellings the earlier
release wrote. When `bregctl test` or `bregctl package` compiles its packaged
sources for a rehearsal, `rowBoundaries: []` reads as `unrestricted`, an
omitted or empty `requiredScopes` reads as `unrestricted`, an empty
`requiredPurposes`, `requesterClients`, or access-requirement list reads as
omitted, an action permission's empty `rowBoundaries` is dropped, `anonymous:
false` is dropped, and a `null` optional member reads as absent. A `null` that
is a value stays one: an `equals` comparison literal, a literal under a hook
condition's `beforeEquals` or `afterEquals`, and a `null` inside a structured
field's `schema`. Each keeps the meaning the earlier release gave it. This
applies to the predecessor only: a project or module you check, build, package
as the successor, or start still refuses the empty list.
A predecessor's module lock is not compared with its module either: the
earlier release computed that digest over the spellings it wrote, and the
sealed package already binds every module byte to the package digest the
rehearsal names. A predecessor that locks a module therefore compiles for a
rehearsal; a module whose version differs from its lock is still refused.
A predecessor's statistical datasets are read with the forms the earlier
release wrote too. A period tagged by `kind` reads as the same period, and
the profiles a dataset named under `live` and `releases` read as the profile
permissions the migration steps of "statistical dataset access is granted in
profile permissions" write: `read-live` for a live profile, `publish` for the
publisher, and `read-releases` for every profile a dataset with `releases`
named. The predecessor compiles to the registry its project compiles to once
those steps are applied, with the live profiles and the publisher it had. Its
reader list leaves out the publisher or a live profile it listed under
`releases.readers`, which the release routes served either way. A dataset
that names a profile the project does not declare is refused, as the earlier
release refused it.
The predecessor's sealed sources are read through the shared reader's
structural pass, so a sealed source outside the YAML subset (an anchor, an
alias, a tag, a merge key, or a duplicate key) is no longer a readable upgrade
baseline and the read refuses it.

These configuration diagnostics are no longer reported, because nothing can
reach them. The second column is the name the code table above gave them:

| Was | Renamed to, now removed |
|---|---|
| `access.profile.anonymous_collection` | `breg.access.profile-anonymous-collection` |
| `access.requirements.authentication` | `breg.access.requirements-authentication` |
| `access_log.anonymous_read_forbidden` | `breg.access-log.anonymous-read-forbidden` |
| `access_profile.anonymous.claim_requirements_forbidden` | `breg.access-profile.anonymous-claim-requirements-forbidden` |
| `access_profile.anonymous.mutation_forbidden` | `breg.access-profile.anonymous-mutation-forbidden` |
| `access_profile.principal_claim.forbidden` | `breg.access-profile.principal-claim-forbidden` |
| `access_profile.public.processing_non_public` | `breg.access-profile.public-processing-non-public` |
| `access_profile.snapshot.anonymous_forbidden` | `breg.access-profile.snapshot-anonymous-forbidden` |
| `action.permission.anonymous_forbidden` | `breg.action.permission-anonymous-forbidden` |
| `attachment.access.authentication_required` | `breg.attachment.access-authentication-required` |
| `change_request.presence.anonymous_claim_boundary` | `breg.change-request.presence-anonymous-claim-boundary` |
| `change_request.presence.anonymous_non_public` | `breg.change-request.presence-anonymous-non-public` |
| `consent.require.anonymous` | `breg.consent.require-anonymous` |
| `query.temporal.public_processing_non_public` | `breg.query.temporal-public-processing-non-public` |
| `statistical_dataset.profile.anonymous` | `breg.statistical-dataset.profile-anonymous` |

To migrate a registry that served anonymous callers:

1. Decide who the callers are, and have the identity provider issue them
   tokens. A public directory becomes a profile whose `requiredScopes`
   names a scope every directory client carries.
2. On the earlier release, delete `anonymous` from every access profile, in
   `registry.yaml` and under `entities` and `extendEntities` in every
   `module.yaml`, and give each profile a `principalClaim` and the scopes
   above. Run `bregctl project lock` in each project that locks a module you
   changed, then `bregctl test`, `package`, and `apply` that package.
3. Upgrade the binaries, rebuild the package from the same sources, and apply
   it. Clients send a bearer token on every request, discovery included.
4. Replace alerts on `breg_anonymous_refusals_total`, and update scripts that
   expected `404` from a request without a token to expect `401`.

### BREAKING: an access member says `unrestricted` or names what it restricts
<!-- upgrade: breg-access-unrestricted, breg-module-access-unrestricted, breg-access-requirements, breg-module-relock -->

An empty list no longer means "no restriction" in an access profile. A
member that grants reach takes the keyword `unrestricted` or a list of at
least one item, a member that only narrows is omitted when it narrows
nothing, and `[]` is refused in both places as `config.invalid-value` at the
member when the file is read. The diagnostic names the fix.

| File | Member | Accepted | Refused |
|---|---|---|---|
| `registry.yaml` | `/accessProfiles/*/requiredScopes` | `unrestricted`, or a list of at least one scope | omitted (`config.missing-key`), `[]` |
| `registry.yaml` | `/accessProfiles/*/requiredPurposes` | omitted, or a list of at least one purpose | `[]`, `unrestricted` |
| `registry.yaml` | `/accessProfiles/*/requesterClients` | omitted, or a list of at least one OAuth client | `[]`, `unrestricted` |
| `registry.yaml` | `/accessProfiles/*/permissions/*/rowBoundaries` on an entity permission | `unrestricted`, or a list of at least one row boundary | omitted, `[]` |
| `registry.yaml` | `/accessProfiles/*/permissions/*/applyTargets/*/rowBoundaries` | `unrestricted`, or a list of at least one row boundary | omitted, `[]` |
| `registry.yaml` | `/accessProfiles/*/permissions/*/requestPresence/*/rowBoundaries` | `unrestricted`, or a list of at least one row boundary | omitted, `[]` |
| `registry.yaml` | `/accessProfiles/*/permissions/*/targets/*/rowBoundaries` on an action permission | `unrestricted`, or a list of at least one row boundary | omitted, `[]` |
| `registry.yaml`, `module.yaml` | `/entities/*/accessRequirements/requiredScopes`, `allowedPurposes`, `rowBoundaries` | omitted, or a list of at least one item | `[]`, `unrestricted` |
| `module.yaml` | `/extendEntities/*/accessRequirements/requiredScopes`, `allowedPurposes`, `rowBoundaries` | omitted, or a list of at least one item | `[]`, `unrestricted` |
| `module.yaml` | `/entities/*/accessProfiles/*/requiredScopes` and `/extendEntities/*/accessProfiles/*/requiredScopes` | `unrestricted`, or a list of at least one scope | omitted (`config.missing-key`), `[]` |
| `module.yaml` | `/entities/*/accessProfiles/*/requiredPurposes`, `requesterClients` and the same under `/extendEntities/*` | omitted, or a list of at least one item | `[]`, `unrestricted` |
| `module.yaml` | `/entities/*/accessProfiles/*/rowBoundaries`, `applyTargets/*/rowBoundaries`, `requestPresence/*/rowBoundaries` and the same under `/extendEntities/*` | `unrestricted`, or a list of at least one row boundary | omitted, `[]` |

`requiredScopes` on a profile is now required, so a profile states whether
it demands a scope. `requiredPurposes` and `requesterClients` stay optional
and do not take the keyword: omitting one applies no restriction on that
dimension, as it did. An access requirement never grants, so it has nothing
to write `unrestricted` for.

The authorization a registry enforces does not change. `unrestricted`
compiles to what `[]` compiled to, so a project rewritten this way keeps its
compiled revision, its tables, its row policies, and its action
fingerprints, and a package an earlier release built still reads as a
predecessor.

Two findings are removed and two are added:

| Finding | Change |
|---|---|
| `breg.access.profile-no-required-scope` | Removed. The profile now writes `requiredScopes: unrestricted`, so the file states the decision the finding asked about. |
| `breg.access.action-no-required-scope` | Removed for the same reason. |
| `breg.access.profile-subsumes-narrower` | Added, a warning at `project.accessProfiles[id=...].requiredScopes`. A profile written `unrestricted` admits every token that another profile admits, so a caller admitted there also reaches what the unrestricted profile grants by selecting it. Two unrestricted profiles behind the same gates are each reported. |
| `breg.access.wildcard-spelled-item` | Added, a warning at the member. An item spelled `*` or `unrestricted` in a profile's `requiredScopes`, `requiredPurposes`, or `requesterClients`, or in an access requirement's `requiredScopes` or `allowedPurposes`, names one entry and matches nothing else. |

A `--deny-warnings` gate that passed can now fail on either added finding,
and a gate that listed the two removed codes no longer sees them.

A module's digest is taken over the module as `bregctl` writes it, and an
access requirement member that holds nothing is no longer written. A module
that declares `accessRequirements` without all three members gets a new
digest: run `bregctl project lock` in each project that locks it.

Module entity profiles under `/entities/*/accessProfiles` and
`/extendEntities/*/accessProfiles` in `module.yaml` follow the same rules as
a project profile, and the published module schema states them.
`requiredScopes` is required and takes `unrestricted` or a list of at least
one scope. `rowBoundaries`, and the row reach of `applyTargets` and
`requestPresence`, take `unrestricted` or a list of at least one boundary.
`requiredPurposes` and `requesterClients` are omitted when they narrow
nothing. A module profile written `[]` or without `requiredScopes` was
accepted and granted every row or every scope; it is now refused, and the
two project findings above (`breg.access.profile-subsumes-narrower` and
`breg.access.wildcard-spelled-item`) also report a module-contributed
profile, at `entities[id=...].accessProfiles[id=...]`. A module's digest is
taken over the module as `bregctl` writes it, so a module that contributes a
profile gets a new digest.

`bregctl init`, `bregctl init --from publicschema`, the consent module, and
the source `bregctl dev` prepares write the new spelling. `caseworkctl
source add` reads `requiredScopes: unrestricted` from a registry project as
no scope and refuses any other non-list value.

To migrate a registry project:

1. In every profile under `accessProfiles`, replace `requiredScopes: []`
   with `requiredScopes: unrestricted`, and add `requiredScopes:
   unrestricted` to a profile that has no `requiredScopes`. Prefer naming a
   scope the profile's callers carry.
2. Delete `requiredPurposes: []` and `requesterClients: []`.
3. Replace `rowBoundaries: []` with `rowBoundaries: unrestricted` in entity
   permissions, action `targets`, `applyTargets`, and `requestPresence`.
4. Under `accessRequirements`, in `registry.yaml` and in every module,
   delete each member written as `[]`, then run `bregctl project lock`.
5. In every `module.yaml` that writes `accessProfiles` on an entity or an
   extension, apply steps 1 to 3 to those profiles: add `requiredScopes:
   unrestricted` (or name the scopes) where it is missing, and replace
   `rowBoundaries: []` with `rowBoundaries: unrestricted`. Then run
   `bregctl project lock` in each project that locks the module.
6. Run `bregctl check`. Review each `breg.access.profile-subsumes-narrower`
   finding: give the unrestricted profile a scope, or accept that its grants
   are reachable by every caller of the narrower profile.

### BREAKING: the runtime file states which OAuth clients it accepts
<!-- upgrade: breg-runtime-allowed-clients -->

`authentication.oidc.allowedClients` in `runtime.yaml` is required. It takes
the keyword `unrestricted`, to accept a token from every client of the
issuer, or a list of at least one OAuth client.

| Written | Before | Now |
|---|---|---|
| member omitted | every client accepted | refused, `config.missing-key` at `/authentication/oidc` |
| `allowedClients: []` | every client accepted | refused, `config.invalid-value` at `/authentication/oidc/allowedClients` |
| `allowedClients: unrestricted` | refused | every client accepted |
| `allowedClients: [a, b]` | only `a` and `b` accepted | unchanged |

The diagnostic names the fix and never repeats what was written. Any other
word in place of the list is refused the same way. A list keeps its bounds:
at most 128 distinct clients of 1 to 512 characters each. The published
runtime schema states the same shape, so a file the schema accepts is a file
the runtime reads.

Token verification does not change. A registry whose runtime file is
rewritten as below accepts exactly the tokens it accepted before.

The startup check that ties a project's clients to this member is unchanged
and compares against the written list. A project that names clients itself,
in a profile's `requesterClients`, in `authorityClaims.trustedActors`, or in
a consent recipient organization, still needs each of them listed, so
`unrestricted` does not start with such a project, as an omitted member did
not.

`bregctl check <project> --runtime-config runtime.yaml` holds the runtime file
to the project it is checked with. It refuses the file when the project names
a client in a profile's `requesterClients`, in `authorityClaims.trustedActors`,
or in a consent recipient organization that `allowedClients` does not list
(`breg.runtime.clients-unlisted`), and when the configured principal claim is not
the one the project's access profiles require
(`breg.runtime.principal-claim-mismatch`). A mapping of authority claims the
runtime would refuse at startup is refused offline as
`breg.runtime.invalid-authority-claims`. A list that spells a wildcard item
is warned of (`breg.access.wildcard-spelled-item`). A registry started with
`allowedClients: unrestricted` logs the closed event
`startup.authentication.clients_unrestricted` once, with no configured value.

`bregctl dev` writes the list of clients its session admits, and writes
`unrestricted` when the session has no client to name. `bregctl init`
writes a list.

To migrate a runtime file:

1. If `allowedClients` is missing or written `[]`, decide which OAuth
   clients call this registry and list them. Listing them is the stronger
   choice: a token issued to any other client of the same issuer is then
   refused before any profile is selected.
2. To keep accepting every client of the issuer, write
   `allowedClients: unrestricted`.
3. Run `bregctl check <project> --runtime-config runtime.yaml`.

### BREAKING: statistical dataset access is granted in profile permissions
<!-- upgrade: breg-statistical-dataset-grants -->

A statistical dataset no longer names the profiles that use it. Each access
profile grants the dataset in its own `permissions`, beside its record
grants, so reviewing one profile shows everything the profile reaches.

| File | Member | Change |
|---|---|---|
| `registry.yaml` | `/statisticalDatasets/*/live` | Removed, refused as `config.removed-key` naming the new home |
| `registry.yaml` | `/statisticalDatasets/*/releases` | Removed, refused as `config.removed-key` naming the new home |
| `registry.yaml` | `/accessProfiles/*/permissions/*` | Accepts a third form, `{dataset, operations}` |

A dataset permission holds `dataset` and `operations` only. Its operations
are `read-live` (exact live counts), `publish` (publish and withdraw
releases), and `read-releases` (read released documents).

The three words are new, so they are kebab-case from their first release
(CFG-NAME-2, CFG-CHANGE-5). The fifteen entity and action operations keep
their spelling (`submit_request` and the rest) until the stable move, and
the operation names the API returns for a dataset in `/v1/registry` and in
the OpenAPI document (`read_live`, `list_releases`, `publish_release`, and
the rest) are unchanged.

```yaml
accessProfiles:
  - id: facility-operator
    permissions:
      - dataset: monthly-discharge-reports
        operations: [read-live, read-releases]
  - id: statistics-publisher
    permissions:
      - dataset: monthly-discharge-reports
        operations: [publish, read-releases]
  - id: statistics-reader
    permissions:
      - dataset: monthly-discharge-reports
        operations: [read-releases]
```

The release routes serve the publisher and every live reader as well as the
listed readers, and they still do. The file now says so: when a dataset has
a publisher, the publisher and every `read-live` profile must also write
`read-releases`. That audience was implied before and is written now.

Refused when the file is read, as `config.invalid-value` at the permission:

| Written | Fix the diagnostic names |
|---|---|
| a dataset permission with an entity or action operation, or with none | write at least one of `read-live`, `publish`, or `read-releases` |
| a dataset permission with any other member (`entity`, `action`, `rowBoundaries`, `readableFields`, and the rest) | keep `dataset` and `operations` only |
| an entity or action permission with `read-live`, `publish`, or `read-releases` | move them to a permission that names a dataset |

An operation outside the eighteen words a permission accepts is refused as
`config.unknown-variant`.

Refused at compile:

| Code | Path | Condition |
|---|---|---|
| `breg.access-profile.permission-dataset-unknown` | `project.accessProfiles[].permissions[].dataset` | The permission names a dataset the project does not declare. Added. |
| `breg.statistical-dataset.publisher-multiple` | the dataset | More than one profile holds `publish`. Added. |
| `breg.statistical-dataset.publisher-missing` | the dataset | A profile holds `read-releases` and no profile holds `publish`. Added. |
| `breg.statistical-dataset.read-releases-required` | the dataset | The publisher or a `read-live` profile of a published dataset does not hold `read-releases`. One diagnostic per profile. Added. |
| `breg.statistical-dataset.profile-duplicate` | the dataset | One profile names the dataset in two permissions. It used to report a profile listed twice on the dataset. |
| `breg.statistical-dataset.grants-empty` | the dataset | No profile holds any operation on the dataset. The fix text now names the profile permission. |

Two codes are no longer reported, because nothing can write the shape they
refused:

| Was | Renamed to, now removed |
|---|---|
| `statistical_dataset.profile.unknown` | `breg.statistical-dataset.profile-unknown` |
| `statistical_dataset.releases.readers_empty` | `breg.statistical-dataset.releases-readers-empty` |

A dataset that only its publisher reads is therefore accepted: the publisher
holds `publish` and `read-releases`, and no other profile is needed.

The message of `breg.access-profile.permission-target-missing` now reads "an
access permission must name one entity, one action, or one statistical
dataset".

The authorization a registry enforces does not change. A project rewritten
as below compiles to the same live profiles, publisher, and readers, so it
keeps its compiled revision and its dataset definition digests. One case
moves the revision without changing who is served: a project that listed the
publisher or a live profile under `releases.readers` compiles to a reader
list without that profile, which the release routes already served.

`bregctl explain access` gains `statisticalDatasets`: one entry per dataset,
in dataset id order, with the profiles holding `readLive`, `publish`, and
`readReleases`. It is `[]` for a project without datasets. The member is
added to `breg-explain/v1alpha4` and to the `AccessExplanation` contract,
where it is required; no member is removed or renamed.

To migrate a registry project, for each entry under `statisticalDatasets`:

1. For each profile under `live`, add `{dataset: <id>, operations:
   [read-live]}` to that profile's `permissions`. If the dataset has
   `releases`, write `operations: [read-live, read-releases]`.
2. For `releases.publisher`, add `{dataset: <id>, operations: [publish,
   read-releases]}` to that profile's `permissions`. A profile that is both
   live and the publisher writes one permission with all three operations.
3. For each profile under `releases.readers`, add `{dataset: <id>,
   operations: [read-releases]}` to that profile's `permissions`, or add
   `read-releases` to the permission steps 1 and 2 already wrote for it.
4. Delete `live` and `releases` from the dataset.
5. Run `bregctl check`, then `bregctl explain access` and compare
   `statisticalDatasets` with the grants you removed.

### BREAKING: an action permission takes no `rowBoundaries`
<!-- upgrade: breg-action-row-boundaries -->

An access-profile permission that names an `action` is refused when it also
writes `rowBoundaries`, with `config.invalid-value` at the permission and the
fix named. The project schema never listed the member for an action, and the
compiled project is now written without it.

Migrate by deleting `rowBoundaries` from every permission that has `action:`;
the row reach of an action is written on each of its `targets`.

## BReg citizen services

This section covers the runtime files of the two citizen services beside the
Base Registry Engine: `breg-mcp`, the citizen MCP gateway, and `breg-review`,
its paired review page. Both formats are experimental, so every
normalization lands in this release.

### BREAKING: both runtime files take a new `apiVersion` and renamed keys
<!-- upgrade: breg-service-runtime-keys -->

`breg-mcp` and `breg-review` read `runtime.yaml` through the shared Registry
Stack reader. The old `apiVersion` is refused as
`config.retired-api-version`, and the refusal names the new one and the keys
to rename. Once the `apiVersion` is replaced, each old key is refused at its
position as `config.removed-key`, and the message names its replacement.
Every value keeps its meaning unless the step below says otherwise.

| Service | Old spelling | New spelling | Migration |
|---|---|---|---|
| `breg-mcp` | `apiVersion: registry.registrystack.org/breg-mcp-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/breg/mcp-runtime/v1alpha1` | Replace the value. |
| `breg-mcp` | `resourceServer.maxTokenLifetimeSeconds` | `resourceServer.maximumTokenLifetimeSeconds` | Rename the key. The value is now bounded 1 to 86400 (it was any positive number); a larger value is refused as `config.out-of-range`, so lower it to 86400 or less. Omitted, it is 3600, as before. |
| `breg-mcp` | `registry.requestTimeoutMilliseconds` | `registry.attemptTimeoutMilliseconds` | Rename the key. The value is now bounded 100 to 120000 (it was any positive number). Omitted, it is 10000, as before. |
| `breg-mcp` | `limits.maxRequestBodyBytes` | `limits.maximumRequestBytes` | Rename the key; keep the value (1 to 1048576, as before). |
| `breg-mcp` | `audit.retainDays` | `audit.retentionDays` | Rename the key; keep the value. |
| `breg-review` | `apiVersion: registry.registrystack.org/breg-review-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/breg/review-runtime/v1alpha1` | Replace the value. |
| `breg-review` | `limits` | `rateLimits` | Rename the key; keep its `perCitizen` and `globalSignIn` members. Each `requestsPerMinute` and `burst` is now bounded 1 to 1000000 (it was any positive number). |
| `breg-review` | `audit.retainDays` | `audit.retentionDays` | Rename the key; keep the value. |

`breg-mcp` keys that predate v0.39.0, `resourceServer.jwks` and
`audit.maximumFileBytes`, stay refused as unknown keys (`config.unknown-key`)
with no named replacement, as in v0.39.0: write `resourceServer.jwksSource`
and `audit.rotateBytes`.

To find every old spelling in a file, run
`breg-mcp --runtime-config FILE check` or
`breg-review --runtime-config FILE check`. It reports a retired `apiVersion`
alone; once that is replaced, it reports each old key at its line and column
with its replacement, and the file is clean when the command exits 0.

### BREAKING: the shared reader refuses values outside the documented grammar
<!-- upgrade: breg-runtime-reader-refusals -->

A file that was already outside the documented grammar is now refused when it
is read, and every refusal carries a code, a JSON Pointer path, a line, a
column, and the edit that fixes it. No refusal repeats a configured value.

| A file that writes | is refused as | Migrate by |
|---|---|---|
| `null`, `~`, or a key with no value | `config.null-value` | Deleting the key; an optional member is written by leaving it out. |
| an unquoted value that looks like a number but is not a plain decimal: a leading zero (`0123`), a bare point (`.5`, `5.`), a base prefix (`0x1F`), `.inf`, or `.nan` | `yaml.ambiguous-number` | Quoting the value when it is text, or writing the plain decimal when it is a number. |
| a number where text is expected, such as an unquoted `clientId: 12345` | `config.expected-string` | Quoting the value: `clientId: "12345"`. |
| text where a number is expected, such as `burst: "10"` | `config.expected-integer` | Writing the number unquoted. |
| a YAML anchor, alias, merge key, or tag | `yaml.anchor`, `yaml.alias`, `yaml.merge-key`, `yaml.tag` | Writing the shared value out in full at every place that used the alias. |
| an empty file | `config.missing-envelope` at line 1, column 1 (was `platform.runtime-config.size`) | Writing the `apiVersion`, `kind`, and members the format requires. |
| a file over the reader's size bound | `yaml.too-large` (was `platform.runtime-config.size`) | Shrinking the file below the bound the message names. |

### BREAKING: members are typed by the shared reader
<!-- upgrade: breg-service-runtime-members -->

Each member is read as the shared type its schema names, so a value outside
that type is refused at the member, as `config.invalid-value`,
`config.invalid-length`, `config.duplicate-item`, or `config.out-of-range`,
rather than after the whole file was decoded.

- **Secret references.** Every `*Ref` member is `secret:file/NAME` or
  `secret:env/NAME`, as before. An inline value is refused as
  `config.invalid-value` at the member, by path only; a `${NAME}` expression
  in a reference is refused as `config.substitution-not-allowed`. Migration:
  none for a file either service started with.
- **URLs.** `resourceServer.resource`, `resourceServer.issuer`,
  `registry.baseUrl`, `exchange.tokenEndpoint`, `service.reviewBaseUrl`,
  `publicOrigin`, `signIn.issuer`, and the review page's `registry.baseUrl`
  are the shared URL type: an absolute `http` or `https` URL with a host, no
  user information, and at most 2048 characters. Plain `http` is still
  accepted only on a loopback host under `listener.tlsTermination:
  development-loopback`, and an endpoint still carries no query or fragment.
  Migration: none for a file either service started with, unless a URL is
  longer than 2048 characters.
- **Local identifiers (narrowed).** `registry.accessProfile`,
  `service.details.entity`, `service.application.entity`, `targetField`, and
  `ownerField` in `breg-mcp`, and `registry.entity`, `targetField`, and
  `accessProfile` in `breg-review`, are local identifiers: a lowercase
  letter, then up to 63 lowercase letters, digits, `_`, or `-`, the grammar
  the Base Registry Engine itself gives them. A dot, an uppercase letter, or
  a name longer than 64 characters is now refused. Migration: write the name
  exactly as the registry project declares it; a name the registry accepts
  already fits.
- **External identifiers (loosened).** `resourceServer.allowedClients`,
  `resourceServer.scopeClaim`, `exchange.clientId`, and
  `exchange.assertionAudience` in `breg-mcp`, and `signIn.clientId` in
  `breg-review`, are external identifiers: 1 to 512 characters with no
  control character, written exactly as the issuer gives them. They were a
  whitespace-free token (`breg-mcp`) or visible ASCII up to 256 bytes
  (`breg-review`). Migration: none.
- **Service text.** `service.name`, `service.description`, and
  `service.disclosure` are 1 to 4096 characters and not blank; the bound was
  4096 bytes. Migration: none.
- **Lists.** `resourceServer.algorithms`, `resourceServer.allowedClients`,
  `resourceServer.requiredScopes`, and `registry.scopes` in `breg-mcp` hold 1
  to 128 items, and `signIn.scopes` in `breg-review` 1 to 16. An empty list
  was already refused; a repeated item is now refused as
  `config.duplicate-item` at the repeat. Migration: delete the repeated item.
- **Integers.** Every integer member states its minimum and maximum in the
  published schema and is refused outside them as `config.out-of-range`.
  Beyond the bounds in the renaming table, `breg-mcp`'s
  `rateLimits.perCitizen` and `rateLimits.perClient` rates are bounded 1 to
  1000000 (they were any positive number). The review page's session store
  sizes and lifetimes keep their previous ranges, now stated by the schema.
  Migration: lower a value above its maximum.

### BREAKING: `check` reads its file offline and reports in the shared shape
<!-- upgrade: no-file -->

`breg-mcp --runtime-config FILE check` and `breg-review --runtime-config
FILE check` are the offline checks for their runtime files.

- **No secret, socket, or audit file.** `check` reads no secret, opens no
  network connection, and opens no audit file. It used to resolve every
  secret the file named (and `breg-review check` used to confirm the audit
  directory was writable). Those faults are now refused only by `serve`,
  before it binds its listener, as before. Migration: a deployment step that
  relied on `check` to catch a missing or unsafe secret file, or an
  unwritable audit directory, must rely on `serve` refusing to start, or
  check those files itself. A `check` run in a container needs only the
  runtime file mounted.
- **Environment expressions.** Without options, `check` checks each
  `${NAME}` expression by its syntax and position only. `--environment`
  substitutes every expression from the current environment and checks every
  value, as `check` used to. Migration: add `--environment` to a `check` run
  that should judge substituted values.
- **Output.** The human report is the shared one: `error[CODE]
  FILE:LINE:COLUMN /path`, the message, a `next:` line, and a closing count
  of errors and warnings. It goes to standard output when the file is
  accepted and to standard error, after one line naming the command, when it
  is refused. `--format json` writes one report object to standard output:
  `apiVersion: id.registrystack.org/formats/breg/mcp-ctl-report/v1alpha1`
  with `kind: BRegMcpCtlReport` for the gateway, and
  `apiVersion: id.registrystack.org/formats/breg/review-ctl-report/v1alpha1`
  with `kind: BRegReviewCtlReport` for the review page. The previous `check`
  wrote its verdict as a JSON log line on standard output, and `breg-review`
  wrote a refusal as a `breg-review:` line on standard error. Migration: a
  script that parsed either reads `--format json` instead.
- **Exit status.** 0 accepted, 1 refused (or a warning under
  `--deny-warnings`), 2 a usage error, and 3 when the file cannot be read.
  `check` used to exit 1 for a refused file and an unreadable one alike.
  Migration: a script that treated any non-zero status as a refused file
  keeps working; one that needs to tell an unreadable file apart matches 3.
- **Every finding at once.** `check` reports every finding in the file, each
  at its own member, where each service's own rules stopped at the first
  refusal.
- **`serve`.** `serve` prints a refused runtime file's diagnostics on
  standard error, after a line naming the service, and exits 1. `breg-mcp`
  used to write that refusal as an `ERROR` JSON line on standard output.
  Other startup failures keep their previous channel. Migration: collect
  standard error for both services.
- **Rust API.** `registry_breg_mcp::runtime::check` and
  `registry_breg_review::check` are removed; `check::run` in each crate is
  the offline check. Each crate's `RuntimeConfigError` is a struct carrying
  the shared `diagnostics`, where it was an enum of refusals.

### Runtime file diagnostic codes

The previous refusals carried no code of their own: each was a sentence that
named a dotted member. The new code and JSON Pointer path for each, with
`breg.mcp-runtime.` and `breg.review-runtime.` abbreviated as `mcp.` and
`review.` in the first column of each table below.

`breg-mcp`:

| Previous refusal | New code | New path |
|---|---|---|
| the listener must bind a loopback or private address for its tlsTermination and networkExposure | `mcp.public-bind` | `/listener/bind` |
| FIELD must be an https URL without credentials, query, or fragment | `mcp.plain-http-endpoint` (plain `http` off loopback or outside `development-loopback`), `mcp.endpoint-query-or-fragment`, or `config.invalid-value` (not a URL, or with user information) | the member |
| resourceServer.resource must name the /mcp endpoint | `mcp.resource-not-mcp-endpoint` | `/resourceServer/resource` |
| FIELD must not be empty | `config.invalid-length` (a list) or `config.invalid-value` (text) | the member |
| FIELD is longer than this gateway accepts | `config.invalid-length` (a list) or `config.invalid-value` (text) | the member, or the item |
| FIELD holds a value that is not a single token | `config.invalid-value` | the member, or the item |
| FIELD holds a value that is not an RFC 6749 scope token | `config.invalid-value` | the item, such as `/registry/scopes/0` |
| FIELD must be an absolute URI without a fragment or credentials | `config.invalid-value` | `/registry/audience` |
| FIELD must be greater than zero | `config.out-of-range` | the member |
| the gateway's own exchange client may not be an accepted inbound client | `mcp.exchange-client-admitted-inbound` | `/exchange/clientId` |
| the registry audience must differ from the gateway's own resource | `mcp.audience-reused` | `/registry/audience` |
| service.reviewBaseUrl must be the review page's publicOrigin, with no path | `mcp.review-base-url-not-origin` | `/service/reviewBaseUrl` |
| service.application.ownerField must name a different field than targetField | `mcp.owner-field-is-target` | `/service/application/ownerField` |
| FIELD must be an absolute path | `mcp.relative-path` | the member |
| an audit destination refusal | `mcp.missing-audit-path` (`/audit`), `mcp.file-only-audit-member` (`/audit/path`, `/audit/rotateBytes`, or `/audit/retentionDays` under `destination: stdout`), `mcp.invalid-audit-path` (`/audit/path`), or `mcp.invalid-audit` | the member named |
| a secret provider or reference refusal | `mcp.no-secret-provider`, `mcp.invalid-secret-reference`, or `mcp.undeclared-secret-provider` | the member |
| a `resourceServer.jwksSource` URI refusal | `mcp.invalid-jwks-uri` | the member |
| any other shared block refusal | `mcp.invalid-block` | the member |
| the runtime configuration is not UTF-8 text | `yaml.not-utf8` | the file |
| the runtime file path could not be made absolute (`check` only) | `breg.mcp-check.runtime-unreadable`, exit 3 | the file |

`breg-review`:

| Previous refusal | New code | New path |
|---|---|---|
| secretProviders must explicitly enable file, environment, or both | `review.no-secret-provider` | `/secretProviders` |
| listener is not valid for its declared TLS termination and network exposure | `review.public-bind` | `/listener/bind` |
| publicOrigin must be an https origin with no path, query, or userinfo | `review.public-origin-not-origin` (a path), `review.plain-http-endpoint`, `review.endpoint-query-or-fragment`, or `config.invalid-value` (not a URL, or with user information) | `/publicOrigin` |
| signIn is invalid | `review.plain-http-endpoint` or `review.endpoint-query-or-fragment` (`/signIn/issuer`), `config.invalid-value` (`/signIn/clientId`, or a scope), `config.invalid-length` (`/signIn/scopes`), `config.duplicate-item` (the repeated scope), or `review.openid-scope` (the `openid` item) | the member or item under `/signIn` |
| registry is invalid | `review.plain-http-endpoint` or `review.endpoint-query-or-fragment` (`/registry/baseUrl`), or `config.invalid-value` (`/registry/resource`, `/registry/entity`, `/registry/targetField`, `/registry/accessProfile`) | the member under `/registry` |
| limits must admit at least one request per minute and a burst of at least one | `config.out-of-range` | `/rateLimits/perCitizen/requestsPerMinute` and the other rate members |
| session bounds are outside their accepted ranges | `config.out-of-range` | the member under `/session` |
| session.maximumPendingSignIns must hold every sign-in limits.globalSignIn admits | `review.pending-sign-ins-fillable`; the message names the formula, not the computed number | `/session/maximumPendingSignIns` |
| an audit destination refusal | `review.missing-audit-path`, `review.file-only-audit-member`, `review.invalid-audit-path`, or `review.invalid-audit` | the member named |
| a secret reference or shared block refusal | `review.invalid-secret-reference`, `review.undeclared-secret-provider`, `review.relative-path`, or `review.invalid-block` | the member |
| the runtime file path could not be made absolute (`check` only) | `breg.review-check.runtime-unreadable`, exit 3 | the file |

For both services, an unknown, removed, null, mistyped, or out-of-range
member, a refused envelope, and a refused `${NAME}` expression carry the
shared `config.*` and `yaml.*` codes at the member, and a runtime file that
cannot be read carries the shared `platform.runtime-config.*` code with exit
status 3.

### The runtime files have published schemas

Each runtime file has a JSON Schema generated from the types the service
reads, embedding the shared platform blocks unchanged:

- `breg-mcp`:
  `https://id.registrystack.org/schemas/breg/mcp-runtime/mcp-runtime.v1alpha1.schema.json`,
  committed as `products/breg/generated/mcp-runtime/mcp-runtime.schema.json`.
- `breg-review`:
  `https://id.registrystack.org/schemas/breg/review-runtime/review-runtime.v1alpha1.schema.json`,
  committed as `products/breg/generated/review-runtime/review-runtime.schema.json`.

A minimal example of each is under `products/breg/examples/mcp-runtime/` and
`products/breg/examples/review-runtime/`.
`python3 editors/configure.py breg-mcp DIRECTORY` and
`python3 editors/configure.py breg-review DIRECTORY` map the directory's
`runtime.yaml` to its schema and add an editor task that runs `check`.
