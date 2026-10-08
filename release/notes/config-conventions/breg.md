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
| an access profile `taskGrant.sourceIssuer` that is not an absolute `http` or `https` URL, such as `urn:casework:issuer` | refused at compile as `access_profile.task_grant.invalid` | `config.invalid-value` at `/accessProfiles/<index>/taskGrant/sourceIssuer` | Writing the Casework task authority's issuer as Casework states it, an `https` URL. An `http` issuer is still refused at compile as `access_profile.task_grant.invalid`. |

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

The compile-time codes stay for the conditions the reader cannot decide
alone: a string `minLength` above its `maxLength`, a decimal `scale` above
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
unprefixed. A refusal the runtime decides itself after the file is read keeps
its prefixed code (for example `verify.runtime_config.environment_identity_conflict`),
and the two whose path was `/`, `runtime_config.invalid_binding` and
`runtime_config.secret`, now report the root pointer `""`.

The runtime file may be up to 1 MiB, the shared bound every product's runtime
file carries (CFG-YAML-6), where it was 64 KiB. No reason was recorded for the
lower bound, and the file carries no inline documents. The separate bound on
the document after `${...}` substitution is gone: a substituted value is held
to the bound of the member it fills, and the environment is operator-held, as
the file is.
