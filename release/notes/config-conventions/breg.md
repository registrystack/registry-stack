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
