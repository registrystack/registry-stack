# Registry Messaging: configuration conventions

Every Registry Messaging change the configuration conventions make, with the
step that migrates a file or a script. Registry Messaging is experimental, so
each normalization lands in this release rather than with the move of the
promised formats to stable. The Messaging `CHANGELOG.md` points here.

## BREAKING: the runtime file's keys and apiVersion are renamed
<!-- upgrade: messaging-runtime-keys -->

The `messaging` runtime and every `messagingctl` command that reads a runtime
file (`check`, `plan`, `apply`, `status`, `messages`, and `retention
erase-expired`) refuse the old spellings; `messagingctl dev` writes its own
runtime file in the new spelling. Each old key is refused at its position
as `config.removed-key`, and the message names its replacement; the old
`apiVersion` is refused as `config.retired-api-version` with the new one.
Every value keeps its meaning unless the step below says otherwise.

A package the previous release built is refused too, so upgrade in this
order: apply the steps in this note to the project and to the runtime file,
build the package again with this release's `messagingctl package` (it writes
a new directory), point `package.root` at it, run `messagingctl plan` and
then `messagingctl apply`, and only then start the runtime.

| Old spelling | New spelling | Migration |
|---|---|---|
| `apiVersion: registry.registrystack.org/messaging-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1` | Replace the value. |
| `retention.payloadDays` | `retention.payloadRetentionDays` | Rename the key; keep the value. |
| `retention.recordDays` | `retention.recordRetentionDays` | Rename the key; keep the value. |
| `retention.submissionReceiptDays` | `retention.submissionReceiptRetentionDays` | Rename the key; keep the value. |
| `audit.retainDays` | `audit.retentionDays` | Rename the key; keep the value. |
| `providers.<id>.kind` | `providers.<id>.type` | Rename the key; keep the value (`smtp` or `http`). |
| `providers.<id>.authentication.kind` | `providers.<id>.authentication.type` | Rename the key; keep the value. |
| `providers.<id>.callbackVerifier.kind` | `providers.<id>.callbackVerifier.type` | Rename the key; keep the value. |
| `providers.<id>.attemptTimeoutSeconds` (`smtp`) | `providers.<id>.attemptTimeoutMilliseconds` | Multiply by 1000: `attemptTimeoutSeconds: 10` becomes `attemptTimeoutMilliseconds: 10000`. The bound is unchanged, 1 to 60 seconds, now written 1000 to 60000; omitted, it is 30000. |
| `providers.<id>.timeoutMilliseconds` (`http`) | `providers.<id>.attemptTimeoutMilliseconds` | Rename the key; keep the value (1 to 10000). |
| `providers.<id>.concurrencyLimit` (`http`) | `providers.<id>.maximumConcurrentRequests` | Rename the key; keep the value (1 to 64, and at most the provider package's limit). |

`authentication.oidc.jwksSource.kind` keeps its spelling: it is the shared
OIDC block every Registry Stack runtime reads, not a Messaging member.

To find every old spelling in a file, run
`messagingctl check --runtime-config FILE --project PROJECT` (or with
`--package PACKAGE`). It reports a retired `apiVersion` alone; once that is
replaced, it reports each old key at its line and column with its
replacement, and the file is clean when the command exits 0.

The editor schema for the runtime file is published at
`https://id.registrystack.org/schemas/messaging/runtime/runtime.v1alpha1.schema.json`,
and `messagingctl init` writes
`# yaml-language-server: $schema=...` as the first line of
`runtime.example.yaml`.

## BREAKING: retention periods are named with the runtime file's keys everywhere
<!-- upgrade: no-file -->

The `messaging.runtime.started`, `messaging.retention.requested`, and
`messaging.retention.erased` audit events, and the `messagingctl --format
json` reports that state the retention periods, name them `payloadRetentionDays`,
`recordRetentionDays`, and `submissionReceiptRetentionDays`, where they
named them `payloadDays`, `recordDays`, and `submissionReceiptDays`.
Migration: update audit queries, dashboards, and scripts that read the old
names; events written before the upgrade keep the old names.

## BREAKING: provider connection members are refused by the reader, at the member
<!-- upgrade: already-wrong -->

An `http` connection's `attemptTimeoutMilliseconds` (1 to 10000),
`maximumResponseBytes` (1 to 1048576), and `maximumConcurrentRequests` (1 to
64) outside their bounds, and a callback verifier's malformed `header`, `url`,
or secret reference, are refused when the runtime file is read, at the
member's line and column, as `config.out-of-range` or `config.invalid-value`.
They were refused after the package was read, as `config.refused` at
`providers.<id>`. An OAuth client credential's `maximumCacheSeconds` or
`assumedLifetimeSeconds` outside 10 to 86400 is refused the same way, where it
was refused only when the runtime resolved the provider's credentials. The
callback verifier's `url` is the shared URL type in the narrower callback
shape: an `http` or `https` URL with a host and a path, and no credentials,
query, or fragment. Migration: none for a runtime file the runtime started
with; each of these files was already refused.

The OIDC block, the audit key block, and each provider connection are read
as the shared runtime blocks they are, so each unknown key in them is refused
at that key, where the first one was reported for the block. Migration: none;
those files were already refused.

## BREAKING: `messagingctl check --runtime-config` reports every refusal at its position
<!-- upgrade: no-file -->

- Each refusal is its own diagnostic with its own code (table below), a
  JSON Pointer `path` (`/package/expectedDigest`), and a `source` with the
  file, line, and column, where every refusal was `config.refused` at a
  dotted path (`package.expectedDigest`). Migration: a script that matched
  `config.refused` matches the exit status (1 for a refused file, 3 when a
  file it names cannot be read) or the code; a script that matched a dotted
  path matches the JSON Pointer.
- The human output is the shared report: `error[CODE] FILE:LINE:COLUMN
  /path`, the message, a `next:` line, and a closing count of errors and
  warnings. Migration: a script that parsed the human output reads
  `--format json` instead.
- `messagingctl check --runtime-config FILE --project DIRECTORY` checks a
  runtime file against an editable project before any package is built, and
  `--package DIRECTORY` against a built package; without either, against the
  package `package.root` names. The check opens no database, no network
  connection, and no secret. `${NAME}` expressions are checked by their
  syntax and position unless `--environment` is given, which fills them from
  the current environment and checks every value. `--deny-warnings` refuses
  the check when it reports a warning. Exits: 0 clean, 1 refused, 2 usage,
  3 a file it needs could not be read.
- `package.expectedDigest` that does not pin the package now names only the
  digest computed from the package at `package.root`, never the pinned value
  as written. Migration: set `package.expectedDigest` to the digest
  `messagingctl package` reported, or remove it.
- `messaging serve` prints the same positioned report on standard error when
  it refuses its runtime file.
- `registry-messaging` (Rust): `RuntimeConfigError::path` is removed. Use
  `RuntimeConfigError::pointer`, which returns a JSON Pointer, and
  `RuntimeConfigError::code` for the diagnostic code.

### Runtime file diagnostic codes

Every refusal below was `config.refused`, at the dotted path in the first
column. The new path is a JSON Pointer; `<id>`, `<name>`, and `<client>` are
the local identifiers the file declares.

| Old path | New code | New path |
|---|---|---|
| `identity.databaseId` (absent) | `messaging.runtime.missing-identity` | `/identity` |
| `identity.databaseId` | `messaging.runtime.invalid-database-id` | `/identity/databaseId` |
| `audit` | `messaging.runtime.invalid-audit` | the `/audit` member |
| the dotted path of an operated path | `messaging.runtime.relative-path` | the member |
| `secretProviders` | `messaging.runtime.unusable-secret-providers` | `/secretProviders` |
| `listener` | `messaging.runtime.invalid-listener` | `/listener` |
| `metricsListener.bind` | `messaging.runtime.invalid-metrics-listener` | `/metricsListener/bind` |
| `authentication.oidc` | `messaging.runtime.empty-scope-claim` | `/authentication/oidc/scopeClaim` |
| `authentication.oidc` | `messaging.runtime.allowed-clients-required` | `/authentication/oidc/allowedClients` |
| `authentication.oidc` | `messaging.runtime.empty-assertion-issuers` | `/authentication/oidc/assertionIssuers/<client>` |
| `authentication.oidc` | `messaging.runtime.assertion-issuer-client-not-allowed` | `/authentication/oidc/assertionIssuers/<client>` |
| `authentication.oidc` (discovery failed) | `messaging.runtime-dependency.unavailable` | `/authentication/oidc` |
| `authentication.oidc.jwksSource.documentRef` | `messaging.runtime.unreadable-jwks-secret` | `/authentication/oidc/jwksSource/documentRef` |
| `authentication.oidc.allowedClients` | `messaging.runtime.profile-client-not-allowed` | `/authentication/oidc/allowedClients` |
| `database` | `messaging.runtime.invalid-database-reference` | `/database` |
| `database` | `messaging.runtime.plaintext-database` | `/database/testOnlyPlaintext` |
| `retention` | `messaging.runtime.record-retention-shorter-than-payload` | `/retention/recordRetentionDays` |
| `retention` | `messaging.runtime.receipt-retention-longer-than-record` | `/retention/submissionReceiptRetentionDays` |
| `tlsTrustProfiles` | `messaging.runtime.too-many-tls-trust-profiles` | `/tlsTrustProfiles` |
| `tlsTrustProfiles.<name>` | `messaging.runtime.invalid-secret-reference`, `messaging.runtime.secret-provider-disabled`, or `messaging.runtime.no-secret-provider` | `/tlsTrustProfiles/<name>/bundleRef` |
| `providers.<id>` | `messaging.runtime.undeclared-provider` | `/providers/<id>` |
| `providers.<id>` | `messaging.runtime.provider-type-mismatch` | `/providers/<id>/type` |
| `providers.<id>` | `messaging.package.missing-provider-source` | `/providers/<id>` |
| `providers.<id>` | `messaging.runtime.undeclared-tls-trust-profile` | `/providers/<id>/tlsTrustProfile` |
| `providers.<id>` | `messaging.runtime.invalid-provider-connection` | the member of `/providers/<id>` the rule reads |
| `providers.<id>` | `messaging.runtime.invalid-secret-reference`, `messaging.runtime.secret-provider-disabled`, or `messaging.runtime.no-secret-provider` | the reference member under `/providers/<id>` |
| a shared block member | `messaging.runtime.empty-value`, `messaging.runtime.invalid-digest`, `messaging.runtime.invalid-uri`, `messaging.runtime.invalid-audience`, `messaging.runtime.invalid-assertion-issuers`, `messaging.runtime.invalid-secret-reference`, `messaging.runtime.secret-provider-disabled`, `messaging.runtime.no-secret-provider`, or `messaging.runtime.relative-path` | the member |
| `package.expectedDigest` | `messaging.package.digest-mismatch` | `/package/expectedDigest` |
| `package.root` or a file under it | `messaging.package.invalid` | `/package/root` |
| the member, for an unknown, removed, null, mistyped, or out-of-range member | the shared code: `config.unknown-key`, `config.removed-key`, `config.retired-api-version`, `config.null-value`, `config.out-of-range`, `config.invalid-value`, and the other `config.*` and `yaml.*` codes | the member |
| the file, exit 3, when the runtime file cannot be read | `platform.runtime-config.unavailable` | the file |

## BREAKING: the project, template, and provider files carry the shared envelope
<!-- upgrade: messaging-project-envelope, messaging-template-envelope, messaging-provider-envelope -->

`messaging.yaml`, every `templates/<id>/<version>/template.yaml`, and every
`providers/<id>/provider.yaml` are read by the shared reader under their own
envelope. `messagingctl check --project`, `messagingctl package`, and the
runtime refuse a file without it.

| File | Old first lines | New first lines | Migration |
|---|---|---|---|
| `messaging.yaml` | `apiVersion: registry.registrystack.org/messaging-package/v1alpha1`, `kind: MessagingPackage` | `apiVersion: id.registrystack.org/formats/messaging/project/v1alpha1`, `kind: MessagingProject`, and a `project` block with `id` and `version` | Replace both lines and add `project: {id: <local id>, version: "<label>"}`; quote a numeric version. |
| `template.yaml` | none | `apiVersion: id.registrystack.org/formats/messaging/template/v1alpha1`, `kind: MessagingTemplate` | Add both lines at the top of every template version's file. |
| `provider.yaml` | none | `apiVersion: id.registrystack.org/formats/messaging/provider/v1alpha1`, `kind: MessagingProvider` | Add both lines at the top of every HTTP provider's file. |

An old `messaging.yaml` is refused as `config.wrong-kind` at `/kind`, naming
`MessagingProject`, and, in the same report, its old `apiVersion` is refused
as `config.retired-api-version`, naming the new envelope. A template
or provider file without an envelope is refused as `config.missing-envelope`,
whose next step names both lines. `project.id` is a local identifier (below)
and `project.version` a text label.

Each file may name its editor schema on its first line, as the starter does:
`# yaml-language-server: $schema=https://id.registrystack.org/schemas/messaging/project/project.v1alpha1.schema.json`,
and `.../messaging/template/template.v1alpha1.schema.json` and
`.../messaging/provider/provider.v1alpha1.schema.json` for the other two. The
schemas are generated into `products/messaging/generated/authoring/`.

The editor integrations and the language server recognize a Messaging
project by a `messaging.yaml` declaring `kind: MessagingProject` under the
new `apiVersion`. Migration: update the file, then reopen the folder or rerun
`python3 editors/configure.py messaging DIRECTORY`.

## BREAKING: three authored members are renamed
<!-- upgrade: messaging-project-renames, messaging-provider-capabilities -->

Each old key is refused at its position as `config.removed-key`, and the
message names its replacement. A required replacement that is absent is also
reported as `config.missing-key` at the parent.

| File | Old spelling | New spelling | Migration |
|---|---|---|---|
| `messaging.yaml` | `providers[].kind` | `providers[].type` | Rename the key; keep the value (`smtp` or `http`). |
| `messaging.yaml` | `accessProfiles[].dailyLimit` | `accessProfiles[].maximumMessagesPerDay` | Rename the key; keep the value (1 to 10000000). |
| `provider.yaml` | `capabilities.concurrencyLimit` | `capabilities.maximumConcurrentRequests` | Rename the key; keep the value (1 to 64). |

The `maximumMessagesPerDay` limit still counts over any 24 hours and still
answers `429 rate-limit.exceeded` past it; the
`messaging_limit_refusals_total` label is unchanged.

## BREAKING: authored members are typed and bounded when the file is read
<!-- upgrade: messaging-required-scopes, messaging-authored-bounds -->

Each member below is refused when the file is read, at its line and column,
with the shared code (`config.invalid-value`, `config.out-of-range`,
`config.duplicate-item`, `config.missing-key`, or another `config.*` code),
where some were refused later as one `config.refused` for the whole project
and others were not refused at all.

| Member | Rule now | Migration |
|---|---|---|
| Every `id` and reference in `messaging.yaml` (`providers[].id`, `senderProfiles[].id` and `.provider`, `templates[].id`, `accessProfiles[].id`, `.senderProfiles[]`, `.templates[]`), and `project.id` | A local identifier: a lowercase letter, then up to 63 lowercase letters, digits, underscores, or hyphens | Rename an identifier that starts with a digit, and every reference to it. An identifier was lowercase letters, digits, and hyphens, starting and ending with a letter or digit. |
| `accessProfiles[].requiredScopes` | Required: a list of at least one scope, each once, or `unrestricted` | A profile that omitted the member or listed none required no scope: write `requiredScopes: unrestricted` to keep that, or list the scopes. |
| `accessProfiles[].requesterClients` | A list of at least one client, each once | Remove a repeated client. |
| `accessProfiles[].senderProfiles`, `.templates` | Local identifiers, each once | Remove a repeated entry. |
| `accessProfiles[].requestsPerMinute` | 1 to 60000 | Lower a larger value. |
| `accessProfiles[].burst` | 1 to 10000 | Lower a larger value. |
| `accessProfiles[].maximumMessagesPerDay` | 1 to 10000000, when set | Lower a larger value, or omit the member for no daily bound. |
| `template.yaml` `locales` | 1 to 32 language tags, each once | Remove a repeated tag. |
| `template.yaml` `parts` | At least one part, each once | Remove a repeated part. |
| `provider.yaml` `capabilities.maximumConcurrentRequests` (1 to 64), `capabilities.ratePerSecond` (1 to 1000, when set), `request.headers` and `responseHeaders` (at most 16 lowercase header names a script may set or read, each once) | Unchanged rules, refused when the file is read where they were refused when the provider was assembled | None; such a file was already refused. |
| `provider.yaml` script paths (`prepareScript`, `interpretScript`, `receiptScript`) | A relative path of lowercase segments ending in `.rhai`, at most 256 bytes, no segment starting with `.` | Rename a script whose path has a segment starting with `.`, such as `.hidden.rhai`; only `.` and `..` segments were refused. |

The references between declarations (an unknown provider, sender profile, or
template; a requester client in two profiles; a sender profile that does not
fit its provider) are refused as before, now each as its own diagnostic at
the member, with a `messaging.project.*`, `messaging.template.*`, or
`messaging.provider.*` code. An item spelled `*` or `unrestricted` inside a
`requiredScopes`, `requesterClients`, `senderProfiles`, or `templates` list
is reported as the warning `messaging.project.wildcard-spelled-item`: a
list item grants only itself, so the spelling names no wildcard. Migration:
write `requiredScopes: unrestricted` without a list, or list the items
meant.

## BREAKING: `messagingctl check --project`, `package`, and the runtime report every finding at its file
<!-- upgrade: no-file -->

- A refused project or package prints the shared report, one diagnostic per
  finding, each with its code, JSON Pointer `path`, and a `source` naming the
  file, line, and column, where it printed one `config.refused` (or, for
  `check --project`, one `package.project-refused`) at the first problem.
  `package.project-refused` is removed. Migration: a script that matched
  `package.project-refused` or `config.refused` matches the exit status (1
  refused, 3 a file could not be read) or the codes above.
- A file the project cannot use for its layout (a symbolic link, an
  undeclared entry, a template file over 64 KiB that is not YAML, a file that
  is not UTF-8 outside the YAML files) remains one `config.refused`, now with
  `source.file` naming the file.
- A YAML file over its bound is refused as `yaml.too-large` at the file,
  naming the bound: 1 MiB for `messaging.yaml`, 64 KiB for `template.yaml`
  and `provider.yaml`. A YAML file that is not UTF-8 is refused as
  `yaml.not-utf8` at its first invalid byte. Both were `config.refused`.
- The JSON report of a successful check carries `filesChecked` and a
  `diagnostics` list holding any warning; a refusal carries `filesChecked`
  too. `--deny-warnings` refuses a project or package check that reports a
  warning, as it already did for a runtime file.
- `messaging serve` prints the same report on standard error when it refuses
  its package.

## BREAKING: every `messagingctl --format json` report names its format
<!-- upgrade: no-file -->

- Every JSON report names its format with `apiVersion` and `kind`, written
  after `ok`, `command`, and `status`:

  ```json
  "apiVersion": "id.registrystack.org/formats/messaging/ctl-report/v1alpha1",
  "kind": "MessagingCtlReport",
  ```

  A command cannot replace either member. A successful `preview` still prints
  the HTTP preview's body unwrapped, without them.
  `products/messaging/examples/formats/ctl-report.json` is the report
  `check --project products/messaging/examples/starter` writes. Migration: a
  script that compared the whole report, or its leading members, accepts the
  two new members; a script that reads members by name needs no change.

## BREAKING: the `check` and `package` reports name the project like the flag
<!-- upgrade: no-file -->

| Old member | New member | Migration |
|---|---|---|
| `package` (the directory `check` read) | `project` | Read `project`. |
| `packageDigest` (`check`, `package`) | `projectDigest` | Read `projectDigest`; the value is unchanged. |
| `packageFiles` (`check`, `package`) | `projectFiles` | Read `projectFiles`; the value is unchanged. |

The `plan`, `apply`, `status`, and `preview` reports keep `packageDigest`: it
names the package a runtime activated, as the HTTP contract does.
`products/messaging/examples/formats/ctl-report.json` shows the new members.
Human output is unchanged.

## BREAKING: `authentication.oidc.assertionIssuers: {}` is refused
<!-- upgrade: messaging-runtime-empty-assertion-issuers -->

| Before | Now | Migration |
|---|---|---|
| `authentication.oidc.assertionIssuers: {}`, which applied no assertion-issuer rule | `config.invalid-value` at `/authentication/oidc/assertionIssuers` | Delete the member: omitting it applies no assertion-issuer rule. |

## BREAKING: a repeated `authentication.oidc.allowedClients` item is refused
<!-- upgrade: messaging-duplicate-allowed-client -->

| Before | Now | Migration |
|---|---|---|
| A client listed twice in `authentication.oidc.allowedClients` was accepted | `config.duplicate-item` at the second item, naming the first as a related position | List each client once. |

## BREAKING: a repeated key in `schema.json` or `sample.json` is refused
<!-- upgrade: messaging-template-duplicate-key -->

| Before | Now | Migration |
|---|---|---|
| An object key repeated in a template's `schema.json` or `sample.json` was accepted and the last value won | `messaging.template.schema-syntax` or `messaging.template.sample-syntax` at the line where the repeat is read | Keep one value for each key. |

## BREAKING: Rust API
<!-- upgrade: no-file -->

- `registry-messaging-core`: `MessagingPackage` is `MessagingProject`, read
  with `MessagingProject::decode` through the shared reader;
  `MESSAGING_PACKAGE_API_VERSION` and `MESSAGING_PACKAGE_KIND` are
  `MESSAGING_PROJECT_API_VERSION` and `MESSAGING_PROJECT_KIND`, with
  `RETIRED_MESSAGING_PROJECT_API_VERSION`, `MESSAGING_TEMPLATE_*`, and
  `MESSAGING_PROVIDER_*` beside them. `AccessProfile::daily_limit` is
  `maximum_messages_per_day`, `ProviderDeclaration::kind` is read from
  `type`, and package checks return `MessagingFinding` values (with
  `FindingReason` and a `code()` of the form `messaging.<area>.<condition>`)
  where they returned text. The authored types no longer implement
  `Serialize`.
- `registry-messaging`: `PackageLoadReason::Authored`, `::Parse`, and
  `::Provider` are removed; a refused file is `PackageLoadReason::Refused`,
  whose report `PackageLoadError::report` returns. `LoadedPackage::warnings`
  returns the warnings a clean load found, and `RuntimeCheck::files_checked`
  the files a check read. `HttpProviderPackage` is read with
  `HttpProviderPackage::decode`, and its `capabilities.concurrency_limit` is
  `maximum_concurrent_requests`.
- `registry-messaging` no longer depends on `serde_norway` outside its tests,
  or on `serde_path_to_error`.

## A template or provider file may be 1 MiB

`template.yaml` and `provider.yaml` are read up to the shared YAML document
bound of 1 MiB. The package applied a 64 KiB bound to them before, which
refused a file the convention accepts. Locale text, `schema.json`, and
`sample.json` keep their 64 KiB bound. No migration step: a file that loaded
still loads.

## `messagingctl check` prints the verdict and summary lines

A passed `messagingctl check` ends with the shared summary line
(`0 errors, 0 warnings in 18 files`), and a refused one opens with
`messagingctl check refused the input.` and ends with the summary line.
Migration: a script that parsed the human output reads `--format json`.
