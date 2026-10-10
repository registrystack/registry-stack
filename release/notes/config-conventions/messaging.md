# Registry Messaging: configuration conventions

Every Registry Messaging change the configuration conventions make, with the
step that migrates a file or a script. Registry Messaging is experimental, so
each normalization lands in this release rather than with the move of the
promised formats to stable. The Messaging `CHANGELOG.md` points here.

v0.40.0 does not upgrade v0.39.0 state in place; apply to a new database.
Fresh installation creates the current schema directly. No schema step
converts or discards rows an earlier release wrote.

This fragment describes the final v0.40.0 interface. An `Old` or `Before`
example is a v0.39.0 file, request, response, or value to replace. Reauthor the
files, build the package with v0.40.0, and apply it to a new database;
v0.40.0 supports no in-place upgrade of a v0.39.0 Messaging database.
The database clean break does not require a new `audit.path`: the runtime
appends to the configured audit file, and retained v0.39.0 records keep their
old spellings.

## BREAKING: the runtime file's keys and apiVersion are renamed

The `messaging` runtime and every `messagingctl` command that reads a runtime
file (`check`, `plan`, `apply`, `status`, `messages`, and `retention
erase-expired`) refuse the old spellings; `messagingctl dev` writes its own
runtime file in the new spelling. Each old key is refused at its position
as `config.removed-key`, and the message names its replacement; the old
`apiVersion` is refused as `config.retired-api-version` with the new one.
Every value keeps its meaning unless the step below says otherwise.

A package the previous release built is refused too, and this release does
not upgrade `v0.39.0` state in place: apply the steps in this note to the
project and to the runtime file, build the package again with this release's
`messagingctl package` (it writes a new directory), point `package.root` at
it, run `messagingctl plan` and then `messagingctl apply` against a new
database, and only then start the runtime.

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

`authentication.oidc.jwksSource.kind` is not part of this step: it is the
shared OIDC block every Registry Stack runtime reads, and the section "Stable
move" renames it to `type`.

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

The `messaging.runtime.started`, `messaging.retention.requested`, and
`messaging.retention.erased` audit events, and the `messagingctl --format
json` reports that state the retention periods, name them `payloadRetentionDays`,
`recordRetentionDays`, and `submissionReceiptRetentionDays`, where they
named them `payloadDays`, `recordDays`, and `submissionReceiptDays`.
Migration: update audit queries, dashboards, and scripts that read the old
names. New v0.40.0 records use the new names; queries that span retained
v0.39.0 and v0.40.0 audit records must match both the old and new names.

## BREAKING: provider connection members are refused by the reader, at the member

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

## BREAKING: an optional member written as `null` is refused

The reader refuses an explicit `null` at its member with `config.null-value`
where it read `null` as the member left out. Migration: remove the key, in
`messaging.yaml` (`actorKind: null` becomes no `actorKind` key, and an
access profile without `actorKind` admits any actor kind), in
`template.yaml` and `provider.yaml`, and in `runtime.yaml`
(`metricsListener: null` becomes no `metricsListener` key, and a runtime
without one serves no metrics listener). Leaving a member out has the
meaning `null` had.

## BREAKING: `messagingctl check --project`, `package`, and the runtime report every finding at its file

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
  naming the bound: 1 MiB for `messaging.yaml`, `template.yaml`, and
  `provider.yaml`. A YAML file that is not UTF-8 is refused as
  `yaml.not-utf8` at its first invalid byte. Both were `config.refused`.
- The JSON report of a successful check carries `filesChecked` and a
  `diagnostics` list holding any warning; a refusal carries `filesChecked`
  too. `--deny-warnings` refuses a project or package check that reports a
  warning, as it already did for a runtime file.
- `messaging serve` prints the same report on standard error when it refuses
  its package.

## BREAKING: every `messagingctl --format json` report names its format

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

| Before | Now | Migration |
|---|---|---|
| `authentication.oidc.assertionIssuers: {}`, which applied no assertion-issuer rule | `config.invalid-value` at `/authentication/oidc/assertionIssuers` | Delete the member: omitting it applies no assertion-issuer rule. |

## BREAKING: a repeated `authentication.oidc.allowedClients` item is refused

| Before | Now | Migration |
|---|---|---|
| A client listed twice in `authentication.oidc.allowedClients` was accepted | `config.duplicate-item` at the second item, naming the first as a related position | List each client once. |

## BREAKING: a repeated key in `schema.json` or `sample.json` is refused

| Before | Now | Migration |
|---|---|---|
| An object key repeated in a template's `schema.json` or `sample.json` was accepted and the last value won | `messaging.template.schema-syntax` or `messaging.template.sample-syntax` at the line where the repeat is read | Keep one value for each key. |

## Protocol words

Every value Registry Messaging itself defines and writes outside the process
follows CFG-NAME-2, lowercase kebab-case. The message, dispatch, report, and
attempt words of the HTTP contract, the problem codes, the words Messaging
stores in its own columns, and the audit event names already did, and are
unchanged. The dispatch queue takes its job words from the shared dispatch
primitive, which respells four of them in this release. Messaging stores one
of the four in its job table; the other three are written to the audit
journal only.

### BREAKING: the `artifact` words of a refused `messagingctl --format json` report are kebab-case

A refused report names what each diagnostic is about in `artifact`. Eight of
those words were written with underscores:

| Old `artifact` | New `artifact` | Codes that carry it |
|---|---|---|
| `command_arguments` | `command-arguments` | `usage.invalid`, `messagingctl.activation.invalid-reference`, `retention.future-cutoff` |
| `package_output` | `package-output` | `package.refused` |
| `runtime_configuration` | `runtime-configuration` | `config.refused` |
| `template_data` | `template-data` | `data.unreadable`, `data.invalid` |
| `runtime_dependency` | `runtime-dependency` | `runtime.unavailable`, `output.failed`, and an operational failure without its own entry |
| `database_activation` | `database-activation` | the `messagingctl.activation.*` codes other than `invalid-reference` |
| `dev_session` | `dev-session` | `dev.refused`, `dev.failed`, `dev.interrupted` |
| `messaging_package` | `messaging-package` | a domain refusal without its own entry |

`filesystem`, `database`, `audit`, and `message` are unchanged, and a
diagnostic the shared reader places in a file keeps the `kind` of that file.
No alias is written or read. The codes, the exit codes, and human output are
unchanged.

Migration: a script that matches `artifact` matches the new word. Matching
`code` needs no change.

### BREAKING: the dispatch queue's job words are kebab-case

| Old | New | Where Messaging writes it |
|---|---|---|
| `dead_lettered` | `dead-lettered` | the `messaging_dispatch_jobs.state` column, and the `from` and `disposition` members of the `messaging.attempt.finished`, `messaging.dispatch.transition`, and `messaging.message.quarantined` audit records |
| `retry_pending` | `retry-pending` | the `disposition` member of the `messaging.attempt.finished` and `messaging.dispatch.transition` audit records |
| `replay_pending` | `replay-pending` | the `disposition` member of a `messaging.dispatch.transition` audit record whose `transition` is `replayed` |
| `lease_lapsed` | `lease-lapsed` | the `transition` member of the `messaging.dispatch.transition` audit record |

A message that exhausted its attempts, or was refused permanently, is held
in the job state `dead-lettered`. The HTTP contract and `messagingctl` report
that message as `failed`, as before: no request, response, or command output
changes. The old spellings are not read: this runtime refuses a job row
whose state is `dead_lettered`, and its retention would never erase one.

No schema version rewrites a stored job state: v0.40.0 does not upgrade
v0.39.0 state in place; apply to a new database. The schema `messagingctl
apply` creates names the new word in the two check constraints on the state
(`messaging_dispatch_jobs_state_values` and `messaging_dispatch_jobs_shape`)
and in the partial index retention reads terminal jobs through
(`messaging_dispatch_jobs_terminal_idx`), so the database refuses a write of
the old spelling.

The supported v0.40.0 path starts a new database, so queries of the job table
match the new spellings only. Migration: update every query, alert, or
dashboard that matches one of the four words. Audit queries that span retained
v0.39.0 and v0.40.0 records must match both the old and new spellings.

### BREAKING: five client error words are written in kebab-case

The Node.js and Python Messaging clients name a failure with fixed words a
caller branches on. Five of them carried an underscore (CFG-NAME-2): four
are the client's own, and the transport word comes from the shared HTTP
primitives, which respell it in this release.

| Member of `MessagingClientError` (Node.js, Python) | Old word | New word |
|---|---|---|
| `kind` | `invalid_request` | `invalid-request` |
| `protocolFailure`, `protocol_failure` | `header_bounds` | `header-bounds` |
| `protocolFailure`, `protocol_failure` | `trace_context` | `trace-context` |
| `protocolFailure`, `protocol_failure` | `media_type` | `media-type` |
| `transportKind`, `transport_kind` | `response_too_large` | `response-too-large` |

The other words of the three members are unchanged, and so is the Rust
client, whose errors are enum variants with no word of their own.
`@registrystack/client` and `registry-stack-client` carry the same words.

No file an adopter writes changes. To migrate, change what a consumer of a
client error compares each of these members with.

## BREAKING: Rust API

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

## Stable move

The changes below move promised spellings to the form the configuration
conventions give them. Each old spelling is refused with a diagnostic that
names its replacement; no release reads both.

### BREAKING: `authentication.oidc.jwksSource` is tagged by `type`

The shared OIDC key source block is a union tagged by `type` (CFG-ID-7),
where it was tagged by `kind`. The `messaging` runtime and every command
that reads a runtime file refuse `kind` under `jwksSource` as
`config.removed-key` at `/authentication/oidc/jwksSource/kind`, and the
message names `type`. The values and their members are unchanged.

| Old spelling | New spelling | Migration |
|---|---|---|
| `authentication.oidc.jwksSource.kind` | `authentication.oidc.jwksSource.type` | Rename the key; keep the value (`discovery`, `uri`, or `static`). |

`jwksSource: {kind: static, documentRef: secret:file/jwks}` becomes
`jwksSource: {type: static, documentRef: secret:file/jwks}`. A file that
omits `jwksSource` needs no change: the default is still `type: discovery`.
`messagingctl check --runtime-config FILE --project PROJECT` reports the old
key at its line and column.

### A client listed with no assertion issuer is refused by the reader

`authentication.oidc.assertionIssuers` in the runtime file already refused a
client written with an empty issuer list. The shared block now refuses it
when the file is read, so the code changes:

| Member | Code before | Code now |
|---|---|---|
| `/authentication/oidc/assertionIssuers/<client>` with `[]` | `messaging.runtime.empty-assertion-issuers` | `config.invalid-value` |

The pointer is unchanged, and the runtime schema declares `minItems: 1` on
the list. `messaging.runtime.empty-assertion-issuers` stays in the catalogue
for a configuration that is not read from a file.

Migration: no file changes. A script that matches the product code must
match `config.invalid-value`.

### BREAKING: `messagingctl plan` writes `databaseId: not-recorded`

The plan's `databaseId` comparison is the shared `DatabaseIdCheck` of
`registry-platform-activation`, which is written in kebab-case (CFG-NAME-2):
`notRecorded` becomes `not-recorded`. `matches` and `differs` are unchanged.

Migration: no file changes; a script that compares `notRecorded` compares
`not-recorded`.

### BREAKING: a client repeated in `allowedClients` is refused

`authentication.oidc.allowedClients` in the runtime file is read by the
shared block, which requires the member and reads its list as a set
(CFG-EMPTY-2, CFG-ID-6). Messaging already refused an omitted member and an
empty list; a repeated client was accepted.

| Written | Before | Now |
|---|---|---|
| `allowedClients: [a, b, a]` | only `a` and `b` admitted | refused, `config.duplicate-item` at `/authentication/oidc/allowedClients/2` |
| member omitted | refused, `messaging.runtime.allowed-clients-required` at `/authentication/oidc/allowedClients` | refused, `config.missing-key` at `/authentication/oidc` |
| `allowedClients: []` | refused, `messaging.runtime.allowed-clients-required` | refused, `config.invalid-value` at `/authentication/oidc/allowedClients` |
| `allowedClients: unrestricted` | refused by the reader, which took only a list | refused, `messaging.runtime.allowed-clients-required` at `/authentication/oidc/allowedClients` |
| `allowedClients: [a, b]` | only `a` and `b` admitted | unchanged |

The shared block accepts the keyword `unrestricted`, which the Casework and
Scheduling runtimes take on development loopback. Messaging accepts it in no
mode: an access profile resolves its caller from the matched client, so an
open client list reaches no profile. The runtime schema states the list with
`minItems: 1` and `uniqueItems: true`.

Migration: write a client that `allowedClients` repeats once, then run
`messagingctl check --runtime-config runtime.yaml`. A script that matches
`messaging.runtime.allowed-clients-required` for an omitted member or an
empty list must match `config.missing-key` or `config.invalid-value`.
