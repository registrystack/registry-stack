# Registry Messaging: configuration conventions

Every Registry Messaging change the configuration conventions make, with the
step that migrates a file or a script. Registry Messaging is experimental, so
each normalization lands in this release rather than with the move of the
promised formats to stable. The Messaging `CHANGELOG.md` points here.

## BREAKING: the runtime file's keys and apiVersion are renamed

The `messaging` runtime and every `messagingctl` command that reads a runtime
file (`check`, `plan`, `apply`, `status`, `messages`, and `retention
erase-expired`) refuse the old spellings; `messagingctl dev` writes its own
runtime file in the new spelling. Each old key is refused at its position
as `config.removed-key`, and the message names its replacement; the old
`apiVersion` is refused as `config.retired-api-version` with the new one.
Every value keeps its meaning unless the step below says otherwise.

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

The `messaging.runtime.started`, `messaging.retention.requested`, and
`messaging.retention.erased` audit events, and the `messagingctl --format
json` reports that state the retention periods, name them `payloadRetentionDays`,
`recordRetentionDays`, and `submissionReceiptRetentionDays`, where they
named them `payloadDays`, `recordDays`, and `submissionReceiptDays`.
Migration: update audit queries, dashboards, and scripts that read the old
names; events written before the upgrade keep the old names.

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
