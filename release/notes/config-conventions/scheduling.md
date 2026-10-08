# Registry Scheduling: configuration conventions

Every Registry Scheduling change the configuration conventions make, with the
step that migrates a file or a script. Registry Scheduling is experimental, so
each normalization lands in this release rather than with the move of the
promised formats to stable. The Scheduling `CHANGELOG.md` points here.

The HTTP contract does not change. The public policy view, the appointment
and hold documents, and the Rust, Node.js, and Python clients keep
`maxRecipients`, `minutesBefore`, and `schedulingId`.

## BREAKING: the authored files are read by the shared configuration reader

`scheduling.yaml`, `records.yaml`, and every fixture are read through the
reader every Registry Stack product shares, wherever Scheduling reads them:
`schedulingctl check`, `explain`, `test`, `package`, and `records apply`, and
the `scheduling` runtime when it loads the packaged `scheduling.yaml`. The
runtime file was already read by the shared reader.

- Every problem in a file is reported, each as its own diagnostic with the
  file, line, and column where it was written, a JSON Pointer `path` into the
  file as written (`/offerings/0/because`), and a `next:` action. A check
  reported each finding as a `path` in dotted form (`offerings[0].because`)
  and a `reason`. Migration: read `source` for the position and `path` for
  the member; nothing in a file changes for this.
- Refused now, each at its position, where the file was read before:
  anchors, aliases, and merge keys (write the value in full where it is
  used); explicit tags such as `!!str` (quote the value instead); a number
  with a leading zero, a bare point, or a base prefix, and `.inf` or `.nan`
  (`yaml.ambiguous-number`: quote the value when it is text, or write a
  plain decimal); `null`, `~`, or an empty value after a key (remove the key
  to use the default, or write a value); a file larger than 1 MiB or nested
  deeper than 128 levels.
- `${NAME}` in `scheduling.yaml`, `records.yaml`, or a fixture is refused as
  `config.substitution-not-allowed` at its position; the fix names
  `runtime.yaml` as the place for deployment values.
- An empty list where a list restricts something is refused, because it
  would read as "no restriction": an offering's `requiresCapabilities` and
  `prerequisites`, a holiday set's `dates`, and a window's `subquotas`.
  Migration: remove the key. An empty `pools`, `exceptions`, or `initial` is
  accepted; the examples omit them.
- Every number has stated bounds, refused by the reader at the member as
  `config.out-of-range`: `holdPolicy.ttlMinutes` 1 to 1440,
  `holdPolicy.maximumPerCaller` at most the unit ceiling, `leadTimeMinutes` 1
  to the booking horizon in minutes, a pool's `reservedMembers` at most 256,
  a fixture party's `attendees` and `recipients` at most the unit ceiling,
  and a fixture case's `policyRevision` at least 1. For these members a value
  out of range was the finding `invalid-bound`.
- Identifiers are the shared local identifier: 1 to 64 characters, a
  lowercase letter, then lowercase letters, digits, `-`, or `_`. `_` is newly
  accepted.
- `schedulingctl check` and `test` read fixtures named `*.yml` as well as
  `*.yaml`.

## BREAKING: `scheduling.yaml` is a `SchedulingProject`

Each old spelling is refused at its position as `config.removed-key`, and
the message names its replacement; the old `apiVersion` is refused as
`config.retired-api-version` with the new one.

| Old spelling | New spelling | Migration |
|---|---|---|
| `apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1` | `apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1` | Replace the value. |
| `kind: SchedulingPolicyPackage` | `kind: SchedulingProject` | Replace the value. |
| `scheduling: {id, version}` with an integer `version` | `project: {id, version}` with a text `version` | Rename the key and quote the version: `version: 3` becomes `version: "3"`. |
| `offerings[].exactTime.maxRecipients` | `offerings[].exactTime.maximumRecipients` | Rename the key; keep the value. |
| `offerings[].reminders[].minutesBefore` | `offerings[].reminders[].offsetMinutes` | Rename the key; keep the value. |
| `holdPolicy.maxPerCaller` | `holdPolicy.maximumPerCaller` | Rename the key; keep the value. |
| `hooks[].handler.kind: url` | `hooks[].handler.type: url` | Rename the key; keep the value. |
| `channels` absent, serving every channel | `channels` required, with at least one channel | List every channel the deployment serves, such as `channels: [public, assisted]`. |

`channels` is now the whole list of channels a deployment serves: a hold or
an appointment on a channel outside it is refused as `request.unprocessable`.
An absent `channels` used to serve every channel in the vocabulary; it is now
refused as a missing key.

A hook is an `after` observer with a `url` handler, as before. A `when`
condition or a `principal` is now `config.unknown-key` at that member, and a
phase other than `after`, a trigger outside the three appointment events, or
a handler of another type is refused by the reader at `/hooks/N/phase`,
`/hooks/N/trigger`, or `/hooks/N/handler/type`. They were the findings
`unsupported-hook-condition`, `unsupported-hook-principal`,
`unsupported-hook-phase`, `unsupported-hook-trigger`, and
`unsupported-hook-abi`. Migration: none for a project that passed its check;
each of these was already refused.

The editor schema is published at
`https://id.registrystack.org/schemas/scheduling/project/project.v1alpha1.schema.json`.
`schedulingctl init` writes `# yaml-language-server: $schema=...` as the
first line of every file it creates, and
`python3 editors/configure.py scheduling PROJECT` maps the project, records,
fixture, and runtime schemas for an editor.

## BREAKING: `records.yaml` and fixtures carry their own envelopes

| Old spelling | New spelling | Migration |
|---|---|---|
| `records.yaml` without an envelope | `apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1` and `kind: SchedulingRecords` | Add both lines at the top of the file. |
| fixture `apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1` | `apiVersion: id.registrystack.org/formats/scheduling/fixture/v1alpha1` | Replace the value. |
| `unitsPolicy.kind: fixed`, `perRecipient`, or `bandedTable` | `unitsPolicy.type: fixed`, `per-recipient`, or `banded-table` | Rename the key and write the value in kebab case. |
| `unitsPolicy.input: serviceRecipientCount` | `unitsPolicy.input: service-recipient-count` | Write the value in kebab case. |
| `unitsPolicy.aboveHighestBand.policy` | `unitsPolicy.aboveHighestBand.type` | Rename the key; keep the value (`refuse` or `units`). |
| fixture `cases[].expect.outcome` | `cases[].expect.type` | Rename the key; keep the value (`admitted` or `refused`). |
| fixture `cases[].request.policyRevision` equal to the integer `scheduling.version` | `policyRevision: 1` | Replay runs every case at policy revision 1, because the project version is text. Write `1`; another revision exercises the `policy.changed` refusal. |

The `unitsPolicy` renames apply to a window in `records.yaml` and to a
window under a fixture's `facts`. The editor schemas are published at
`https://id.registrystack.org/schemas/scheduling/records/records.v1alpha1.schema.json`
and
`https://id.registrystack.org/schemas/scheduling/fixture/fixture.v1alpha1.schema.json`.

`records apply` reads `records.yaml` with the same reader and checks it
against the policy the runtime file binds before anything opens, so a
refusal names the file, line, column, and member. An expected code a
fixture names that is not a Scheduling problem code is refused at
`/cases/N/expect/code`.

## BREAKING: the runtime file's keys and apiVersion are renamed

The `scheduling` runtime and every `schedulingctl` command that reads a
runtime file (`check --runtime-config`, `plan`, `apply`, `status`, `records
apply`, and `intents`) refuse the old spellings at their positions, naming
the replacement.

| Old spelling | New spelling | Migration |
|---|---|---|
| `apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1` | Replace the value. |
| `audit.retainDays` | `audit.retentionDays` | Rename the key; keep the value (1 to 36500). |
| `retention.attemptReceiptDays` | `retention.attemptReceiptRetentionDays` | Rename the key; keep the value (1 to 65535). |
| `retention.hookPayloadDays` | `retention.hookPayloadRetentionDays` | Rename the key; keep the value (1 to 30). |

An explicit `null` is refused at its member where leaving the member out
loads its default. Migration: remove the key (`reminders: null` becomes no
`reminders` key). The two retention periods, a hook destination's
`attemptTimeoutMilliseconds` (100 to 10000) and `maximumAttempts` (1 to 20),
and the number of hook destinations (at most 128) are refused by the reader
at the member, where they were refused after the read at `retention` or
`destinations.hooks`.

The editor schema for the runtime file is published at
`https://id.registrystack.org/schemas/scheduling/runtime/runtime.v1alpha1.schema.json`.

## BREAKING: runtime refusals carry their own codes and JSON Pointers

`scheduling serve` prints `scheduling: the Scheduling runtime configuration
was refused` and then every rule the runtime file breaks, in the shared
report form on standard error: `error[CODE] FILE:LINE:COLUMN /path`, the
message, a `next:` line, and a closing count. When the packaged
`scheduling.yaml` is refused, it prints that file's own diagnostics at their
positions in it. `schedulingctl` prints the same report on standard error,
or in its JSON report under `--format json`, where it reported each of these
as one `schedulingctl.runtime-configuration.invalid` diagnostic at
`runtime.yaml` with the message in one sentence. A runtime file that cannot
be read at all exits 3.

| Old path | New code | New path |
|---|---|---|
| `apiVersion` | `config.retired-api-version`, `config.unsupported-api-version`, or `config.wrong-kind` | `/apiVersion` or `/kind` |
| `identity.databaseId` (absent) | `scheduling.runtime.missing-identity` | `/identity` |
| `identity.databaseId` | `scheduling.runtime.invalid-database-id` | `/identity/databaseId` |
| the dotted path of an operated path | `scheduling.runtime.relative-path` | the member |
| `listener` | `scheduling.runtime.invalid-listener` | `/listener/bind` |
| `authentication.oidc` (a claim name) | `scheduling.runtime.invalid-oidc-claim` | the claim member, such as `/authentication/oidc/scopeClaim` |
| `authentication.oidc` (no allowed clients) | `scheduling.runtime.allowed-clients-required` | `/authentication/oidc/allowedClients` |
| `database` | `scheduling.runtime.invalid-database-reference` | `/database` |
| `database` (plaintext) | `scheduling.runtime.plaintext-database` | `/database/testOnlyPlaintext` |
| `audit`, `audit.path`, `audit.rotateBytes`, `audit.retainDays` | `scheduling.runtime.invalid-audit` | `/audit`, `/audit/path`, `/audit/rotateBytes`, or `/audit/retentionDays` |
| `retention` | `config.out-of-range` | `/retention/attemptReceiptRetentionDays` or `/retention/hookPayloadRetentionDays` |
| `destinations.reminders.url`, or `destinations.hooks` for a hook URL | `scheduling.runtime.invalid-destination-url` | `/destinations/reminders/url` or `/destinations/hooks/<id>/url` |
| `destinations.hooks` (a destination the policy names is unbound) | `scheduling.runtime.unbound-hook-destination` | `/destinations/hooks` |
| `destinations.hooks` (the number of bindings, a timeout, or an attempt count) | a shared `config.*` code | the member |
| a secret reference or another shared block member | `scheduling.runtime.empty-value`, `scheduling.runtime.invalid-digest`, `scheduling.runtime.invalid-uri`, `scheduling.runtime.invalid-audience`, `scheduling.runtime.invalid-assertion-issuers`, `scheduling.runtime.invalid-secret-reference`, `scheduling.runtime.secret-provider-disabled`, or `scheduling.runtime.no-secret-provider` | the member, such as `/destinations/hooks/<id>/hmacSha256KeyRef` |

A refusal of the package `package.root` names, or of a dependency the
runtime reaches at startup, has no position in the runtime file. It prints
its message as before, and `schedulingctl` still reports it as
`schedulingctl.runtime-configuration.invalid`; a Rust caller reads its code
and pointer from the error:

| Refusal | Code | Path |
|---|---|---|
| `package.expectedDigest` does not match | `scheduling.package.digest-mismatch` | `/package/expectedDigest` |
| the package is not one `schedulingctl package` wrote | `scheduling.package.invalid` | `/package/root` |
| the package holds files beyond its sums | `scheduling.package.unexpected-contents` | `/package/root` |
| the package holds the retired `scheduling.package.json` | `scheduling.package.retired-manifest` | `/package/root` |
| `scheduling.yaml` changed after verification | `scheduling.package.file-changed` | `/package/root` |
| `scheduling.yaml` could not be read | `scheduling.package.unreadable-project` | `/package/root` |
| `scheduling.yaml` is refused | `scheduling.package.invalid-project`, printed as the project's own diagnostics | `/package/root` |
| the OIDC issuer or mounted JWKS could not be initialized | `scheduling.runtime-dependency.unavailable` | `/authentication/oidc` |
| the static OIDC signing keys could not be read | `scheduling.runtime.unreadable-jwks-secret` | `/authentication/oidc/jwksSource/documentRef` |

## BREAKING: `authentication.oidc.assertionIssuers: {}` is refused

| Before | Now | Migration |
|---|---|---|
| `authentication.oidc.assertionIssuers: {}`, which applied no assertion-issuer rule | `config.invalid-value` at `/authentication/oidc/assertionIssuers` | Delete the member: omitting it applies no assertion-issuer rule. |

## BREAKING: Rust API

`registry-scheduling`:

- `RuntimeConfigError::path`, which returned a dotted path, is removed. Use
  `RuntimeConfigError::pointer`, which returns a JSON Pointer, with
  `RuntimeConfigError::code`, `RuntimeConfigError::suggested_action`, and
  `RuntimeConfigError::in_file`, which tells a rule the file breaks from a
  refusal of the package or a dependency. `config::startup_report` turns a
  refusal into the positioned report `scheduling serve` prints, and
  `config::check_runtime` checks a runtime file offline.
- `InvalidEnvelope` is split into `InvalidApiVersion` and `InvalidKind`,
  `InvalidIdentity` is `InvalidDatabaseId`, `InvalidOidc` is split into
  `InvalidOidcClaim` and `AllowedClientsRequired`, `InvalidDestination` is
  `InvalidDestinationUrl`, and `PolicyRead` is `PolicyUnreadable`.
  `PolicyParse`, `PolicyFindings`, and `PolicyEnvironmentExpression` are
  `Policy`, which carries the project's report. `InvalidRetention` and
  `InvalidHookDestination` are removed, because the reader refuses those
  members, and `BindingSecret` is new: a secret reference under a hook
  binding, located by its pointer.
- `RetentionConfig::attempt_receipt_days` and `hook_payload_days` are
  `attempt_receipt_retention_days` and `hook_payload_retention_days`, now
  `u32`. `DEFAULT_ATTEMPT_RECEIPT_DAYS` and `MAX_HOOK_PAYLOAD_DAYS` are
  `DEFAULT_ATTEMPT_RECEIPT_RETENTION_DAYS` and
  `MAX_HOOK_PAYLOAD_RETENTION_DAYS`, now `u32`, beside the new
  `MAX_ATTEMPT_RECEIPT_RETENTION_DAYS`.

`registry-scheduling-core`:

- `parse_policy_yaml` and `parse_fixture_yaml` are removed. Use
  `SchedulingPolicy::read`, `SchedulingRecords::read`, and
  `SchedulingFixture::read`, which return the reader's positioned report.
- `PolicyIdentity` is the shared `ProjectIdentity` at
  `SchedulingPolicy::project`, with a text `version`.
- `HookPolicy` was an alias of the shared hook declaration; it is now
  Scheduling's own closed observer type, turned into the shared declaration
  by `SchedulingPolicy::hook_declarations`.

## BREAKING: `schedulingctl check`, `test`, and their reports

- A finding is an error: `check` exits 1 when it reports one, where a
  finding that was not a malformed value exited 0 with `status: incomplete`.
  `test` refuses the same project instead of replaying it. `--deny-findings`
  is removed (a usage error, exit 2); `--deny-warnings` refuses a check that
  reports a warning. Migration: drop `--deny-findings`; a script that read
  `status: incomplete` or `invalid` reads the exit status.
- The JSON report carries `diagnostics`, in the shared diagnostic shape, and
  `filesChecked`, where it carried `findings` (`{path, reason}`) and, for
  `test`, `authoringStatus`. A refused check writes `ok: false`, `status:
  "domain-refusal"`, and every diagnostic, where it wrote one
  `schedulingctl.check.refused` or `schedulingctl.test.refused` diagnostic;
  both codes are retired. Migration: match the exit status or the diagnostic
  `code`, which is `scheduling.<area>.<condition>` with the area `project`,
  `records`, or `fixture` (the old `reason` with its area, such as
  `scheduling.project.invalid-because`), or a shared `config.*` or `yaml.*`
  code. The findings `empty-text`, `invalid-label`, `too-many-entries`,
  `unknown-location`, `unknown-pool`, `unknown-timezone`,
  `resource-in-many-pools`, `inverted-range`, `lead-time-beyond-horizon`, and
  `calendar-refused` are new: each names a rule that was enforced elsewhere
  or not at all.
- Every JSON report names its format with `apiVersion:
  id.registrystack.org/formats/scheduling/ctl-report/v1alpha1` and `kind:
  SchedulingCtlReport`, written after `ok`, `command`, and `status`.
  `products/scheduling/examples/formats/ctl-report.json` is the report
  `check` writes for the exact-time example.
- `effective.schedulingId` and `effective.schedulingVersion` are
  `effective.projectId` and `effective.projectVersion`, a string, and
  `effective.holdPolicy.maxPerCaller` is
  `effective.holdPolicy.maximumPerCaller`. `explain` names the project under
  `project`, where it used `scheduling`, and its offerings and windows carry
  the renamed members above. Migration: read the new names.
- The human report opens with `Authoring check passed.` and closes with
  `N errors, M warnings in K files`; a refusal prints the shared report on
  standard error. Migration: a script that parsed the human output reads
  `--format json` instead.
- `test` with no fixture exits 1 with `scheduling.fixture.none`, where it
  passed with no case run. Migration: add a fixture under `fixtures/`.
- New: `schedulingctl check PROJECT --runtime-config FILE` checks a runtime
  file the way startup reads it, against the project's policy, with no
  package, database, network, or secret material. `${NAME}` expressions are
  checked by their syntax and position unless `--environment` is given, which
  fills them from the current environment and checks every value. Exits: 0
  clean, 1 refused, 2 usage, 3 a file it needs could not be read.

## BREAKING: a database an earlier release wrote is not read

The active policy, published windows, and environment records are retained
in the database in the shape of the authored files, so a database an
earlier Scheduling release wrote holds the old member names. The runtime
refuses to read it: `the Scheduling database is not in the state this
runtime expects`. Migration: start from a new database, then run
`schedulingctl apply` and `schedulingctl records apply` with the migrated
files.
