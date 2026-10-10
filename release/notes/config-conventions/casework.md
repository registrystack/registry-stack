# Registry Casework: configuration conventions

Every Registry Casework change the configuration conventions make, with the
step that migrates a file or a script. The Casework `CHANGELOG.md` points here.

v0.40.0 does not upgrade v0.39.0 state in place; apply to a new database.
Fresh installation creates the current schema directly. No schema step
converts or discards rows an earlier release wrote.

This fragment describes the final v0.40.0 interface. An `Old` or `Before`
example is a v0.39.0 file, request, response, or value to replace. Reauthor the
files, build the package with v0.40.0, and apply it to a new database;
v0.40.0 supports no in-place upgrade of a v0.39.0 Casework database.
The database clean break does not require a new `audit.path`: the runtime
appends to the configured audit file, and retained v0.39.0 records keep their
old spellings.

## BREAKING: `casework.yaml` is read by the shared configuration reader

`caseworkctl` (every command that reads a project: `check`, `explain`,
`test`, `simulate`, `package`, `source add`, and `dev`) and the `casework`
runtime read `casework.yaml` through the reader every Registry Stack product
shares.

- Every problem a pass finds in the file is reported (see
  the "Read a diagnostic" section of the Configuration files reference), each as its own diagnostic with the
  file, line, and column where it was written, where the first problem was
  reported alone. `path` is a JSON pointer into the file as written
  (`/reviewProducers/0/recoveryDays`), where it was a file-prefixed path
  (`casework.yaml:/reviewProducers[0].recoveryDays`). The file is named in
  `source.file`, and a problem that involves a second place names it in
  `related`. Migration: read `source` for the position and `path` for the
  member; nothing in the file changes.
- `casework.project.invalid` is retired. Each problem now carries its own
  code, listed under "Diagnostic codes" below. Migration: a script that
  matched `casework.project.invalid` matches the exit status (1 for a refused
  project) or the code families `yaml.`, `config.`, and `casework.`.
- Refused now, each at its position, where the file was read before:
  `null`, `~`, or an empty value after a key in any member, which read as
  absent (remove the key to use the default, or write a value); anchors and
  aliases, which were expanded (write the value in full where it is used);
  explicit tags such as `!!str` (quote the value instead); a plain number or
  boolean where text is expected, which read as text (`version: 1.0` read as
  `"1.0"`; quote it: `version: "1.0"`); an integer with a base prefix, which
  read as its value (`0x1F` read as 31; write `31`); `.inf` and `.nan` where
  text is expected (quote them); a file larger than 1 MiB or nested deeper
  than 128 levels.
- A routing predicate can no longer compare a field with `null`
  (`equals: null`, or `null` inside `oneOf`). Migration: remove the predicate
  and let the request's fallback queue, or a later rule that does not test the
  field, take the case. A projected field the source leaves unset already
  falls through to the next rule.
- `${NAME}` anywhere in `casework.yaml` is refused as
  `config.substitution-not-allowed` at its position, in every member,
  whatever its type. The fix names `runtime.yaml` as the place for
  deployment values.
- When `casework serve` refuses the packaged `casework.yaml`, it prints
  `casework: the Casework project is invalid` and then the reader's lines on
  standard error, each in the form `error[CODE] FILE:LINE:COLUMN /path`, with
  the message and a `next:` line, and a closing count of errors and warnings.
- The `caseworkctl --format json` report schemas under
  `products/casework/contracts/cli/` describe the shared diagnostic shape:
  `artifact` is optional, and `source` (`file`, `line`, `column`) and
  `related` (`file`, `line`, `column`, `path`, `message`) are allowed.
  Migration: a consumer that validates reports against an older copy of these
  schemas takes the regenerated ones.

## BREAKING: `casework.yaml` has a schema, and the reader holds its bounds

`casework.yaml` has a published JSON Schema,
`https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json`,
generated from the reader types into
`products/casework/generated/project/project.schema.json`.
`caseworkctl init` copies it to `.casework/schemas/project.schema.json`
beside the runtime schema, and writes
`# yaml-language-server: $schema=./.casework/schemas/project.schema.json` as
the first line of `casework.yaml` (and the runtime schema's modeline as the
first line of `runtime.example.yaml`). `python3 editors/configure.py casework`
maps it for `casework.yaml`.

The reader now refuses, at its position, what the project check reported
after the read. Each of these files was already refused; what changes is the
code, the position, and that the read stops at the first such member.

- A number outside its bound is `config.out-of-range`:
  `reviewProducers[].recoveryDays` (1 to 3650),
  `reviewKinds[].retention.terminalDays` and `accountabilityDays` (1 to
  3650), `reviewKinds[].stages[].requiredApprovals` (1 to 32),
  `inbox.defaultPageSize` (1 to 100), `inbox.maximumCandidateScan` and
  `inbox.maximumSourceReads` (1 to 10000),
  `inbox.maximumConcurrentSourceReads` (1 to 32),
  `inbox.pageDeadlineMilliseconds` (100 to 30000), a clock's
  `after.workingDays`, `atRisk.workingDaysBefore`, and
  `reminders[].workingDaysBefore` (1 to 3650), and
  `taskTemplates[].lifetimeSeconds` (1 to 900). Migration: write a value
  within the bound.
- A repeated item in a list that is a set is `config.duplicate-item`, at the
  second occurrence: `calendars[].workingWeekdays`, a subject clock's
  `pauseWhile`, and `taskTemplates[].itemStates`. Migration: write each item
  once.
- `reviewProducers[].issuer`, `reviewProducers[].trustedInitiatorIssuer`,
  and `taskTemplates[].agent.issuer` must be absolute `http` or `https` URLs
  with a host and no user information, and are otherwise
  `config.invalid-value`. These issuers are compared with the issuer of a
  token the runtime accepted, which its OIDC configuration already requires
  to be such a URL, so a value that is not one never matched. Migration: write
  the issuer exactly as the token's `iss` claim carries it.

The project check keeps the old codes for a project built in code, which the
reader never sees; the table below gives the code a file now receives.

## BREAKING: `runtime.yaml` members are typed by the shared reader

The `casework` runtime and every `caseworkctl` command that reads
`runtime.yaml` (`plan`, `apply`, `status`, `doctor`, and `dev`) read its
secret references, URLs, digests, and bounded numbers through the shared
reader. A refused member is reported at its line and column, and the
diagnostic never repeats the value.

- A member written as `null`, `~`, or an empty value is refused, where it
  read as absent: `audit.path`, `audit.rotateBytes`, `audit.retainDays`,
  `package.expectedDigest`, `package.acknowledgeStrandedWork`, a review
  completion destination's `bearerTokenRef` or `auth.header`, and every other
  optional member. Migration: remove the key to take its default.
- A secret reference that is not `secret:env/NAME` or `secret:file/name` is
  `config.invalid-value` at its position, where it was refused after the read
  with the dotted path alone: `taskAuthority.signingKeyRef`, a review
  completion destination's `bearerTokenRef` and `auth.secretRef`, and a BReg
  binding's `clientIdRef`, `clientAssertionKeyRef`, `webhookSecretRef`, and
  `trustedRootCertificatesRef`. Migration: none for a file that started.
- `package.expectedDigest` and `package.acknowledgeStrandedWork` that are not
  `sha256:` followed by 64 lowercase hexadecimal digits are
  `config.invalid-value` at their position. Migration: none for a file that
  started.
- A BReg binding's `connectTimeoutMilliseconds` and
  `requestTimeoutMilliseconds` outside 1 to 300000, and its
  `reconciliationIntervalMilliseconds` outside 1000 to 3600000, are
  `config.out-of-range` at their position, where they were refused after the
  read. `audit.rotateBytes` outside 1048576 to 4294967295 and
  `audit.retainDays` outside 1 to 36500 are `config.out-of-range` at their
  position, where the audit writer refused them at startup. Migration: none
  for a file that started.
- A BReg binding's `baseUrl`, a review completion destination's `url`, and
  `taskAuthority.issuer` must be absolute `http` or `https` URLs with a host
  and no user information, and are otherwise `config.invalid-value`. Only
  `taskAuthority.issuer` accepted more before: any absolute URI. Migration:
  write `taskAuthority.issuer` as an absolute `https` URL.
- Two unknown keys inside `audit` or `authentication.oidc` are now both
  reported, each at its position, where the first was reported alone.
  Migration: none.

## BREAKING: a refused `runtime.yaml` is reported in full, and `caseworkctl check` reads it offline

The `casework` runtime and every `caseworkctl` command that reads
`runtime.yaml` report every problem a pass finds in the file, each at its line and
column, where they reported the first problem alone. The diagnostics never
repeat a value from the file.

- `casework serve` prints `casework: the Casework runtime configuration was
  refused` and then the reader's lines on standard error, each in the form
  `error[CODE] FILE:LINE:COLUMN /path` with the message and a `next:` line,
  in file order, and a closing count of errors and warnings. It printed one
  sentence naming the first problem. Migration: a log rule that matched
  `the Casework runtime configuration is invalid` or `is not valid YAML`
  matches the new sentence.
- `caseworkctl plan`, `apply`, `status`, `doctor`, and `dev` refuse the
  runtime file with one diagnostic per problem, each with its own code, a
  JSON pointer `path` into the file (`/listener/bind`), and the file as given
  in `source.file`. They reported one diagnostic with the code
  `casework.runtime-configuration.invalid` and a file-prefixed path
  (`runtime.yaml:/listener/bind`). A refusal that is not about the file's
  contents, such as a package that does not match its `SHA256SUMS`, keeps
  one diagnostic with a `runtime.yaml:/...` path, under its own
  `casework.package.*` code. Migration: match the exit status (1 for a
  refused file) or the code families `yaml.`, `config.`, `platform.`, and
  `casework.`, and read `source` for the position.
- A runtime file that cannot be read is
  `platform.runtime-config.unavailable` with exit status 3, where it was
  `caseworkctl.io-failure` with the same exit status. Migration: match the
  new code.
- `caseworkctl check PROJECT --runtime-config FILE` checks a runtime file
  offline against the authored project, as `casework serve` reads it,
  without the package, the database, the issuer, a source, or a secret. A
  `${NAME}` expression, and every rule that reads its value, is left
  unchecked; `--environment` fills the expressions from the current
  environment and checks the values they produce. A refusal lists the
  project's diagnostics and the runtime file's together. A passing check
  reports the file in `runtimeConfig` and adds its warnings to
  `diagnostics`. `CheckReport.schema.json` allows `runtimeConfig`.

| Old code | New code |
|---|---|
| `casework.runtime-configuration.invalid` for a problem in the file | the problem's own code: a reader code (`yaml.*`, `config.*`, `platform.runtime-config.*`) or a `casework.runtime.*` code listed below |
| `casework.runtime-configuration.invalid` for a package refusal | a `casework.package.*` code listed below |
| `caseworkctl.io-failure` for a runtime file that cannot be read | `platform.runtime-config.unavailable` |

Runtime file codes: `casework.runtime.allowed-clients-required`, `casework.runtime.empty-value`, `casework.runtime.inactive-review-source-namespace`, `casework.runtime.invalid-assertion-issuers`, `casework.runtime.invalid-audience`, `casework.runtime.invalid-audit`, `casework.runtime.invalid-database-id`, `casework.runtime.invalid-database-reference`, `casework.runtime.invalid-digest`, `casework.runtime.invalid-listener`, `casework.runtime.invalid-metrics-listener`, `casework.runtime.invalid-oidc-claim`, `casework.runtime.invalid-review-completion-auth`, `casework.runtime.invalid-review-completion-destination`, `casework.runtime.invalid-secret-reference`, `casework.runtime.invalid-source-binding`, `casework.runtime.invalid-stranded-work-acknowledgement`, `casework.runtime.invalid-task-authority`, `casework.runtime.invalid-uri`, `casework.runtime.missing-identity`, `casework.runtime.no-secret-provider`, `casework.runtime.plaintext-database`, `casework.runtime.principal-claim-conflict`, `casework.runtime.relative-path`, `casework.runtime.secret-provider-disabled`, `casework.runtime.source-bindings-mismatch`, `casework.runtime.unconfigured-review-completion-destination`, `casework.runtime.unreadable-jwks-secret`, `casework.runtime.unsupported-api-version`, `casework.runtime.wrong-kind`.

Package codes: `casework.package.digest-mismatch`, `casework.package.file-changed`, `casework.package.invalid`, `casework.package.invalid-project`, `casework.package.retired-manifest`, `casework.package.source-description-mismatch`, `casework.package.unexpected-contents`, `casework.package.unreadable-project`.

## BREAKING: `caseworkctl check` and `test` report diagnostics, and `--deny-warnings` replaces `--deny-findings`

`caseworkctl check` and `caseworkctl test` report what they find in the one
diagnostic shape every Registry Stack check command shares, and exit as every
check command does: 0 when no error was reported, warnings allowed, and 1
when the project was refused or, under `--deny-warnings`, when a warning was
reported.

- The `--format json` check and test reports carry `diagnostics`, where they
  carried `findings`. A passing report lists its warnings there, possibly
  none, and `filesChecked` counts the files the command read. The warnings
  include those the reader reports for `casework.yaml`, such as a deprecated
  `apiVersion`. Migration: read `diagnostics` where a script read
  `findings`.
- A source whose imported description file does not exist is a `warning`,
  where its severity was `finding`, and an `error` under `--production`. It
  is reported at the source's `description` value: `path` is the JSON
  pointer `/sources/0/description` and `source` names `casework.yaml` with
  its line and column, where `path` was `casework.yaml:/sources/0/description`.
  `artifact` is `CaseworkProject`, where it was `casework_project`. The
  message no longer repeats the source id; the `suggestedAction` names the
  `caseworkctl source add` command with `SOURCE_ID` and the pointer of the
  id to put there.
- `--deny-findings` is removed. `--deny-warnings` refuses the check with exit
  1 when it reports any warning, and the refusal lists every diagnostic.
  Migration: replace `--deny-findings` with `--deny-warnings`.
- Human output prints each diagnostic position first,
  `warning[casework.source-description.missing] FILE:LINE:COLUMN /sources/0/description`,
  then the message and a `next:` line, and ends with a count such as
  `0 errors, 1 warning in 1 file`. It printed
  `finding[CODE] casework.yaml:/sources/0/description: MESSAGE`. A passing
  check prints them on standard output after its outcome; a refusal prints
  them on standard error. Migration: a script that matched `finding[` matches
  `warning[`, or reads `--format json`.
- `CheckReport.schema.json` and `TestReport.schema.json` require
  `filesChecked` and `diagnostics` in place of `findings`, and every
  diagnostic in a passing report is a warning. Migration: a consumer that
  validates reports against an older copy of these schemas takes the
  regenerated ones.

| Old | New |
|---|---|
| `--deny-findings` | `--deny-warnings` |
| `findings` in the check and test reports | `diagnostics` |
| severity `finding` | `warning`, or `error` under `--production` |
| `path: casework.yaml:/sources/N/description` | `path: /sources/N/description`, with `source.file`, `source.line`, and `source.column` |
| `artifact: casework_project` | `artifact: CaseworkProject` |

## BREAKING: every project refusal against its source descriptions is placed in `casework.yaml`

`caseworkctl check`, `explain`, `simulate`, and `package` check a project
against the source descriptions it imported. Each problem they find is its
own diagnostic in the shared shape, placed at the line and column of
`casework.yaml` it concerns, where the first problem was reported alone as
`caseworkctl.refused` with `artifact: authoring_input` and `path:
authoring`.

- A source description that pins a review kind is named in `related`, with
  the pointer of its `review/policyId` in that file.
- A routing rule the source description rejects is reported with the
  `casework.routing.*` code of its condition, at the pointer of the rule
  (`/sources/0/requests/0/routing/0/when/fields/region`), where the message
  began `routing policy refused at`.
- A diagnostic names a review kind or a source only when its id is a valid
  identifier, and never repeats a revision or another value from the file;
  the position names the member instead. A `suggestedAction` that names
  `caseworkctl source add` for a source whose id it does not name writes
  `SOURCE_ID` and the pointer of the id to put there.
- The `--against-breg-package` refusals keep their codes.
  `casework.source.none`, `casework.source.ambiguous`, and
  `casework.source.unknown` are placed at `/sources`, where `path` was
  `arguments`; `casework.source-description.missing` and
  `casework.source-revision.stale` are placed at `/sources/N/description`,
  where `path` was `casework.yaml:/sources/N/description`. `artifact` is
  `CaseworkProject` for all five, where it was `command_arguments`,
  `casework_project`, or `source_description`. The stale refusal no longer
  repeats the pinned or the rederived revision; its `related` entry names
  the source description file and `/sourceRevision`.

Migration: a script that matched a refusal's message matches its `code`
and reads `source` for the position and `path` for the member. Nothing in a
project changes.

| Refusal | Old code and path | New code and path |
|---|---|---|
| a source whose `adapter` is not `breg` | `caseworkctl.refused`, `authoring` | `casework.source.unsupported-adapter`, `/sources/N/adapter` |
| a source with more than 32 requests | `caseworkctl.refused`, `authoring` | `casework.source.too-many-requests`, `/sources/N/requests` |
| a source description that does not match the BReg adapter contract | `caseworkctl.refused`, `authoring` | `casework.source-description.contract-mismatch`, `/sources/N/description` |
| a policy field the source description does not publish | `caseworkctl.refused`, `authoring` | `casework.source.unpublished-field`, the pointer of the field |
| a pinned review kind `reviewKinds` does not declare | `caseworkctl.refused`, `authoring` | `casework.source-description.unknown-review-kind`, `/sources/N/description` |
| a pinned review kind whose purpose is not `approval` | `caseworkctl.refused`, `authoring` | `casework.source-description.review-kind-not-approval`, `/reviewKinds/K/purpose` |
| a pinned review kind whose `contextStrategy` is not `source` | `caseworkctl.refused`, `authoring` | `casework.source-description.review-kind-not-source-context`, `/reviewKinds/K/contextStrategy` |
| no review producer admits the source for the pinned review kind | `caseworkctl.refused`, `authoring` | `casework.source-description.review-not-admitted`, `/sources/N/description` |
| a `displaySchema` that rejects what a source request discloses | `caseworkctl.refused`, `authoring` | `casework.review-kind.display-hides-disclosure`, `/reviewKinds/K/displaySchema` |
| a routing rule the source description rejects | `caseworkctl.refused`, `authoring` | the `casework.routing.*` code of its condition, the pointer of the rule |
| `--against-breg-package` with no, several, or an unknown BReg source | unchanged code, `arguments` | unchanged code, `/sources` |
| `--against-breg-package` with a missing or stale description | unchanged code, `casework.yaml:/sources/N/description` | unchanged code, `/sources/N/description` |

## BREAKING: fixtures, simulations, and holiday sets are read by the shared reader

`caseworkctl check`, `test`, and `simulate` read the files under
`fixtures/`, `simulations/`, and `simulations/holiday-sets/` through the
reader every Registry Stack product shares. Each format has a published JSON
Schema, generated from the reader types into
`products/casework/generated/{fixture,simulation,holiday-set}/`:
`https://id.registrystack.org/schemas/casework/fixture/fixture.v1alpha1.schema.json`,
`.../simulation/simulation.v1alpha1.schema.json`, and
`.../holiday-set/holiday-set.v1alpha1.schema.json`.
`python3 editors/configure.py casework` maps them for those directories.
Everything the `casework.yaml` reader refuses (null, anchors, tags, plain
numbers where text is expected, unknown keys) is refused in these files too,
each at its position.

A fixture changes spelling:

| Old | New |
|---|---|
| `apiVersion: registry.registrystack.org/casework-fixture/v1alpha1` | `apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1` |
| `name: X` | `id: X` |
| `source: {id: S, requestEntity: E, reviewStage: T}` | `request: {source: S, entity: E}`; `reviewStage` was never read and is removed |
| `expect.targetElapsed: PT48H` | `expect.target: {elapsedMinutes: 2880}` |
| `expect.targetElapsed:` (empty), or `expect.targetElapsed` omitted, meaning no target | `expect.target: none`; an absent `target` is no longer checked |

A simulation and a holiday set gain an envelope, and a simulation changes
spelling:

| Old | New |
|---|---|
| a simulation with no envelope | `apiVersion: id.registrystack.org/formats/casework/simulation/v1alpha1` and `kind: CaseworkSimulation` |
| a holiday set with no envelope | `apiVersion: id.registrystack.org/formats/casework/holiday-set/v1alpha1` and `kind: CaseworkHolidaySet` |
| a fixture file named `*.yml` | rename it to `*.yaml` first; the previous release did not run a `.yml` fixture, this release reads it and refuses the old spelling, and the automated spelling changes apply only to `.yaml` files |
| a simulation file named `*.yml` | rename it to `*.yaml` first; the automated spelling changes apply only to `.yaml` files |
| `subject.id` | `subject.recordId` |
| `expect.ruleId` | `expect.rule` |
| `expect.ruleId` absent, meaning no rule matches | `expect.rule: none`; an absent `rule` is no longer checked |
| `expect.dueState: atRisk` | `expect.dueState: at-risk` (`pending` and `due` are unchanged) |
| `pauseStartedAt: null`, `completedAt: null` | omit the member |
| `subject.fields.F: null` | omit `F`: routing reads a null field exactly as an absent one |
| a list or a mapping as a `subject.fields` value | a boolean, a number, or text |

The reader names the replacement for each old spelling at its position
(`config.removed-key`, `config.retired-api-version`). Other changes:

- Every member of a fixture's or a simulation's `expect` other than `queue`
  is optional, and one you leave out is not checked. `eligibleReminders`,
  `eligibleSteps`, and `outcomes` are compared as sets.
- A holiday-set file is named `<holidaySet>-<revision>.yaml` (`.yml` is not
  accepted for a holiday set),
  and a simulation finds the revision `holidayRevisions` pins by that name.
  A file whose name does not match its `holidaySet` and `revision` is
  `casework.holiday-set.misnamed`. Migration: rename the file.
- `caseworkctl check` reads every `.yaml` and `.yml` file directly under the
  three directories, counts each in `filesChecked`, and refuses, at its
  position: a fixture or simulation that names a source, request, review
  kind, or field `casework.yaml` does not declare; a fixture review display
  its kind's `displaySchema` rejects (`casework.fixture.display-mismatch`,
  with the schema's position in `related`); a simulation field the request
  does not project or the source description types otherwise; a missing
  pinned holiday set; a nested directory, link, or special file, which is
  never skipped silently; and a file of one format under another format's
  directory (`casework.project.misplaced-file`).
- `caseworkctl test` runs every fixture and every simulation, where it ran
  only fixtures and a simulation placed under `fixtures/`, and refuses a
  project with neither (`casework.test.no-fixtures`). Each expectation that
  does not hold is its own diagnostic at the `expect` member that states it,
  where the first failure was reported alone as `caseworkctl.refused`.
- `caseworkctl simulate --simulation FILE` reports the same diagnostics for the
  one simulation it reads.

Migration: rewrite each file as the tables above show; `caseworkctl check`
names each member to change. A script that matched a failure's message
matches its `code`.

| Failure | Old code | New code |
|---|---|---|
| a fixture or simulation that does not parse or has the wrong envelope | `caseworkctl.refused` | a reader code |
| a fixture reference `casework.yaml` does not declare | `caseworkctl.refused` | `casework.fixture.unknown-reference` |
| a fixture expectation that does not hold | `caseworkctl.refused` | `casework.fixture.expectation-not-met` |
| a fixture display the kind's schema rejects | `caseworkctl.refused` | `casework.fixture.display-mismatch` |
| a simulation reference `casework.yaml` does not declare | `caseworkctl.refused` | `casework.simulation.unknown-reference` |
| a simulation expectation that does not hold | `caseworkctl.refused` | `casework.simulation.expectation-not-met` |
| a missing pinned holiday set | `caseworkctl.refused` | `casework.simulation.missing-holiday-set` |
| a project with no fixture | `caseworkctl.refused` | `casework.test.no-fixtures` |

Offline file codes: `casework.fixture.display-mismatch`, `casework.fixture.display-too-large`, `casework.fixture.expectation-not-met`, `casework.fixture.no-subject`, `casework.fixture.request-expectation`, `casework.fixture.review-expectation`, `casework.fixture.two-subjects`, `casework.fixture.unknown-reference`, `casework.holiday-set.misnamed`, `casework.holiday-set.too-many-dates`, `casework.project.misplaced-file`, `casework.project.not-a-directory`, `casework.project.not-a-regular-file`, `casework.project.too-many-files`, `casework.project.unread-directory`, `casework.project.unreadable-file`, `casework.simulation.clock-expectation`, `casework.simulation.clock-failed`, `casework.simulation.clock-input`, `casework.simulation.expectation-not-met`, `casework.simulation.field-mismatch`, `casework.simulation.missing-holiday-set`, `casework.simulation.stage-mismatch`, `casework.simulation.unknown-field`, `casework.simulation.unknown-reference`, `casework.simulation.unprojected-field`, `casework.test.no-fixtures`.

## BREAKING: `caseworkctl simulate` names its file with `--simulation`

`caseworkctl simulate` reads one simulation, a `CaseworkSimulation` file, and
takes it as `--simulation FILE`, where the flag was `--fixture`. A fixture is
a different file kind, the one `caseworkctl test` runs beside the simulations.
There is no alias: `--fixture` is a usage error (exit 2). The file, the
report, and every other argument are unchanged.

| Old | New |
|---|---|
| `caseworkctl simulate PROJECT --fixture FILE` | `caseworkctl simulate PROJECT --simulation FILE` |

Migration: replace `--fixture` with `--simulation` in every script that runs
`caseworkctl simulate`.

## BREAKING: a project check reads a bounded number of files

- A project declares at most 64 sources. More is refused at `/sources` with
  `casework.source.too-many`. Migration: split the sources across Casework
  projects.
- `caseworkctl check` and `test` read at most 1024 YAML files from each of
  `fixtures/`, `simulations/`, and `simulations/holiday-sets/`. A directory
  holding more is refused with `casework.project.too-many-files`, and none
  of its files is read. Migration: remove files until no more than 1024
  remain.
- `filesChecked` in `CheckReport.schema.json` and `TestReport.schema.json`
  states its maximum, 3140: the project file, the runtime configuration,
  `dev-clients.yaml`, the development session state, 64 source
  descriptions, and 1024 files from each of the three directories.
  A `warning` in a report's `diagnostics` is a closed object. A consumer that
  validates reports takes the regenerated schemas.
- A checked request's `target` in `CheckReport.schema.json` is a closed
  object holding `id`, a local identifier, and `elapsed`, or null when the
  request declares no target. The report itself is unchanged.

## BREAKING: `source add` reports positioned warnings in `diagnostics`

`caseworkctl source add --format json` reports the warnings it used to
report as findings in the same `diagnostics` shape every other report uses.
Neither warning blocks the pairing, and their codes are unchanged:
`casework.source-add.review-policy-unresolved` and
`casework.source-add.row-boundary-claim-unsupported`.

| Before | After |
|---|---|
| `findings` | `diagnostics` |
| `severity: finding` | `severity: warning` |
| `path: registry.yaml:/entities/1/changeRequest/review/policyId` | `path: /entities/1/changeRequest/review/policyId`, with `source.file`, `source.line`, and `source.column` naming the BReg `registry.yaml` |
| `artifact: breg_entity` or `breg_access_profile` | removed; the code and the path name the member |
| a message naming the entity, policy, profile, or claims | a message naming no value; the path locates it |

- `source add` reads `casework.yaml` through the project reader, so a
  project `caseworkctl check` refuses is refused by `source add` with the
  same positioned diagnostics. Migration: run `caseworkctl check` and fix
  what it reports before pairing a source.
- A consumer that reads `findings` reads `diagnostics` instead and takes the
  regenerated `SourceAddReport.schema.json`. The `findings` definition is
  removed from every report schema.

## BREAKING: `dev-clients.yaml` is read by the shared reader

`dev-clients.yaml`, the local callers `caseworkctl dev` registers, carries
the format envelope, is read through the shared configuration reader, and is
checked by `caseworkctl check`.

- Replace `version: 1` with:

  ```yaml
  apiVersion: id.registrystack.org/formats/casework/dev-clients/v1alpha1
  kind: CaseworkDevClients
  ```

  A file that still carries `version` is refused with `config.removed-key`
  at `/version`.
- The schema is published at
  `products/casework/generated/dev-clients/dev-clients.schema.json` with
  `$id`
  `https://id.registrystack.org/schemas/casework/dev-clients/dev-clients.v1alpha1.schema.json`.
  `caseworkctl init` copies it to `.casework/schemas/dev-clients.schema.json`,
  names it in a modeline, and maps it in the project's VS Code settings, and
  `editors/configure.py casework` maps it for `dev-clients.yaml`. Migration
  for an existing project: copy the schema and add
  `# yaml-language-server: $schema=./.casework/schemas/dev-clients.schema.json`
  as the file's first line, or run `editors/configure.py`.
- `caseworkctl check` reads `dev-clients.yaml` when the project has one and
  reports a client bound to an undeclared profile, a missing required scope
  or claim, and a directory team on an unknown queue or with a member whose
  profile does not fit the role, each at the entry that causes it.
  `filesChecked` counts the file. A consumer that validates reports takes
  the regenerated `CheckReport.schema.json` and `TestReport.schema.json`.
  Checks that need a connected source's
  arguments still run at `caseworkctl dev`.
- `caseworkctl dev` reports every problem a pass finds in the file as a positioned
  diagnostic with its own code, where it reported the first problem alone as
  one sentence. No diagnostic repeats a client, claim, or scope value; the
  path locates it.
- A `${...}` expression is refused with `config.substitution-not-allowed`;
  the file takes literal text only. `null` is refused with
  `config.null-value`; omit the key instead.
- `integrations.taskAuthority.jwksPort` is refused outside 1 to 65535 with
  `config.out-of-range`.
- A client ID, a service client ID, and each key of `integrations.sources`,
  `integrations.secretFiles`, and `integrations.taskAuthority.statusClients`
  is a local identifier: a lowercase letter, then at most 63 lowercase
  letters, digits, `_`, or `-`. A leading digit is now refused and `_` is
  now accepted. The reader refuses any other spelling with
  `config.invalid-value`, where `caseworkctl dev` reported
  `casework.dev-clients.invalid-id` for a client ID; that code now covers
  `browserClients` alone. Migration: rename an ID that starts with a digit,
  and the references to it under `directory` and `statusClients`.
- A claim name is an external identifier of 1 to 512 characters without
  control characters, and a service client's claim value is text: a list or
  mapping value is refused with `config.invalid-value`. Migration: write the
  claim value as one string.
- `integrations.taskAuthority.issuer` is an absolute URL, refused otherwise
  with `config.invalid-value`; an `http` URL is still reported with
  `casework.dev-clients.invalid-task-authority-issuer`.
- A source binding under `integrations.sources` no longer takes
  `requestTimeoutMilliseconds`, `connectTimeoutMilliseconds`, or
  `reconciliationIntervalMilliseconds`; the session leaves them at the
  runtime's defaults, and the reader refuses them with `config.removed-key`.
  Migration: remove them; set them in a deployed runtime configuration.

Development clients codes: `casework.dev-clients.clients-out-of-range`, `casework.dev-clients.duplicate-access-profile`, `casework.dev-clients.duplicate-id`, `casework.dev-clients.duplicate-member`, `casework.dev-clients.duplicate-queue`, `casework.dev-clients.duplicate-scope`, `casework.dev-clients.duplicate-team`, `casework.dev-clients.invalid-access-profile`, `casework.dev-clients.invalid-claim-name`, `casework.dev-clients.invalid-claim-value`, `casework.dev-clients.invalid-id`, `casework.dev-clients.invalid-queue`, `casework.dev-clients.invalid-resource`, `casework.dev-clients.invalid-scope`, `casework.dev-clients.invalid-secret-file`, `casework.dev-clients.invalid-status-client`, `casework.dev-clients.invalid-task-authority-issuer`, `casework.dev-clients.invalid-task-exchange`, `casework.dev-clients.invalid-team`, `casework.dev-clients.member-role-mismatch`, `casework.dev-clients.missing-administrator`, `casework.dev-clients.missing-human-claim`, `casework.dev-clients.missing-integrations`, `casework.dev-clients.missing-principal-claim`, `casework.dev-clients.missing-required-scope`, `casework.dev-clients.missing-task-authority`, `casework.dev-clients.missing-task-exchange-client`, `casework.dev-clients.repeated-principal`, `casework.dev-clients.requester-human-claim`, `casework.dev-clients.requester-member`, `casework.dev-clients.reserved-claim`, `casework.dev-clients.reserved-id`, `casework.dev-clients.scopes-out-of-range`, `casework.dev-clients.service-client-human-claim`, `casework.dev-clients.source-bindings-mismatch`, `casework.dev-clients.staff-out-of-range`, `casework.dev-clients.too-many-claims`, `casework.dev-clients.too-many-integrations`, `casework.dev-clients.too-many-supervisors`, `casework.dev-clients.too-many-teams`, `casework.dev-clients.unknown-access-profile`, `casework.dev-clients.unknown-client`, `casework.dev-clients.unknown-queue`, `casework.dev-clients.unserved-queue`.

## BREAKING: the development session state is read by the shared reader

`.casework/dev/state.json`, the session state `caseworkctl dev` writes and
reads back, carries the format envelope, is read through the shared
configuration reader, and is checked by `caseworkctl check`.

- The file declares:

  ```json
  "apiVersion": "id.registrystack.org/formats/casework/dev-state/v1alpha1",
  "kind": "CaseworkDevState"
  ```

  in place of `"version": 2`. `caseworkctl dev` refuses a session an
  earlier `caseworkctl` started and changes nothing. Migration: run
  `caseworkctl dev stop --remove` with the `caseworkctl` that started the
  session, remove `.casework/dev`, and start again. If that `caseworkctl` is
  gone, remove the session's `casework-dev-<owner>` database container with
  `docker rm -fv`, then remove `.casework/dev`.
- An absent optional member is omitted rather than written as `null`, and a
  `null` is refused with `config.null-value`. A team recorded twice under
  `seeded` is refused with `config.duplicate-item`.
- `caseworkctl check` reads the file when the project has one, counts it in
  `filesChecked`, and reports a problem at its line and column with a reader
  code, or with `casework.dev-state.invalid-ownership` when the owner, an
  issuer owner, the resource, the directory revision, the container, or the
  ports are ones `caseworkctl` never writes. A link or special file in its
  place is refused with `casework.project.not-a-regular-file`. No diagnostic
  repeats a value from the file.

Development state codes: `casework.dev-state.invalid-ownership`.

## BREAKING: `caseworkctl` report schema identifiers

The 21 schemas in `products/casework/contracts/cli/`, one per
`caseworkctl --format json` report `kind`, are published in the identifier
catalog under the `kind` in kebab case, as the table lists. The file names and the
`apiVersion` the reports carry, `registry.registrystack.org/caseworkctl/v1alpha3`,
are unchanged, and so is every report `caseworkctl` writes.

| `kind` | Old `$id` | New `$id` |
|---|---|---|
| `ApplyReport` | `https://registrystack.org/caseworkctl/v1alpha3/ApplyReport.schema.json` | `https://id.registrystack.org/schemas/casework/apply-report/apply-report.v1alpha3.schema.json` |
| `AttemptSettlementReport` | `https://registrystack.org/caseworkctl/v1alpha3/AttemptSettlementReport.schema.json` | `https://id.registrystack.org/schemas/casework/attempt-settlement-report/attempt-settlement-report.v1alpha3.schema.json` |
| `AttemptUncertainMarkingReport` | `https://registrystack.org/caseworkctl/v1alpha3/AttemptUncertainMarkingReport.schema.json` | `https://id.registrystack.org/schemas/casework/attempt-uncertain-marking-report/attempt-uncertain-marking-report.v1alpha3.schema.json` |
| `CheckReport` | `https://registrystack.org/caseworkctl/v1alpha3/CheckReport.schema.json` | `https://id.registrystack.org/schemas/casework/check-report/check-report.v1alpha3.schema.json` |
| `DevEventsReport` | `https://registrystack.org/caseworkctl/v1alpha3/DevEventsReport.schema.json` | `https://id.registrystack.org/schemas/casework/dev-events-report/dev-events-report.v1alpha3.schema.json` |
| `DevGrantReport` | `https://registrystack.org/caseworkctl/v1alpha3/DevGrantReport.schema.json` | `https://id.registrystack.org/schemas/casework/dev-grant-report/dev-grant-report.v1alpha3.schema.json` |
| `DevIdentityReport` | `https://registrystack.org/caseworkctl/v1alpha3/DevIdentityReport.schema.json` | `https://id.registrystack.org/schemas/casework/dev-identity-report/dev-identity-report.v1alpha3.schema.json` |
| `DevReport` | `https://registrystack.org/caseworkctl/v1alpha3/DevReport.schema.json` | `https://id.registrystack.org/schemas/casework/dev-report/dev-report.v1alpha3.schema.json` |
| `DevTokenReport` | `https://registrystack.org/caseworkctl/v1alpha3/DevTokenReport.schema.json` | `https://id.registrystack.org/schemas/casework/dev-token-report/dev-token-report.v1alpha3.schema.json` |
| `DoctorReport` | `https://registrystack.org/caseworkctl/v1alpha3/DoctorReport.schema.json` | `https://id.registrystack.org/schemas/casework/doctor-report/doctor-report.v1alpha3.schema.json` |
| `ExplainReport` | `https://registrystack.org/caseworkctl/v1alpha3/ExplainReport.schema.json` | `https://id.registrystack.org/schemas/casework/explain-report/explain-report.v1alpha3.schema.json` |
| `InitReport` | `https://registrystack.org/caseworkctl/v1alpha3/InitReport.schema.json` | `https://id.registrystack.org/schemas/casework/init-report/init-report.v1alpha3.schema.json` |
| `LifecycleReport` | `https://registrystack.org/caseworkctl/v1alpha3/LifecycleReport.schema.json` | `https://id.registrystack.org/schemas/casework/lifecycle-report/lifecycle-report.v1alpha3.schema.json` |
| `PackageReport` | `https://registrystack.org/caseworkctl/v1alpha3/PackageReport.schema.json` | `https://id.registrystack.org/schemas/casework/package-report/package-report.v1alpha3.schema.json` |
| `PlanReport` | `https://registrystack.org/caseworkctl/v1alpha3/PlanReport.schema.json` | `https://id.registrystack.org/schemas/casework/plan-report/plan-report.v1alpha3.schema.json` |
| `RetentionEraseReport` | `https://registrystack.org/caseworkctl/v1alpha3/RetentionEraseReport.schema.json` | `https://id.registrystack.org/schemas/casework/retention-erase-report/retention-erase-report.v1alpha3.schema.json` |
| `SimulationReport` | `https://registrystack.org/caseworkctl/v1alpha3/SimulationReport.schema.json` | `https://id.registrystack.org/schemas/casework/simulation-report/simulation-report.v1alpha3.schema.json` |
| `SourceAddReport` | `https://registrystack.org/caseworkctl/v1alpha3/SourceAddReport.schema.json` | `https://id.registrystack.org/schemas/casework/source-add-report/source-add-report.v1alpha3.schema.json` |
| `StatusReport` | `https://registrystack.org/caseworkctl/v1alpha3/StatusReport.schema.json` | `https://id.registrystack.org/schemas/casework/status-report/status-report.v1alpha3.schema.json` |
| `TestReport` | `https://registrystack.org/caseworkctl/v1alpha3/TestReport.schema.json` | `https://id.registrystack.org/schemas/casework/test-report/test-report.v1alpha3.schema.json` |
| `UsageReport` | `https://registrystack.org/caseworkctl/v1alpha3/UsageReport.schema.json` | `https://id.registrystack.org/schemas/casework/usage-report/usage-report.v1alpha3.schema.json` |

Each schema declares `apiVersion` and `kind` beside its variants and refuses
a member no variant declares. The members the schemas left open are typed
and closed: the attempt settlement, uncertain marking, and retention erasure
detail; the effective project `check` reports; the `doctor` secret file and
source checks and stranded work; the `explain` requests; the `package` files;
the `simulate` routing; the `source add` connection; and the `plan` and
`apply` effects. Every count states its maximum: the range of the Rust type
`caseworkctl` writes, or 0 to 9007199254740991, the largest integer JSON
carries exactly, where that type is wider. Where `caseworkctl` holds a
tighter limit the schema states it: 64 sources per project, 64 routing
rules per request, 1048576 bytes per package file, and 2147483647 consecutive
reconciliation failures.

`ExplainReport` and `CheckReport` refer to the project schema,
`https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json`,
for the queues, review kinds, review producers, inbox, routing rules, access
profiles, calendars, and clocks they carry, rather than copying it.

Migration: load the report schemas by their new identifiers. A validator
checking an `explain` or `check` report needs the project schema,
`products/casework/generated/project/project.schema.json`, loaded beside the
report schema; the reference is relative, so it resolves to the copy
published beside the report schema.

The members still left open are listed in
`products/casework/contracts/cli/README.md`.

## BREAKING: `authentication.oidc.assertionIssuers: {}` is refused

| Before | Now | Migration |
|---|---|---|
| `authentication.oidc.assertionIssuers: {}`, which applied no assertion-issuer rule | `config.invalid-value` at `/authentication/oidc/assertionIssuers` | Delete the member: omitting it applies no assertion-issuer rule. |

## Diagnostic codes

| Old code | New code |
|---|---|
| `casework.project.invalid` | a reader code for the file's structure, or a `casework.<area>.<condition>` code for its meaning, both listed below |
| `casework.review-producer.recovery-days-out-of-range` | `config.out-of-range` for a file |
| `casework.review-kind.retention-out-of-range` | `config.out-of-range` for a file |
| `casework.review-kind.required-approvals-out-of-range` | `config.out-of-range` for a file |
| `casework.inbox.out-of-range` | `config.out-of-range` for a file |
| `casework.clock.working-days-out-of-range` | `config.out-of-range` for a file |
| `casework.task-template.lifetime-out-of-range` | `config.out-of-range` for a file |
| `casework.calendar.duplicate-working-weekday` | `config.duplicate-item` for a file |
| `casework.clock.unsupported-pause` | `config.duplicate-item` for a file whose `pauseWhile` repeats an item; unchanged otherwise |
| `casework.task-template.duplicate-entry` | `config.duplicate-item` for a file whose `itemStates` repeats an item; unchanged for the template's other lists |
| `casework.review-producer.invalid-issuer` | `config.invalid-value` for a file whose issuer is not a URL; unchanged for one longer than 512 bytes |
| `casework.review-producer.invalid-trusted-initiator-issuer` | `config.invalid-value` for a file whose issuer is not a URL; unchanged for one longer than 256 bytes |
| `casework.task-template.invalid-text` | `config.invalid-value` for a file whose `agent.issuer` is not a URL; unchanged otherwise |

Reader codes: `config.deprecated-api-version`, `config.duplicate-id`, `config.duplicate-item`, `config.duplicate-key`, `config.expected-boolean`, `config.expected-integer`, `config.expected-number`, `config.expected-string`, `config.invalid-length`, `config.invalid-type`, `config.invalid-value`, `config.missing-envelope`, `config.missing-key`, `config.null-value`, `config.out-of-range`, `config.removed-key`, `config.retired-api-version`, `config.substitution-not-allowed`, `config.unknown-key`, `config.unknown-variant`, `config.unsupported-api-version`, `config.wrong-kind`, `yaml.alias`, `yaml.ambiguous-number`, `yaml.anchor`, `yaml.colon-in-plain-value`, `yaml.duplicate-key`, `yaml.merge-key`, `yaml.multiple-documents`, `yaml.non-string-key`, `yaml.not-utf8`, `yaml.syntax`, `yaml.tab-indentation`, `yaml.tag`, `yaml.too-deep`, `yaml.too-large`, `yaml.unclosed-quote`, `yaml.unexpected-end`.

Project codes:

- `casework.access-profile.*`: `casework.access-profile.duplicate-id`, `casework.access-profile.empty-principal-claim`, `casework.access-profile.invalid-id`, `casework.access-profile.invalid-scope`, `casework.access-profile.missing-role`, `casework.access-profile.no-required-scope`, `casework.access-profile.shared-scopes`.
- `casework.calendar.*`: `casework.calendar.duplicate-id`, `casework.calendar.duplicate-working-weekday`, `casework.calendar.invalid-holiday-set`, `casework.calendar.invalid-id`, `casework.calendar.no-working-weekdays`, `casework.calendar.too-many`, `casework.calendar.unknown-timezone`.
- `casework.clock.*`: `casework.clock.duplicate-id`, `casework.clock.duplicate-reminder-id`, `casework.clock.duplicate-step-id`, `casework.clock.invalid-because`, `casework.clock.invalid-due-time`, `casework.clock.invalid-elapsed`, `casework.clock.invalid-id`, `casework.clock.invalid-reminder-id`, `casework.clock.invalid-step-id`, `casework.clock.too-many-reminders`, `casework.clock.too-many-steps`, `casework.clock.too-many`, `casework.clock.unknown-calendar`, `casework.clock.unknown-queue`, `casework.clock.unsupported-pause`, `casework.clock.working-days-out-of-range`.
- `casework.inbox.*`: `casework.inbox.inconsistent-bounds`, `casework.inbox.out-of-range`.
- `casework.project.*`: `casework.project.empty-version`, `casework.project.no-work`, `casework.project.wrong-api-version`, `casework.project.wrong-kind`.
- `casework.queue.*`: `casework.queue.duplicate-id`, `casework.queue.invalid-id`, `casework.queue.invalid-label`, `casework.queue.none`.
- `casework.request.*`: `casework.request.duplicate-context-field`, `casework.request.duplicate-entity`, `casework.request.empty-entity`, `casework.request.empty-target-id`, `casework.request.invalid-context-field`, `casework.request.invalid-display-reference`, `casework.request.invalid-target-elapsed`, `casework.request.too-many-context-fields`, `casework.request.unknown-clock`.
- `casework.review-kind.*`: `casework.review-kind.accountability-before-terminal`, `casework.review-kind.answer-stage-approvals`, `casework.review-kind.answer-stage-count`, `casework.review-kind.answer-without-outcomes`, `casework.review-kind.answered-outcome-in-approval`, `casework.review-kind.display-hides-disclosure`, `casework.review-kind.duplicate-clock`, `casework.review-kind.duplicate-deciding-profile`, `casework.review-kind.duplicate-id`, `casework.review-kind.duplicate-outcome-id`, `casework.review-kind.duplicate-stage-id`, `casework.review-kind.ineligible-deciding-profile`, `casework.review-kind.invalid-clock`, `casework.review-kind.invalid-deciding-profile`, `casework.review-kind.invalid-display-schema`, `casework.review-kind.invalid-id`, `casework.review-kind.invalid-outcome-id`, `casework.review-kind.invalid-outcome-label`, `casework.review-kind.invalid-result-schema`, `casework.review-kind.invalid-stage-id`, `casework.review-kind.invalid-stage-queue`, `casework.review-kind.invalid-version`, `casework.review-kind.no-deciding-profiles`, `casework.review-kind.no-stages`, `casework.review-kind.required-approvals-out-of-range`, `casework.review-kind.result-required-without-result-schema`, `casework.review-kind.retention-out-of-range`, `casework.review-kind.too-many-clocks`, `casework.review-kind.too-many-deciding-profiles`, `casework.review-kind.too-many-outcomes`, `casework.review-kind.too-many-stages`, `casework.review-kind.too-many`, `casework.review-kind.unanswered-outcome-in-answer`, `casework.review-kind.unknown-clock`, `casework.review-kind.unknown-queue`.
- `casework.review-producer.*`: `casework.review-producer.duplicate-id`, `casework.review-producer.duplicate-kind`, `casework.review-producer.duplicate-principal`, `casework.review-producer.duplicate-source-namespace`, `casework.review-producer.ineligible-initiator-profile`, `casework.review-producer.invalid-completion-destination`, `casework.review-producer.invalid-id`, `casework.review-producer.invalid-initiator-profile`, `casework.review-producer.invalid-issuer`, `casework.review-producer.invalid-kind`, `casework.review-producer.invalid-profile`, `casework.review-producer.invalid-recipient-binding`, `casework.review-producer.invalid-source-namespace`, `casework.review-producer.invalid-subject`, `casework.review-producer.invalid-trusted-initiator-issuer`, `casework.review-producer.missing-trusted-initiator-issuer`, `casework.review-producer.no-kinds`, `casework.review-producer.no-source-namespaces`, `casework.review-producer.none`, `casework.review-producer.not-a-requester-profile`, `casework.review-producer.recovery-days-out-of-range`, `casework.review-producer.recovery-exceeds-retention`, `casework.review-producer.too-many-kinds`, `casework.review-producer.too-many-source-namespaces`, `casework.review-producer.too-many`, `casework.review-producer.unknown-review-kind`, `casework.review-producer.without-review-kinds`.
- `casework.routing.*`: `casework.routing.duplicate-predicate-value`, `casework.routing.duplicate-projection-field`, `casework.routing.duplicate-rule-id`, `casework.routing.empty-condition`, `casework.routing.field-not-projected`, `casework.routing.invalid-because`, `casework.routing.invalid-predicate-value`, `casework.routing.invalid-rule-id`, `casework.routing.invalid-source-description`, `casework.routing.invalid-source-value`, `casework.routing.predicate-value-count`, `casework.routing.stage-without-review`, `casework.routing.too-many-predicates`, `casework.routing.too-many-projection-fields`, `casework.routing.too-many-rules`, `casework.routing.unexpected-source-state`, `casework.routing.unknown-field`, `casework.routing.unknown-queue`, `casework.routing.unknown-stage`, `casework.routing.unreachable-rule`.
- `casework.source.*`: `casework.source.ambiguous`, `casework.source.duplicate-id`, `casework.source.empty-adapter`, `casework.source.empty-description`, `casework.source.empty-id`, `casework.source.no-requests`, `casework.source.none`, `casework.source.too-many`, `casework.source.too-many-requests`, `casework.source.unknown`, `casework.source.unpublished-field`, `casework.source.unsupported-adapter`.
- `casework.source-description.*`: `casework.source-description.contract-mismatch`, `casework.source-description.missing`, `casework.source-description.review-kind-not-approval`, `casework.source-description.review-kind-not-source-context`, `casework.source-description.review-not-admitted`, `casework.source-description.unknown-review-kind`.
- `casework.source-revision.*`: `casework.source-revision.stale`.
- `casework.task-template.*`: `casework.task-template.duplicate-entry`, `casework.task-template.duplicate-id`, `casework.task-template.duplicate-permission`, `casework.task-template.empty-list`, `casework.task-template.ineligible-profile`, `casework.task-template.invalid-audience`, `casework.task-template.invalid-bounds`, `casework.task-template.invalid-entry`, `casework.task-template.invalid-id`, `casework.task-template.invalid-operation`, `casework.task-template.invalid-purpose`, `casework.task-template.invalid-requester-tag`, `casework.task-template.invalid-scope`, `casework.task-template.invalid-subject-claim`, `casework.task-template.invalid-subject-field`, `casework.task-template.invalid-team`, `casework.task-template.invalid-text`, `casework.task-template.lifetime-out-of-range`, `casework.task-template.missing-evidence-context`, `casework.task-template.mixed-eligibility`, `casework.task-template.no-eligibility`, `casework.task-template.permissions-out-of-range`, `casework.task-template.subjects-out-of-range`, `casework.task-template.too-many-entries`, `casework.task-template.too-many`, `casework.task-template.unexpected-evidence-context`, `casework.task-template.unknown-item-kind`, `casework.task-template.unknown-review-kind`, `casework.task-template.unknown-source`, `casework.task-template.unsupported-item-state`.

## Stable move

The changes below move promised spellings to the form the configuration
conventions give them. Each old spelling is refused with a diagnostic that
names its replacement; no release reads both.

### BREAKING: `authentication.oidc.jwksSource` is tagged by `type`

The shared OIDC key source block is a union tagged by `type` (CFG-ID-7),
where it was tagged by `kind`. The `casework` runtime and every command
that reads a runtime file refuse `kind` under `jwksSource` as
`config.removed-key` at `/authentication/oidc/jwksSource/kind`, and the
message names `type`. The values and their members are unchanged.

| Old spelling | New spelling | Migration |
|---|---|---|
| `authentication.oidc.jwksSource.kind` | `authentication.oidc.jwksSource.type` | Rename the key; keep the value (`discovery`, `uri`, or `static`). |

`jwksSource: {kind: static, documentRef: secret:file/jwks}` becomes
`jwksSource: {type: static, documentRef: secret:file/jwks}`. A file that
omits `jwksSource` needs no change: the default is still `type: discovery`.
`caseworkctl check PROJECT --runtime-config FILE` reports the old key at
its line and column.

### BREAKING: `runtime.yaml` carries the format identifier as its `apiVersion`

The Casework runtime configuration names its format the way every other
Registry Stack file does (CFG-ENV-2). The `casework` runtime and every
command that reads a runtime file refuse the old value as
`config.retired-api-version` at `/apiVersion`, and the message names the new
one. `kind: CaseworkRuntimeConfig` and every other member are unchanged.

| Old spelling | New spelling | Migration |
|---|---|---|
| `apiVersion: registry.registrystack.org/casework-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/casework/runtime/v1alpha1` | Replace the line. |

`caseworkctl dev` writes the new value into the runtime file it generates.

### BREAKING: four `runtime.yaml` keys are renamed

A retention period ends in `RetentionDays`, the time one attempt may take
is `attemptTimeoutMilliseconds`, and the wait between attempts is a retry
delay (CFG-NAME-5). The `casework` runtime and every command that reads a
runtime file refuse each old key as `config.removed-key` at its own pointer,
and the message names the replacement. Values, units, defaults, and bounds
are unchanged.

| Old spelling | New spelling | Migration |
|---|---|---|
| `audit.retainDays` | `audit.retentionDays` | Rename the key; keep the value. |
| `sources.<id>.requestTimeoutMilliseconds` | `sources.<id>.attemptTimeoutMilliseconds` | Rename the key; keep the value. |
| `reviewCompletionDestinations.<id>.timeoutMilliseconds` | `reviewCompletionDestinations.<id>.attemptTimeoutMilliseconds` | Rename the key; keep the value. |
| `reviewCompletionDestinations.<id>.retrySeconds` | `reviewCompletionDestinations.<id>.retryDelaySeconds` | Rename the key; keep the value. |

`sources.<id>.connectTimeoutMilliseconds` keeps its name. A refusal of an
audit member now names `audit.retentionDays` in its message and path.

### BREAKING: the keys of three id-keyed `runtime.yaml` maps are typed

The runtime schema states the grammar of each id-keyed map's keys (CFG-ID-1,
CFG-ID-2), and the reader refuses a key outside it as `config.invalid-value`
at the key's own pointer, before any cross-check against `casework.yaml`.

| Map | Key grammar | Migration |
|---|---|---|
| `sources` | local identifier, `^[a-z][a-z0-9_-]{0,63}$` | None for a file the runtime started with: a source id in `casework.yaml` already had a narrower grammar. |
| `reviewCompletionDestinations` | kept as written: 1 to 512 characters, no control characters | Rewrite an empty, over-long, or control-character key. |
| `taskAuthority.statusClients` | kept as written: 1 to 512 characters, no control characters | Rewrite an empty, over-long, or control-character key. |

A completion destination id is stored with each review request, so its
grammar is not narrowed: `casework.yaml` still holds `destinationId` to 1 to
128 ASCII letters, digits, `-`, `_`, `.`, or `:`.

### BREAKING: each `caseworkctl` report names its own format

A `caseworkctl --format json` report is a format of its own, as every other
Registry Stack document is (CFG-ENV-2, CFG-ENV-3). Its `apiVersion` is
`id.registrystack.org/formats/casework/<report>/v1alpha3`, where it was
`registry.registrystack.org/caseworkctl/v1alpha3` for every report, and its
`kind` carries the product's name. The 21 reports keep one version and move
together. Every other member, the schema file names in
`products/casework/contracts/cli/`, and the schema `$id` values are
unchanged.

| Old `kind` | New `kind` | New `apiVersion` |
|---|---|---|
| `ApplyReport` | `CaseworkApplyReport` | `id.registrystack.org/formats/casework/apply-report/v1alpha3` |
| `AttemptSettlementReport` | `CaseworkAttemptSettlementReport` | `id.registrystack.org/formats/casework/attempt-settlement-report/v1alpha3` |
| `AttemptUncertainMarkingReport` | `CaseworkAttemptUncertainMarkingReport` | `id.registrystack.org/formats/casework/attempt-uncertain-marking-report/v1alpha3` |
| `CheckReport` | `CaseworkCheckReport` | `id.registrystack.org/formats/casework/check-report/v1alpha3` |
| `DevEventsReport` | `CaseworkDevEventsReport` | `id.registrystack.org/formats/casework/dev-events-report/v1alpha3` |
| `DevGrantReport` | `CaseworkDevGrantReport` | `id.registrystack.org/formats/casework/dev-grant-report/v1alpha3` |
| `DevIdentityReport` | `CaseworkDevIdentityReport` | `id.registrystack.org/formats/casework/dev-identity-report/v1alpha3` |
| `DevReport` | `CaseworkDevReport` | `id.registrystack.org/formats/casework/dev-report/v1alpha3` |
| `DevTokenReport` | `CaseworkDevTokenReport` | `id.registrystack.org/formats/casework/dev-token-report/v1alpha3` |
| `DoctorReport` | `CaseworkDoctorReport` | `id.registrystack.org/formats/casework/doctor-report/v1alpha3` |
| `ExplainReport` | `CaseworkExplainReport` | `id.registrystack.org/formats/casework/explain-report/v1alpha3` |
| `InitReport` | `CaseworkInitReport` | `id.registrystack.org/formats/casework/init-report/v1alpha3` |
| `LifecycleReport` | `CaseworkLifecycleReport` | `id.registrystack.org/formats/casework/lifecycle-report/v1alpha3` |
| `PackageReport` | `CaseworkPackageReport` | `id.registrystack.org/formats/casework/package-report/v1alpha3` |
| `PlanReport` | `CaseworkPlanReport` | `id.registrystack.org/formats/casework/plan-report/v1alpha3` |
| `RetentionEraseReport` | `CaseworkRetentionEraseReport` | `id.registrystack.org/formats/casework/retention-erase-report/v1alpha3` |
| `SimulationReport` | `CaseworkSimulationReport` | `id.registrystack.org/formats/casework/simulation-report/v1alpha3` |
| `SourceAddReport` | `CaseworkSourceAddReport` | `id.registrystack.org/formats/casework/source-add-report/v1alpha3` |
| `StatusReport` | `CaseworkStatusReport` | `id.registrystack.org/formats/casework/status-report/v1alpha3` |
| `TestReport` | `CaseworkTestReport` | `id.registrystack.org/formats/casework/test-report/v1alpha3` |
| `UsageReport` | `CaseworkUsageReport` | `id.registrystack.org/formats/casework/usage-report/v1alpha3` |

Migration: no file changes. A script that selects a report by `kind`, or
checks `apiVersion`, matches the new values; nothing reads a report back, so
no old value is refused anywhere.

### BREAKING: `casework.yaml` carries the format identifier as its `apiVersion`

A Casework project names its format the way every other Registry Stack file
does (CFG-ENV-2): `apiVersion` is
`id.registrystack.org/formats/casework/project/v1alpha1`, where it was
`registry.registrystack.org/casework/v1alpha1`. `kind: CaseworkProject` and
every other member are unchanged. Every command that reads a project and the
`casework` runtime refuse the old value as `config.retired-api-version` at
`/apiVersion`, and the diagnostic names the new one.

Migration: reauthor `casework.yaml` with
`apiVersion: id.registrystack.org/formats/casework/project/v1alpha1`, build the
package with v0.40.0, and apply it to a new database. The header is part of the
packaged policy, so the package digest changes.

### BREAKING: the identifiers `casework.yaml` declares are local identifiers

Thirteen members of `casework.yaml` are typed by the shared identifier types
(CFG-ID-1, CFG-ID-2), so the schema, the reader, and the semantic checks hold
one grammar: `^[a-z][a-z0-9_-]{0,63}$`.

| Member | Before | Now |
|---|---|---|
| `calendars[].id`, `clocks[].id`, `clocks[].reminders[].id`, `clocks[].steps[].id`, `reviewKinds[].id`, `reviewKinds[].stages[].id`, `reviewKinds[].outcomes[].id`, the `id` of a rule under `routing`, a key under a routing rule's `when.fields` | `^[a-z][a-z0-9-]{0,63}$` | local identifier: `_` is also accepted |
| `sources[].id`, `sources[].requests[].target.id` | any non-empty string | local identifier |
| a key under `taskTemplates[].subjects` | untyped in the schema | external identifier in the schema; the check still holds it to letters, digits, `-`, `_`, and `.` up to 128 bytes |

A malformed identifier in a file is refused by the reader as
`config.invalid-value` at the identifier's own pointer, before the semantic
checks run. The identifier pattern the OpenAPI document publishes for these
ids, and for the holiday-set path parameter, accepts `_` as well: a client
that validates responses against a copied pattern must take the new one.

Migration: a source id or a target id that is not a local identifier must be
rewritten, in `casework.yaml` and as the matching key under `sources` in
`runtime.yaml`. Reauthor the project, build the package with v0.40.0, and apply
it to a new database. No other file changes.

### A repeated id in `casework.yaml` is refused by the reader

The eight named lists of `casework.yaml` (`accessProfiles`, `queues`,
`sources`, `reviewKinds`, `reviewProducers`, `calendars`, `clocks`, and
`taskTemplates`) are read through the shared unique-by-id list type
(CFG-ID-5). A file that repeats an id was refused before and is refused now;
the code and the order change:

| List | Code before | Code now |
|---|---|---|
| `accessProfiles` | `casework.access-profile.duplicate-id` | `config.duplicate-id` |
| `queues` | `casework.queue.duplicate-id` | `config.duplicate-id` |
| `sources` | `casework.source.duplicate-id` | `config.duplicate-id` |
| `reviewKinds` | `casework.review-kind.duplicate-id` | `config.duplicate-id` |
| `reviewProducers` | `casework.review-producer.duplicate-id` | `config.duplicate-id` |
| `calendars` | `casework.calendar.duplicate-id` | `config.duplicate-id` |
| `clocks` | `casework.clock.duplicate-id` | `config.duplicate-id` |
| `taskTemplates` | `casework.task-template.duplicate-id` | `config.duplicate-id` |

The diagnostic sits at the `id` of the second item, as before. The reader
refuses first, so a repeated id is reported before the semantic checks run.
The product codes stay in the catalogue: they still report a repeated id in a
project that was not read from a file.

Migration: no file changes. A script that matches the product code of a
repeated id must match `config.duplicate-id`.

### BREAKING: the required scopes of an access profile are a set

`accessProfiles[].requiredScopes` in `casework.yaml` is read as a set
(CFG-ID-6). A scope listed twice in one profile, which was accepted and
counted once, is refused by the reader as `config.duplicate-item` at the
second occurrence, and the schema declares `uniqueItems`.

Migration: delete the repeated scope. A profile that lists each scope once
needs no change.

### BREAKING: a client listed under `assertionIssuers` names at least one issuer

`authentication.oidc.assertionIssuers` in the runtime file refuses a client
written with an empty issuer list (CFG-EMPTY-2). The runtime, `caseworkctl
check`, and every command that reads a runtime file report
`config.invalid-value` at `/authentication/oidc/assertionIssuers/<client>`,
and the runtime schema declares `minItems: 1` on the list. A client that is
not listed may exchange from no authority, which is what the empty list
meant.

Migration: remove a client that lists no issuer from `assertionIssuers`, or
list its issuers. Do not delete the whole member to get there unless no
assertion-issuer rule is wanted: with the member omitted, a token exchanged
from any authority the issuer federates is accepted.

### BREAKING: five `caseworkctl` reports respell values and type their identifiers

Nothing an operator writes changes; a script that reads these reports does.

| Report | Member | Old | New |
|---|---|---|---|
| `plan` | `databaseIdCheck` | `notRecorded` | `not-recorded` |
| `lifecycle` | `lifecycles[].id` | `review_request` | `review-request` |
| `simulate` | `subject.id` | `id` | `recordId` |
| `source add` | `activation` | `not_performed` | `not-performed` |
| `test` | `proofBoundary` | `offline_synthetic` | `offline-synthetic` |

- `subject.recordId` in the simulation report is the source record
  identifier the simulation file writes under the same name. It is the
  source's own identifier, not a local identifier, so the report no longer
  calls it `id` (CFG-ID-1, CFG-ID-2).
- `LifecycleReport.schema.json` types a lifecycle's `id`, a state's `id`, and
  an enforcement layer's `id` as local identifiers. The state and layer
  identifiers are written as the runtime stores them. The two waiting item
  states are respelled with the runtime (see "the two waiting item states are
  kebab-case" below), and the review state `changes_requested` with the
  report words (see "the words `caseworkctl` prints in its reports are
  kebab-case" under "Protocol words").
- `PlanReport.schema.json` has two variants, told apart by `ok`, where it had
  three (CFG-ID-7). A refusal carries the plan it refused when its `status`
  is `refused` and carries none of the plan's members otherwise; the schema
  states that with `if`, `then`, and `else` inside the one refusal variant.
  The report itself is unchanged apart from `databaseIdCheck`.

Migration: a script that compares one of the old values compares the new
one, and a script that reads `.subject.id` from `caseworkctl simulate` reads
`.subject.recordId`. A consumer that validates reports takes the regenerated
schemas.

### BREAKING: `casework.yaml` names the project in a `project` block

A Casework project names itself the way every other Registry Stack project
does (CFG-ENV-6): the top-level `project` block holds the shared
`ProjectIdentity` members, `id` and `version`, where the block was called
`casework`. Every command that reads a project and the `casework` runtime
refuse `casework` as `config.removed-key` at `/casework`, and the diagnostic
names `project`. An empty project version is still
`casework.project.empty-version`, now at `/project/version`.

Nothing stored changes: the runtime keeps no project id, and it reports the
one the packaged project declares as `projectId` in its description
response, whose member names are unchanged. `caseworkctl` reports keep `projectId` and
`policyVersion`.

Migration: rename the top-level `casework` key to `project` in
`casework.yaml`, then run `caseworkctl package`, `caseworkctl plan`, and
`caseworkctl apply`.

### BREAKING: the project id in `casework.yaml` is a local identifier

`project.id` is a local identifier (CFG-ID-1): a lowercase letter, then at
most 63 lowercase letters, digits, underscores, or hyphens. It was any
non-empty text. A value outside that grammar is refused as
`config.invalid-value` at `/project/id`.

| Failure | Old code | New code |
|---|---|---|
| an empty project id | `casework.project.empty-id` | `config.invalid-value` |

Migration: rewrite `project.id` when it is not a local identifier, then
package, plan, and apply. A caller that compares `projectId` from the
runtime's description response or from a `caseworkctl` report compares the
new value.

### BREAKING: the runtime file states which OAuth clients it admits

`authentication.oidc.allowedClients` in `runtime.yaml` is required
(CFG-EMPTY-2). It takes the keyword `unrestricted`, to admit a token from
every client the issuer verifies, or a list of at least one client, none
repeated (CFG-ID-6). The `casework` runtime and
`caseworkctl check PROJECT --runtime-config FILE` refuse the other forms
when the file is read.

| Written | Before | Now |
|---|---|---|
| member omitted, development loopback | every client admitted | refused, `config.missing-key` at `/authentication/oidc` |
| `allowedClients: []`, development loopback | every client admitted | refused, `config.invalid-value` at `/authentication/oidc/allowedClients` |
| member omitted or `[]`, `operator-controlled-upstream` | refused, `casework.runtime.allowed-clients-required` | refused with the reader codes above |
| `allowedClients: unrestricted`, development loopback | refused | every client admitted |
| `allowedClients: unrestricted`, `operator-controlled-upstream` | refused | refused, `casework.runtime.allowed-clients-required` at `/authentication/oidc/allowedClients` |
| `allowedClients: [a, b]` | only `a` and `b` admitted | unchanged |
| `allowedClients: [a, b, a]` | only `a` and `b` admitted | refused, `config.duplicate-item` at `/authentication/oidc/allowedClients/2` |

The diagnostic names the fix and never repeats what was written. Token
verification does not change: a runtime file rewritten as below admits
exactly the tokens it admitted before. A configured `taskAuthority` still
requires a list in either listener mode. `caseworkctl init` and the
maintained examples, which listen on development loopback, write
`allowedClients: unrestricted`; `caseworkctl dev` writes the session's
clients as it did.

Migration:

1. If `allowedClients` is missing or written `[]`, list the OAuth clients
   that call this deployment. Listing them is the stronger choice: a token
   issued to any other client of the same issuer is then refused.
2. To keep admitting every client on development loopback, write
   `allowedClients: unrestricted`.
3. Write a client the list repeats once.
4. Run `caseworkctl check PROJECT --runtime-config runtime.yaml`.

### BREAKING: a clock is tagged by `type`, and its four values are kebab-case

A clock in `casework.yaml` says which kind it is with `type` (CFG-ID-7),
where the member was called `scope`, and the four values a clock names are
lowercase kebab-case (CFG-NAME-2). One spelling is used everywhere a clock
appears: the authored file, the record a running occurrence stores, the
digest computed over a clock, and the `clocks` member of `GET /v1/casework`.

| Member | Before | Now |
|---|---|---|
| the tag | `scope: subject`, `scope: activity` | `type: subject`, `type: activity` |
| `anchor` of a subject clock | `firstSubmittedAt` | `first-submitted-at` |
| `completeOn` | `reviewCompleted` | `review-completed` |
| `pauseWhile` items | `awaitingApplicant` | `awaiting-applicant` |
| `anchor` of an activity clock | `stageEnteredAt` | `stage-entered-at` |

`scope` on a clock is refused as `config.removed-key` at `/clocks/N/scope`,
and the diagnostic names `type: subject` and `type: activity`. Each old value
is refused as `config.unknown-variant` at its own position, and the
diagnostic lists the values the member accepts. The members of a simulation
file that carry the same words as keys, `subject.stageEnteredAt` and
`subject.reviewTiming.firstSubmittedAt`, are member names and do not change.

HTTP: `GET /v1/casework` returns each clock with `type` in place of `scope`
and with the four values above respelled. The `scope` member of a review
clock's `correlation` in `GET /v1/review-requests/{request}/clocks` is a
different member and does not change. The Rust client, the Node.js and
Python bindings, and `@registrystack/client` carry the new spellings in their
types.

Stored state: a running clock occurrence keeps the clock it started under,
with the digest computed when it started, and the runtime reads that record
for as long as the occurrence runs. A stored clock in the previous spelling
is not read: v0.40.0 does not upgrade v0.39.0 state in place; apply to a new
database. An authored file in that spelling is refused.

Migration: in `casework.yaml`, rename `scope` to `type` on every clock and
respell the four values as the table gives them, then run `caseworkctl
package`, `caseworkctl plan`, and `caseworkctl apply`. Update a caller that
reads the `clocks` member of `GET /v1/casework`.

### BREAKING: the two waiting item states are kebab-case

The two waiting states of a work item are lowercase kebab-case (CFG-NAME-2),
as the other closed values Casework reads and writes. One spelling is used
everywhere the state appears: `itemStates` of a task template in
`casework.yaml`, the `state` column of a stored work item, the template a
task grant was approved under, and every HTTP response that carries a work
item.

| Before | Now |
|---|---|
| `waiting_applicant` | `waiting-applicant` |
| `waiting_application` | `waiting-application` |

An old value under `taskTemplates[].itemStates` is refused as
`config.unknown-variant` at its own position, and the diagnostic lists the
values the member accepts. The other six states (`open`, `claimed`,
`synchronizing`, `completed`, `superseded`, `cancelled`) are unchanged. The
lifecycle event identifiers `caseworkctl lifecycle` prints
(`observe_waiting_applicant`, `observe_waiting_application`) are another
vocabulary, respelled with the report words (see "the words `caseworkctl`
prints in its reports are kebab-case" under "Protocol words").

HTTP: the `state` member of a work item carries the new spelling in every
response that returns one: `GET /v1/work-items`, `GET /v1/work-items/next`,
`GET /v1/work-items/{item_id}`, `POST /v1/directory/caseload/preview`, and
the `item` of the response to `POST /v1/work-items/{item_id}/claim`,
`release`, `assign`, `delegate`, `decisions`, `attempts/recover`, and
`attempts/{attempt_id}/recover`. No HTTP response carries a task template's
`itemStates`. `caseworkctl attempt settle` and `caseworkctl attempt
mark-uncertain` print `itemState` in the same spelling, and `caseworkctl
lifecycle` prints the two state identifiers in it. The Rust client, the
Node.js and Python bindings, and `@registrystack/client` carry the new
spellings in their types.

Database: the v0.40.0 schema stores only the new values. It does not convert
the task templates, grants, or work items of a database v0.39.0 wrote.

Migration: in `casework.yaml`, respell the two values under
`taskTemplates[].itemStates`, keeping each template's `version`; build the
package with v0.40.0 and apply it to a new database. Update a caller that
compares a work item's `state` with either old value.

### BREAKING: the settlement that asks for changes is `changes-requested`

The settlement of a review outcome is a closed value and is lowercase
kebab-case (CFG-NAME-2). One of the three had an underscore:

| Before | Now |
|---|---|
| `changes_requested` | `changes-requested` |

`rejected` and `answered` are unchanged. The old value under
`reviewKinds[].outcomes[].settlement` is refused as `config.unknown-variant`
at its own position, and the diagnostic lists the values the member accepts.
One spelling is used everywhere the settlement of an outcome appears: the
authored review kind, the digest input of the kind's policy, the snapshot a
review pins, and the HTTP responses that carry a snapshot.

Three other words carried the same value in another vocabulary: the
`lifecycle` of a review request, the `status` of a review result (the review
protocol a producer such as BReg reads), and the `type` of a reviewer's
decision. They use the final spelling too: see
"the review protocol words are kebab-case" under "Protocol words".

HTTP: `outcomes[].settlement` carries the new spelling in the review kind
snapshots returned by `GET /v1/review-kinds` and `GET
/v1/review-kinds/{kind_id}`, and in the `policySnapshot` of `GET
/v1/review-tasks/{task_id}/context`. The policy `digest` of a review kind
that declares a changes-requested outcome is a new value, wherever that
kind's policy identity is returned.
The Rust client, the Node.js binding, and `@registrystack/client` carry the
new spelling in their types.

Stored state: a review pins its kind's policy snapshot and the snapshot's
digest when it is admitted, and keeps both until it is erased. A stored
snapshot in the previous spelling is not read, and a snapshot verifies only
under the digest this release computes for it: v0.40.0 does not upgrade
v0.39.0 state in place; apply to a new database. An authored file in the old
spelling is refused. No schema migration is involved for the settlement of
an outcome.

Migration: in `casework.yaml`, respell `settlement: changes_requested` to
`settlement: changes-requested` under each review kind, keeping the kind's
`version`; build the package with v0.40.0 and apply it to a new database.
Update a caller that compares an outcome's `settlement` with the old value.

### BREAKING: four more ids `casework.yaml` declares are local identifiers

The id of an access profile, a queue, a review producer, and a task template
is typed by the shared identifier type (CFG-ID-1), so the schema, the reader,
and the semantic checks hold one grammar: `^[a-z][a-z0-9_-]{0,63}$`.

| Member | Before | Now |
|---|---|---|
| `accessProfiles[].id`, `reviewProducers[].id` | letters, digits, `-`, `_`, `.`, and `:`, up to 128 bytes | local identifier |
| `queues[].id`, `taskTemplates[].id` | letters, digits, `-`, `_`, and `.`, up to 128 bytes | local identifier |

An id outside the grammar is refused by the reader as `config.invalid-value`
at the id's own pointer, before the semantic checks run. A reference to one of
these ids (`reviewProducers[].profile`, a stage's `queue` and
`decidingProfiles`, a source request's `queue`, a template's
`eligibleProfiles`, a routing rule's queue, `accessProfile` and a team's
`queue` in `dev-clients.yaml`) is still checked by resolving it, so a
reference to an id that no longer exists is refused as it was.

HTTP: no response member is renamed. The `Registry-Casework-Profile` header
and a queue id in a directory request keep their 128-byte bound; a name
outside the grammar selects no profile and no queue. The ids themselves are
returned where they were: a renamed id is returned under its new name.

Database: v0.40.0 does not convert rows stored under a v0.39.0 identifier.
An identifier already inside the new grammar needs no change. Otherwise,
rename the identifier and every reference to it in `casework.yaml`, and
rename `accessProfile` or a team's `queue` in `dev-clients.yaml`; build the
package with v0.40.0 and apply it to a new database. Update callers to send
the new access-profile and queue identifiers.

### BREAKING: a registry operation in a task template is a local identifier

A registry operation a task template lists under
`taskTemplates[].bounds.permissions[].operations` follows the identifier
grammar every other id in the file follows (CFG-ID-1):
`^[a-z][a-z0-9_-]{0,63}$`, where it was any run of lowercase letters and
underscores. A hyphen and a digit are admitted, so a template may name a
kebab-case registry operation such as `apply-request`; a snake_case name
that starts with a letter is accepted as before.

| Value | Before | Now |
|---|---|---|
| `apply-request`, `read-live`, `revision2` | refused | accepted |
| `apply_request`, `get` | accepted | accepted |
| a name that starts with `_`, or is longer than 64 characters | accepted | refused |
| an uppercase letter, a space, `.`, `:`, `/`, `*`, a leading digit or hyphen | refused | refused |

The project check refuses a value outside the grammar as
`casework.task-template.invalid-operation` at the operation's own pointer.
Casework copies the listed operations into the task assertion unchanged and
infers nothing from their spelling: the registry that verifies the
assertion still decides what each operation permits.

Migration: a template whose operations start with a letter and fit in 64
characters needs no change. Otherwise write the operation name the registry
declares, give the template a new `version`, and run `caseworkctl package`,
`caseworkctl plan`, and `caseworkctl apply`.

### BREAKING: a source description carries its format identifier and one request list

The description `caseworkctl source add` writes under `sources/` is a
generated project file. It carries the format identifier as its `apiVersion`
(CFG-ENV-2) and one kind, named for the product that reads it (CFG-ENV-3).

| Member | Before | Now |
|---|---|---|
| `apiVersion` | `registry.registrystack.org/casework-source-description/v1alpha1` for one request entity, `registry.registrystack.org/casework-source-description/v1alpha2` for several | `id.registrystack.org/formats/casework/breg-source-description/v1alpha1` |
| `kind` | `BRegCaseworkSourceDescription` | `CaseworkBregSourceDescription` |
| request entities | `request` (one object) under `v1alpha1`, `requests` (a list) under `v1alpha2` | `requests`, a list in declaration order, one entry for a source with one entity |

Two versions were live against one format: which one a description carried
depended on how many request entities the source declared. One version and
one shape are read now. A description under either earlier `apiVersion` is
refused and imported again; no reader accepts the earlier shape.

- `caseworkctl check` and `caseworkctl package` refuse it as
  `config.retired-api-version` at `/sources/N/description`, naming the current
  `apiVersion` and the `caseworkctl source add` command for that source.
- `caseworkctl source add --apply` does not replace it: the run names the file
  as carrying a retired `apiVersion` and prints the command that moves it
  aside and retries.
- The runtime refuses a package that carries one as
  `casework.package.source-description-mismatch`, whose `next` names
  `caseworkctl source add` and `caseworkctl package`.

HTTP: no response member changes. A diagnostic's related pointer into a
one-entity description reads `/requests/0/...` where it read `/request/...`.

Migration, for each source in `casework.yaml`, regenerate the description
before building the v0.40.0 package:

1. Move the description aside:
   `test ! -e sources/SOURCE_ID.json.previous && mv sources/SOURCE_ID.json sources/SOURCE_ID.json.previous`.
2. Import it again:
   `caseworkctl source add BREG_PROJECT --project DIR --source-id SOURCE_ID --apply`.
3. Run `caseworkctl package`, then apply the package to a new database.

### BREAKING: `caseworkctl check` and `caseworkctl init` summarize in the human format

In the human format both commands printed every member of their report as a
`key: value` line, the effective configuration among them as one line of
JSON. They now print what a person reads and leave the report to
`--format json`, which is unchanged.

| Command | Human format now | Lines no longer printed |
|---|---|---|
| `caseworkctl check` | the outcome line, `project:`, `runtime config:` when a runtime file was given, `profile:`, each warning, then `N errors, M warnings in K files` | `status:`, `effective:`, `networkAccess:`, `databaseAccess:` |
| `caseworkctl init` | `created:` with the project directory, one indented line for each entry written, then `next:` with the step that follows | `init succeeded.`, `template:`, `project:`, the one-line `created:` and `next:` lists |

No file changes. A script that read one of the removed lines reads the same
member from `caseworkctl --format json check` or `caseworkctl --format json
init`. The other commands print as before.

### BREAKING: `caseworkctl lifecycle` spells its enforcement layer ids in kebab-case

Each lifecycle `caseworkctl lifecycle` reports lists the enforcement layers a
request meets, and each layer carries an `id`. The ids were snake_case and are
lowercase kebab-case now (CFG-NAME-2), the spelling `bregctl explain
lifecycle` gives its own: every underscore became a hyphen.

| Lifecycle | Before | Now |
|---|---|---|
| `occurrence` | `caller_authentication` | `caller-authentication` |
| `occurrence` | `caller_revision_precondition` | `caller-revision-precondition` |
| `occurrence` | `erased_item_idempotency_preflight` | `erased-item-idempotency-preflight` |
| `occurrence` | `source_authorization` | `source-authorization` |
| `occurrence` | `queue_and_holder_authority` | `queue-and-holder-authority` |
| `occurrence` | `idempotency_admission` | `idempotency-admission` |
| `occurrence` | `source_binding_currency` | `source-binding-currency` |
| `occurrence` | `reservation_key_admission` | `reservation-key-admission` |
| `occurrence` | `attempt_fence` | `attempt-fence` |
| `occurrence` | `lifecycle_transition` | `lifecycle-transition` |
| `occurrence` | `persist_serialization` | `persist-serialization` |
| `review-request` | `caller_authentication` | `caller-authentication` |
| `review-request` | `producer_or_reviewer_admission` | `producer-or-reviewer-admission` |
| `review-request` | `review_source_preflight` | `review-source-preflight` |
| `review-request` | `producer_submission_idempotency` | `producer-submission-idempotency` |
| `review-request` | `request_lock_and_lifecycle` | `request-lock-and-lifecycle` |
| `review-request` | `reviewer_queue_authority` | `reviewer-queue-authority` |
| `review-request` | `request_idempotency_admission` | `request-idempotency-admission` |
| `review-request` | `task_revision_and_holder` | `task-revision-and-holder` |
| `review-request` | `decision_eligibility` | `decision-eligibility` |
| `review-request` | `stage_quorum_progression` | `stage-quorum-progression` |
| `review-request` | `settlement_persist_filter` | `settlement-persist-filter` |

The words are printed by `caseworkctl lifecycle` alone, in both formats, as
`lifecycles[].enforcement[].id`. No file an adopter writes carries one, no
HTTP response carries one, and nothing stored holds one, so no file changes
and no migration runs. A script that selects a layer by its id reads the new
spelling. The event ids a layer lists under `events` and the review state id
are respelled with the report words (see "the words `caseworkctl` prints in
its reports are kebab-case" under "Protocol words").

### BREAKING: the lifecycle hook `source add` writes is tagged by `type`

`caseworkctl source add` writes one lifecycle hook for each paired request
entity into the Base Registry Engine project. Its handler is written
`handler: {type: url, destinationId: casework}`, where it was
`handler: {kind: url, destinationId: casework}`, because the Base Registry
Engine of this release tags a hook handler by `type` and refuses `kind` by
name.

Who is affected: a deployment whose Base Registry Engine project was paired
by an earlier `caseworkctl source add`. Its `registry.yaml` carries the hook
with `kind`, which `bregctl check` of this release refuses with
`config.removed-key`.

To migrate, rename `kind` to `type` in the `handler` of each
`casework-lifecycle-v1-<entity>` hook in `registry.yaml`, keeping `url`, or
repeat `caseworkctl source add --apply` with this release, then build the
Base Registry Engine package again.

## Protocol words

A protocol word is a value Casework itself defines and writes where a caller
reads it or where it is stored: a lifecycle, a status, a decision type, an
outcome, a reason, an event kind. Each one is lowercase kebab-case
(CFG-NAME-2), the spelling the configuration files already use. Nothing an
operator writes in `casework.yaml` or `runtime.yaml` changes in this section.
There is no alias: the old spelling is not read from a request, and the new
spelling is the only one written. Audit consumers and archival queries that
span retained v0.39.0 and v0.40.0 records must match both the old and new
spellings listed below.

### BREAKING: the review protocol words are kebab-case

| Where | Member | Before | Now |
|---|---|---|---|
| review request | `lifecycle` | `changes_requested` | `changes-requested` |
| review result | `status` | `changes_requested` | `changes-requested` |
| reviewer decision (request body) | `decision.type` | `changes_requested` | `changes-requested` |
| cancel response | `outcome` | `already_terminal` | `already-terminal` |
| review task context | `bindingStatus` | `binding_changed` | `binding-changed` |
| review history entry `review-decided` | `detail.decision` | `changes_requested` | `changes-requested` |
| review history entry `review-decided` | `detail.transition` | `changes_requested` | `changes-requested` |
| review history entry `review-decided` | `detail.transition` | `stage_advanced` | `stage-advanced` |
| review history entry `review-settled` | `detail.status` | `changes_requested` | `changes-requested` |

HTTP: the values are returned by `GET /v1/review-requests/{request_id}`,
`GET /v1/review-requests/{request_id}/result`, `POST
/v1/review-requests/{request_id}/cancel`, `GET
/v1/review-tasks/{task_id}/context`, and `GET
/v1/review-requests/{request_id}/history`, and the decision type is read from the body of `POST
/v1/review-tasks/{task_id}/decisions`. A decision sent in the old spelling
is refused with the `request.unprocessable` problem and records nothing. The
committed OpenAPI document, the Rust clients (`registry-casework-client`,
`registry-review-client`), the Node.js declarations, the Python stubs, and
`@registrystack/client` carry the new values. A producer that reads a
review result, as the Base Registry Engine does, reads `changes-requested`.

Database and audit: the v0.40.0 schema stores only the new values, and new
audit records carry them. It does not convert v0.39.0 review rows, replay
records, or audit history.

Migration: reauthor the project, build the package with v0.40.0, and apply it
to a new database. Update callers that compare one of the values above or
send a `changes_requested` decision. Audit queries over retained v0.39.0 and
v0.40.0 records must match both spellings.

### BREAKING: the words `caseworkctl` prints in its reports are kebab-case

Every value `caseworkctl` writes in a `--format json` report is lowercase
kebab-case (CFG-NAME-2). These are the words that were still snake_case:

| Report | Member | Before | Now |
|---|---|---|---|
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `attempt_reserved` | `attempt-reserved` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `attempt_uncertain` | `attempt-uncertain` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `attempt_completed` | `attempt-completed` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `attempt_refused` | `attempt-refused` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `observe_open` | `observe-open` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `observe_waiting_applicant` | `observe-waiting-applicant` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `observe_waiting_application` | `observe-waiting-application` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `record_decision` | `record-decision` |
| `lifecycle` | `transitions[].event`, `enforcement[].events[]` | `advance_stage` | `advance-stage` |
| `lifecycle` | `states[].id`, `transitions[].to` | `changes_requested` | `changes-requested` |
| `check` | `effective.sources[].requests[].queueMode` | `first_match` | `first-match` |
| `check` | `effective.sourceDescription` | `pending_source_add` | `pending-source-add` |
| `source add` | `bregAuthoringChanges[].operation` | `ensure_exact` | `ensure-exact` |
| every report | `diagnostics[].artifact` | `runtime_dependency` | `runtime-dependency` |
| every report | `diagnostics[].artifact` | `runtime_configuration` | `runtime-configuration` |
| every report | `diagnostics[].artifact` | `authoring_input` | `authoring-input` |
| every report | `diagnostics[].artifact` | `operator_action` | `operator-action` |
| every report | `diagnostics[].artifact` | `command_arguments` | `command-arguments` |
| every report | `diagnostics[].artifact` | `dev_session` | `dev-session` |

The description of a review enforcement layer names the same events and
states in the new spelling. A diagnostic about a document still names it by
its `kind` (`CaseworkProject`, `CaseworkRuntimeConfig`); only the six words
for something that is not a document changed.

No file an adopter writes carries one of these words, no HTTP response
carries one, and nothing stored holds one, so no file changes and no
migration runs. The committed report examples under
`products/casework/examples/formats/reports` carry the new values.

Migration: update a script that compares one of the values above in a
`caseworkctl` report.

### BREAKING: the validation reason of a refused review submission is kebab-case

Casework refuses a review request or a reviewer's decision that fails
validation with the `request.invalid` problem and two response headers:
`Registry-Casework-Validation-Path` and
`Registry-Casework-Validation-Reason`. The reason is one word from a closed
set, and every word in the set is now lowercase kebab-case (CFG-NAME-2):

| Before | Now |
|---|---|
| `kind_not_allowed` | `kind-not-allowed` |
| `reference_invalid` | `reference-invalid` |
| `object_required` | `object-required` |
| `maximum_bytes_exceeded` | `maximum-bytes-exceeded` |
| `maximum_depth_exceeded` | `maximum-depth-exceeded` |
| `schema_mismatch` | `schema-mismatch` |
| `outcome_not_declared` | `outcome-not-declared` |
| `reason_required` | `reason-required` |
| `text_invalid` | `text-invalid` |
| `result_not_declared` | `result-not-declared` |
| `result_required` | `result-required` |
| `field_not_declared` | `field-not-declared` |
| `constraint_invalid` | `constraint-invalid` |
| `constraint_violated` | `constraint-violated` |

The same words are the `validation.reason` member the Rust client
(`registry-casework-client`), its Node.js and Python bindings, and the unified
`@registrystack/client` and `registry-stack-client` packages expose, and the
reason `registry-review-client` reads for a source that submits review
requests. The header names, the problem code, and the validation path are
unchanged.

There is no alias. A client of the previous release does not know the new
words, so it reports a refused submission as a protocol failure where it
reported the validation problem; a client of this release reads only the new
words and treats the previous spelling the same way. Nothing stored holds a
validation reason, so no file changes and no migration runs. The process log
field `validation_reason` of a refused display document carries the same word
in the new spelling.

Migration: upgrade the Casework clients with the runtime, and update code
that compares `validation.reason` with one of the words above.

### BREAKING: the history, event, and audit words are kebab-case

Every `kind` Casework writes in a history entry, every durable event kind,
and every audit event name is lowercase kebab-case (CFG-NAME-2). A word of
one segment (`observed`, `opened`, `claimed`, `assigned`, `delegated`,
`released`, `superseded`, `completed`, `note`) is unchanged. These are the words
that were still snake_case.

Work item history, the `kind` of an entry of
`GET /v1/work-items/{item_id}/history`, and the audit event `casework.<kind>`:

| Before | Now |
|---|---|
| `caseload_moved` | `caseload-moved` |
| `draft_saved` | `draft-saved` |
| `task_approved` | `task-approved` |
| `task_revoked` | `task-revoked` |
| `task_invalidated` | `task-invalidated` |
| `attempt_reserved` | `attempt-reserved` |
| `attempt_uncertain` | `attempt-uncertain` |
| `action_completed` | `action-completed` |
| `attempt_settled` | `attempt-settled` |
| `clock_reminder` | `clock-reminder` |
| `clock_step_applied` | `clock-step-applied` |
| `clock_recomputed` | `clock-recomputed` |

Review history, the `kind` of an entry of
`GET /v1/review-requests/{request_id}/history`, and the audit event
`casework.<kind>` where one is written:

| Before | Now |
|---|---|
| `request_created` | `request-created` |
| `review_created` | `review-created` |
| `review_decided` | `review-decided` |
| `review_settled` | `review-settled` |
| `review_cancelled` | `review-cancelled` |
| `review_superseded` | `review-superseded` |
| `stage_advanced` | `stage-advanced` |
| `task_assigned` | `task-assigned` |
| `task_claimed` | `task-claimed` |
| `task_delegated` | `task-delegated` |
| `task_released` | `task-released` |
| `task_draft_saved` | `task-draft-saved` |
| `task_absence_reconciled` | `task-absence-reconciled` |
| `task_grant_approved` | `task-grant-approved` |
| `task_grant_revoked` | `task-grant-revoked` |
| `task_grant_invalidated` | `task-grant-invalidated` |
| `clock_reminder` | `clock-reminder` |
| `clock_step_applied` | `clock-step-applied` |

Directory events, stored and written to audit as `casework.<kind>`:

| Before | Now |
|---|---|
| `directory_bootstrapped` | `directory-bootstrapped` |
| `team_updated` | `team-updated` |
| `absence_created` | `absence-created` |
| `absence_updated` | `absence-updated` |
| `absence_deleted` | `absence-deleted` |

Audit events with no history entry:

| Before | Now |
|---|---|
| `casework.holiday_revision_created` | `casework.holiday-revision-created` |
| `casework.review_accountability_read` | `casework.review-accountability-read` |
| `casework.review_note_added` | `casework.review-note-added` |
| `casework.source_retention_erased` | `casework.source-retention-erased` |
| `casework.package_activated` | `casework.package-activated` |

Values inside a history entry and a command report:

| Where | Member | Before | Now |
|---|---|---|---|
| `attempt-settled` history entry, `caseworkctl attempt settle` report | `outcome` | `not_applied` | `not-applied` |
| `released` history entry written by source reconciliation | `detail.reason` | `source_observation` | `source-observation` |
| `released` history entry written by directory reconciliation | `detail.reason` | `directory_membership_changed` | `directory-membership-changed` |

HTTP: the committed OpenAPI document, the Rust client
(`registry-casework-client`), the Node.js declarations, the Python stubs, and
`@registrystack/client` carry the new `kind` values. The
`caseworkctl attempt settle --outcome` option already read `not-applied`; its
JSON report now prints the same word.

Database and audit: the v0.40.0 schema stores only the new values, and new
audit records carry them, for example `casework.review-decided` and
`casework.task-invalidated`. It does not convert v0.39.0 history, durable
events, replay records, or audit history.

Migration: reauthor the project, build the package with v0.40.0, and apply it
to a new database. Update callers that compare a history `kind`, audit
consumers that select by event name, and scripts that read the `outcome` of a
settlement report. Audit queries over retained v0.39.0 and v0.40.0 records
must match both spellings.

### BREAKING: the clock, staffing, inbox, paging, and caseload words are kebab-case

The remaining closed values Casework writes in a response or reads in a
query are lowercase kebab-case (CFG-NAME-2). A word of one segment
(`running`, `paused`, `completed`, `cancelled`, `complete`, `moved`,
`conflict`, `mine`, `overdue`, `assignment`, `claim`, `nomination`,
`delegation`) is unchanged.

| Where | Member | Before | Now |
|---|---|---|---|
| `GET /v1/work-items/{item_id}/clocks` | `state` of a clock occurrence | `verification_pending` | `verification-pending` |
| `GET /v1/work-items/{item_id}/clocks`, `GET /v1/review-requests/{request_id}/clocks` | `state` of a clock occurrence | `source_facts_missing` | `source-facts-missing` |
| a work item | `assignment.staffingDiagnostic` | `no_cover_available` | `no-cover-available` |
| `GET /v1/review-requests/{request_id}/history` | `detail.assignmentKind` of an assignment entry | `absence_cover` | `absence-cover` |
| every paged read | `status` | `budget_exhausted` | `budget-exhausted` |
| every paged read | `status` | `source_unavailable` | `source-unavailable` |
| `POST /v1/directory/caseload/apply` | `result` of an item | `not_visible` | `not-visible` |
| `POST /v1/directory/caseload/apply` | `result` of an item | `not_eligible` | `not-eligible` |
| `POST /v1/directory/caseload/apply` | `result` of an item | `attempt_in_progress` | `attempt-in-progress` |
| `GET /v1/work-items` | `view` query value | `my_teams` | `my-teams` |
| `GET /v1/work-items` | `view` query value | `team_holdings` | `team-holdings` |
| `GET /v1/work-items` | `view` query value | `completed_by_me` | `completed-by-me` |
| `GET /v1/directory/targets` | `purpose` query value | `absence_person` | `absence-person` |
| `GET /v1/directory/targets` | `purpose` query value | `absence_cover` | `absence-cover` |

The query parameter names (`view`, `purpose`) do not change. A request that
names a view or a purpose in the old spelling is refused as any other
unknown value is.

HTTP: the committed OpenAPI document, the Rust client
(`registry-casework-client`), the Node.js declarations, the Python stubs, and
`@registrystack/client` carry the new values.

Database: the v0.40.0 schema, indexes, stored responses, and cursors use only
the new values. It does not convert v0.39.0 clock, staffing, inbox, replay, or
cursor state.

Migration: build the package with v0.40.0 and apply it to a new database.
Update callers that send `view` or `purpose`, or compare the `status` of a
page, the `state` of a clock occurrence, the `result` of a moved item, or
`staffingDiagnostic`.

### BREAKING: the correction action is named `request-correction`

A source action name belongs to the source adapter that offers it, with one
exception: Casework itself gives a meaning to the action that sends a
subject back for correction. When an action of that name completes,
Casework retains the reason and the flagged fields the officer gave as the
correction context of the work item, the context `routingCopy` is read
from. That one name is lowercase kebab-case (CFG-NAME-2).

| Where | Member | Before | Now |
|---|---|---|---|
| a work item | `actions[].operation` | `request_correction` | `request-correction` |
| `POST /v1/work-items/{item_id}/decisions` | `operation` of the request | `request_correction` | `request-correction` |
| `POST /v1/work-items/{item_id}/decisions`, the two attempt recovery routes | `operation` of the attempt | `request_correction` | `request-correction` |
| `GET /v1/work-items/{item_id}/history` | `detail.operation` of an attempt entry | `request_correction` | `request-correction` |

Who is affected: a deployment whose source adapter offers the correction
action, and the callers that send it. The Base Registry Engine adapter
offers `submit`, `revise`, `cancel`, and `apply` only, so a deployment that
uses no other adapter stores no such attempt and changes nothing. An
adapter built on `registry-casework-core` names the action with
`OperationName::REQUEST_CORRECTION`. The old spelling is still a valid
action name under the local identifier grammar, and it is an ordinary one:
an adapter that keeps offering `request_correction` has its action
executed, and no correction context is retained for it.

HTTP: the name is not an enumerated value of the OpenAPI document, so the
document and the generated clients do not change.

Database and audit: v0.40.0 does not convert stored action names or audit
records from v0.39.0. Migration: update the source adapter that offers the
action and every caller that sends it or compares `actions[].operation`, then
apply the rebuilt package to a new database.

### BREAKING: five client error words are written in kebab-case

The Node.js and Python Casework clients name a failure with fixed words a
caller branches on. Five of them carried an underscore (CFG-NAME-2): four
are the client's own, and the transport word comes from the shared HTTP
primitives, which respell it in this release.

| Member of `CaseworkClientError` (Node.js, Python) | Old word | New word |
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
