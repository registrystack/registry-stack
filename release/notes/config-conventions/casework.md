# Registry Casework: configuration conventions

Every Registry Casework change the configuration conventions make, with the
step that migrates a file or a script. The Casework `CHANGELOG.md` points here.

## BREAKING: `casework.yaml` is read by the shared configuration reader
<!-- upgrade: casework-project-reader-refusals -->

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
<!-- upgrade: casework-project-bounds -->

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
<!-- upgrade: casework-runtime-reader-refusals -->

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
<!-- upgrade: no-file -->

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
<!-- upgrade: no-file -->

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
<!-- upgrade: no-file -->

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
<!-- upgrade: casework-fixture-spelling, casework-fixture-target, casework-simulation-file-extension, casework-simulation-spelling, casework-holiday-set-envelope, casework-holiday-set-file-name -->

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
- `caseworkctl simulate --fixture FILE` reports the same diagnostics for the
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

## BREAKING: a project check reads a bounded number of files
<!-- upgrade: casework-project-file-bounds -->

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
<!-- upgrade: no-file -->

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
<!-- upgrade: casework-dev-clients-envelope -->

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
<!-- upgrade: casework-dev-session-reset -->

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
<!-- upgrade: no-file -->

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
<!-- upgrade: casework-runtime-empty-assertion-issuers -->

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
- `casework.project.*`: `casework.project.empty-id`, `casework.project.empty-version`, `casework.project.no-work`, `casework.project.wrong-api-version`, `casework.project.wrong-kind`.
- `casework.queue.*`: `casework.queue.duplicate-id`, `casework.queue.invalid-id`, `casework.queue.invalid-label`, `casework.queue.none`.
- `casework.request.*`: `casework.request.duplicate-context-field`, `casework.request.duplicate-entity`, `casework.request.empty-entity`, `casework.request.empty-target-id`, `casework.request.invalid-context-field`, `casework.request.invalid-display-reference`, `casework.request.invalid-target-elapsed`, `casework.request.too-many-context-fields`, `casework.request.unknown-clock`.
- `casework.review-kind.*`: `casework.review-kind.accountability-before-terminal`, `casework.review-kind.answer-stage-approvals`, `casework.review-kind.answer-stage-count`, `casework.review-kind.answer-without-outcomes`, `casework.review-kind.answered-outcome-in-approval`, `casework.review-kind.display-hides-disclosure`, `casework.review-kind.duplicate-clock`, `casework.review-kind.duplicate-deciding-profile`, `casework.review-kind.duplicate-id`, `casework.review-kind.duplicate-outcome-id`, `casework.review-kind.duplicate-stage-id`, `casework.review-kind.ineligible-deciding-profile`, `casework.review-kind.invalid-clock`, `casework.review-kind.invalid-deciding-profile`, `casework.review-kind.invalid-display-schema`, `casework.review-kind.invalid-id`, `casework.review-kind.invalid-outcome-id`, `casework.review-kind.invalid-outcome-label`, `casework.review-kind.invalid-result-schema`, `casework.review-kind.invalid-stage-id`, `casework.review-kind.invalid-stage-queue`, `casework.review-kind.invalid-version`, `casework.review-kind.no-deciding-profiles`, `casework.review-kind.no-stages`, `casework.review-kind.required-approvals-out-of-range`, `casework.review-kind.result-required-without-result-schema`, `casework.review-kind.retention-out-of-range`, `casework.review-kind.too-many-clocks`, `casework.review-kind.too-many-deciding-profiles`, `casework.review-kind.too-many-outcomes`, `casework.review-kind.too-many-stages`, `casework.review-kind.too-many`, `casework.review-kind.unanswered-outcome-in-answer`, `casework.review-kind.unknown-clock`, `casework.review-kind.unknown-queue`.
- `casework.review-producer.*`: `casework.review-producer.duplicate-id`, `casework.review-producer.duplicate-kind`, `casework.review-producer.duplicate-principal`, `casework.review-producer.duplicate-source-namespace`, `casework.review-producer.ineligible-initiator-profile`, `casework.review-producer.invalid-completion-destination`, `casework.review-producer.invalid-id`, `casework.review-producer.invalid-initiator-profile`, `casework.review-producer.invalid-issuer`, `casework.review-producer.invalid-kind`, `casework.review-producer.invalid-profile`, `casework.review-producer.invalid-recipient-binding`, `casework.review-producer.invalid-source-namespace`, `casework.review-producer.invalid-subject`, `casework.review-producer.invalid-trusted-initiator-issuer`, `casework.review-producer.missing-trusted-initiator-issuer`, `casework.review-producer.no-kinds`, `casework.review-producer.no-source-namespaces`, `casework.review-producer.none`, `casework.review-producer.not-a-requester-profile`, `casework.review-producer.recovery-days-out-of-range`, `casework.review-producer.recovery-exceeds-retention`, `casework.review-producer.too-many-kinds`, `casework.review-producer.too-many-source-namespaces`, `casework.review-producer.too-many`, `casework.review-producer.unknown-review-kind`, `casework.review-producer.without-review-kinds`.
- `casework.routing.*`: `casework.routing.duplicate-predicate-value`, `casework.routing.duplicate-projection-field`, `casework.routing.duplicate-rule-id`, `casework.routing.empty-condition`, `casework.routing.field-not-projected`, `casework.routing.invalid-because`, `casework.routing.invalid-predicate-value`, `casework.routing.invalid-rule-id`, `casework.routing.invalid-source-description`, `casework.routing.invalid-source-value`, `casework.routing.predicate-value-count`, `casework.routing.stage-without-review`, `casework.routing.too-many-predicates`, `casework.routing.too-many-projection-fields`, `casework.routing.too-many-rules`, `casework.routing.unexpected-source-state`, `casework.routing.unknown-field`, `casework.routing.unknown-queue`, `casework.routing.unknown-stage`, `casework.routing.unreachable-rule`.
- `casework.source.*`: `casework.source.ambiguous`, `casework.source.duplicate-id`, `casework.source.empty-adapter`, `casework.source.empty-description`, `casework.source.empty-id`, `casework.source.no-requests`, `casework.source.none`, `casework.source.too-many`, `casework.source.too-many-requests`, `casework.source.unknown`, `casework.source.unpublished-field`, `casework.source.unsupported-adapter`.
- `casework.source-description.*`: `casework.source-description.contract-mismatch`, `casework.source-description.missing`, `casework.source-description.review-kind-not-approval`, `casework.source-description.review-kind-not-source-context`, `casework.source-description.review-not-admitted`, `casework.source-description.unknown-review-kind`.
- `casework.source-revision.*`: `casework.source-revision.stale`.
- `casework.task-template.*`: `casework.task-template.duplicate-entry`, `casework.task-template.duplicate-id`, `casework.task-template.duplicate-permission`, `casework.task-template.empty-list`, `casework.task-template.ineligible-profile`, `casework.task-template.invalid-audience`, `casework.task-template.invalid-bounds`, `casework.task-template.invalid-entry`, `casework.task-template.invalid-id`, `casework.task-template.invalid-operation`, `casework.task-template.invalid-purpose`, `casework.task-template.invalid-requester-tag`, `casework.task-template.invalid-scope`, `casework.task-template.invalid-subject-claim`, `casework.task-template.invalid-subject-field`, `casework.task-template.invalid-team`, `casework.task-template.invalid-text`, `casework.task-template.lifetime-out-of-range`, `casework.task-template.missing-evidence-context`, `casework.task-template.mixed-eligibility`, `casework.task-template.no-eligibility`, `casework.task-template.permissions-out-of-range`, `casework.task-template.subjects-out-of-range`, `casework.task-template.too-many-entries`, `casework.task-template.too-many`, `casework.task-template.unexpected-evidence-context`, `casework.task-template.unknown-item-kind`, `casework.task-template.unknown-review-kind`, `casework.task-template.unknown-source`, `casework.task-template.unsupported-item-state`.
