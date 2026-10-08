# Registry Casework: configuration conventions

Every Registry Casework change the configuration conventions make, with the
step that migrates a file or a script. The Casework `CHANGELOG.md` points here.

## BREAKING: `casework.yaml` is read by the shared configuration reader

`caseworkctl` (every command that reads a project: `check`, `explain`,
`test`, `simulate`, `package`, `source add`, and `dev`) and the `casework`
runtime read `casework.yaml` through the reader every Registry Stack product
shares.

- Every problem in the file is reported, each as its own diagnostic with the
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
- `casework.review-kind.*`: `casework.review-kind.accountability-before-terminal`, `casework.review-kind.answer-stage-approvals`, `casework.review-kind.answer-stage-count`, `casework.review-kind.answer-without-outcomes`, `casework.review-kind.answered-outcome-in-approval`, `casework.review-kind.duplicate-clock`, `casework.review-kind.duplicate-deciding-profile`, `casework.review-kind.duplicate-id`, `casework.review-kind.duplicate-outcome-id`, `casework.review-kind.duplicate-stage-id`, `casework.review-kind.ineligible-deciding-profile`, `casework.review-kind.invalid-clock`, `casework.review-kind.invalid-deciding-profile`, `casework.review-kind.invalid-display-schema`, `casework.review-kind.invalid-id`, `casework.review-kind.invalid-outcome-id`, `casework.review-kind.invalid-outcome-label`, `casework.review-kind.invalid-result-schema`, `casework.review-kind.invalid-stage-id`, `casework.review-kind.invalid-stage-queue`, `casework.review-kind.invalid-version`, `casework.review-kind.no-deciding-profiles`, `casework.review-kind.no-stages`, `casework.review-kind.required-approvals-out-of-range`, `casework.review-kind.result-required-without-result-schema`, `casework.review-kind.retention-out-of-range`, `casework.review-kind.too-many-clocks`, `casework.review-kind.too-many-deciding-profiles`, `casework.review-kind.too-many-outcomes`, `casework.review-kind.too-many-stages`, `casework.review-kind.too-many`, `casework.review-kind.unanswered-outcome-in-answer`, `casework.review-kind.unknown-clock`, `casework.review-kind.unknown-queue`.
- `casework.review-producer.*`: `casework.review-producer.duplicate-id`, `casework.review-producer.duplicate-kind`, `casework.review-producer.duplicate-principal`, `casework.review-producer.duplicate-source-namespace`, `casework.review-producer.ineligible-initiator-profile`, `casework.review-producer.invalid-completion-destination`, `casework.review-producer.invalid-id`, `casework.review-producer.invalid-initiator-profile`, `casework.review-producer.invalid-issuer`, `casework.review-producer.invalid-kind`, `casework.review-producer.invalid-profile`, `casework.review-producer.invalid-recipient-binding`, `casework.review-producer.invalid-source-namespace`, `casework.review-producer.invalid-subject`, `casework.review-producer.invalid-trusted-initiator-issuer`, `casework.review-producer.missing-trusted-initiator-issuer`, `casework.review-producer.no-kinds`, `casework.review-producer.no-source-namespaces`, `casework.review-producer.none`, `casework.review-producer.not-a-requester-profile`, `casework.review-producer.recovery-days-out-of-range`, `casework.review-producer.recovery-exceeds-retention`, `casework.review-producer.too-many-kinds`, `casework.review-producer.too-many-source-namespaces`, `casework.review-producer.too-many`, `casework.review-producer.unknown-review-kind`, `casework.review-producer.without-review-kinds`.
- `casework.routing.*`: `casework.routing.duplicate-predicate-value`, `casework.routing.duplicate-projection-field`, `casework.routing.duplicate-rule-id`, `casework.routing.empty-condition`, `casework.routing.field-not-projected`, `casework.routing.invalid-because`, `casework.routing.invalid-predicate-value`, `casework.routing.invalid-rule-id`, `casework.routing.invalid-source-description`, `casework.routing.invalid-source-value`, `casework.routing.predicate-value-count`, `casework.routing.stage-without-review`, `casework.routing.too-many-predicates`, `casework.routing.too-many-projection-fields`, `casework.routing.too-many-rules`, `casework.routing.unexpected-source-state`, `casework.routing.unknown-field`, `casework.routing.unknown-queue`, `casework.routing.unknown-stage`, `casework.routing.unreachable-rule`.
- `casework.source.*`: `casework.source.duplicate-id`, `casework.source.empty-adapter`, `casework.source.empty-description`, `casework.source.empty-id`, `casework.source.no-requests`.
- `casework.task-template.*`: `casework.task-template.duplicate-entry`, `casework.task-template.duplicate-id`, `casework.task-template.duplicate-permission`, `casework.task-template.empty-list`, `casework.task-template.ineligible-profile`, `casework.task-template.invalid-audience`, `casework.task-template.invalid-bounds`, `casework.task-template.invalid-entry`, `casework.task-template.invalid-id`, `casework.task-template.invalid-operation`, `casework.task-template.invalid-purpose`, `casework.task-template.invalid-requester-tag`, `casework.task-template.invalid-scope`, `casework.task-template.invalid-subject-claim`, `casework.task-template.invalid-subject-field`, `casework.task-template.invalid-team`, `casework.task-template.invalid-text`, `casework.task-template.lifetime-out-of-range`, `casework.task-template.missing-evidence-context`, `casework.task-template.mixed-eligibility`, `casework.task-template.no-eligibility`, `casework.task-template.permissions-out-of-range`, `casework.task-template.subjects-out-of-range`, `casework.task-template.too-many-entries`, `casework.task-template.too-many`, `casework.task-template.unexpected-evidence-context`, `casework.task-template.unknown-item-kind`, `casework.task-template.unknown-review-kind`, `casework.task-template.unknown-source`, `casework.task-template.unsupported-item-state`.
