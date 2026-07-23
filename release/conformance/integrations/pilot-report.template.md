# External integration pilot report

Use this template only after an independent operator has completed the frozen
pilot journey. Publish a concise account of the outcome and link the validated,
sanitized result. Do not include credentials, network origins, operator or
source identifiers, record identifiers, raw audits, private evidence, or links
to restricted evidence.

Plans, dry runs, fixture runs, and source-built branch runs are not pilot
evidence. One completed pilot is not proof of broad production readiness.

## Closing evidence

- Sanitized run result: [link to the schema-valid public result]
- Frozen Registry Stack candidate: [link to the published release]
- Immutable Solmara release and release-pin evidence: [link]
- Independent operator: [confirmed or not confirmed; do not identify the
  operator]
- Owner-approved non-production source: [confirmed or not confirmed; do not
  identify the owner or source]
- Integration profile and reviewed operation: [safe public summary; the exact
  values remain in the sanitized result]
- Supported topology and journey: [safe public summary]
- Generated Registry YAML edited by hand: [no, or explain why the pilot does
  not close]
- Overall outcome: [passed, failed, or incomplete]

Issue closure still requires a frozen published candidate, an immutable Solmara
release pinned to that candidate, an independent operator, and an
owner-approved source. A plan or maintainer-run substitute cannot satisfy any
of these requirements.

## What the pilot did and did not prove

The pilot showed: [summarize only the bounded journey completed from published
artifacts, including offline checks and the selected Relay and, when
applicable, Notary flow].

The pilot did not show: [summarize excluded versions, operations, topologies,
scale, availability, recovery, or other support claims]. It is not upstream
product certification, general country-system conformance, a security audit,
or evidence that Registry Stack is broadly production-ready.

## Findings and triage

Use safe summaries and public issue or pull-request links. Record `not
exercised` rather than inferring success.

| Area | Exercised | Sanitized outcome | Public triage links |
|---|---|---|---|
| Operator handoff and independence | [yes/no] | [summary] | [links or none] |
| Install or deployment | [yes/no] | [summary] | [links or none] |
| Configuration and environment binding | [yes/no] | [summary] | [links or none] |
| Diagnostics and ordinary source failures | [yes/no] | [summary] | [links or none] |
| Upgrade or rollback | [yes/no] | [summary] | [links or none] |
| Restart, teardown, and other operations | [yes/no] | [summary] | [links or none] |
| Security boundaries and redaction | [yes/no] | [summary] | [links or none] |
| Documentation and operator journey | [yes/no] | [summary] | [links or none] |

### Blocking findings

List each blocker with its public triage issue, fix, and independent
re-verification link. Unresolved blockers keep the pilot open.

- [none, or safe finding summary and links]

### Accepted limitations and narrowed support

List each owner-approved limitation or narrowed support claim with its public
decision, operator-guidance update, support-wording update, and review trigger.
Do not use this section to waive a blocker silently.

- [none, or safe limitation summary and links]

## Conclusion

[State whether the bounded pilot closes the external-pilot gate, remains
blocked, or requires a narrower support claim. Reiterate any unexercised area
that affects the conclusion.]
