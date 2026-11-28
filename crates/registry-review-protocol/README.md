# Registry review protocol

This crate owns the runtime-free wire types exchanged between an admitted
producer and an independently authorized review provider. Registry Casework
provides human review; Registry Coordinator may hand a workflow item to Casework
under its own admitted producer identity.
Business sources such as BReg use the types to bind submissions and verify
results without depending on the Casework runtime, task model, policy engine,
or database.

Producer operations use `Registry-Review-Profile` and bounded
`Registry-Review-Validation-Path`/`Registry-Review-Validation-Reason` diagnostics.
Problem type URIs may belong to the provider. Clients treat them as opaque
identifiers, never dereference them, and conservatively classify unknown failures.
Provider-specific human task and policy-evaluation APIs remain provider-owned.

Successful creation and recovery responses may include `Registry-Review-Producer`.
It names the authenticated producer selected by the provider, not an identity
inferred from a digest. The header has one value of 1 to 128 ASCII letters,
digits, hyphens, underscores, periods or colons. Registry Casework supplies it
on both 201 creation and 200 recovery. The accepted JSON envelope is unchanged.

The submission digest covers the authenticated producer, source namespace,
and complete create request, including its original `PolicySelection`.
The default selector is `{"id":"review-policy"}` and delegates version choice
to the trusted provider at first acceptance. Strict mode adds both `version`
and `digest`; partial pins are invalid. The provider atomically persists the
concrete `PolicyBinding`, policy snapshot and idempotent acceptance. Retries
recover that acceptance before consulting current policy. Results repeat the
accepted exact binding, while the original selector and submission digest stay
unchanged. A new request from the same producer for the same subject and
policy supersedes every live one: the provider settles each as `superseded`.
The subject here is its source, type and identifier, not its version. JSON
values are bounded by canonical byte size,
nesting depth, and node count so the same contract applies to parsed and
programmatically constructed values.

`ReviewRequestView.progressCode` is an optional, provider-authored projection
with the bounded local-identifier grammar `^[a-z][a-z0-9_-]{0,63}$`. Providers
omit it unless a producer explicitly requests progress. It is not a shared
stage model: absent mappings and terminal requests have no code, and raw
provider stage, task or reviewer details remain provider-owned.

The crate contains no HTTP client, credentials, persistence, source adapter,
policy evaluator, reviewer task, or source execution code. In particular, a
completion envelope is only a synchronization hint. It cannot carry approval
evidence or authorize a source operation.

An ask is a reviewer's request for more from the subject's owner. The provider
owns it. The producer finds it through the ask feed (`GET /v1/review-asks`,
announcements of ids and times only), reads it at
`/v1/review-requests/{requestId}/asks/{askId}`, and reports it answered with
`POST .../answer`. `ReviewAsk` carries reviewer text bounded like a public
reason, up to eight distinct `wants` (`answer`, `document`), an optional
absolute `dueAt` and a state (`open`, `answered`, `expired`, `closed`).
`askedAt` comes first: `dueAt`, `answeredAt` and `closedAt` are never before it.
`answeredAt` is present exactly when the ask is answered, and `closedAt` exactly
when it is expired or closed. An expired ask has a `dueAt`, and its `closedAt`
is not before it. `ReviewAskAnswer` holds only the subject binding and the
answer time, so it cannot carry the answer itself. The answer time has at most
microsecond precision, so the producer stores and replays exactly the value the
provider keeps.

Rules for the provider:

- A provider judges an answer by its `answeredAt`, not by when it arrives. An
  answer whose `answeredAt` is at or before `dueAt` is accepted even if the ask
  already reads `expired`, and the ask then reads `answered`. A delivery delay
  never makes an on-time answer late.
- Only a not-open ask refuses an answer with 409 and the problem code
  `review.ask-not-open` (`REVIEW_ASK_NOT_OPEN_PROBLEM`). Every other 409, such
  as a reused idempotency key, carries its own code.
- A concealed or unknown ask is an empty 404, as for the result read.
- A provider sends only want kinds the producer's protocol version knows. An
  unknown kind is refused when the ask is decoded, so a producer on an older
  version cannot read the ask at all. The limit of eight wants stays for kinds
  that may repeat.
- A provider validates an ask with `ReviewAsk::check` before it stores it.

Keep producer and provider clocks synchronized within five minutes: Casework permanently refuses an `answeredAt` beyond that future tolerance with `review.ask-answer-time-invalid`.

Rules for the producer:

- Never stall the feed on one bad ask. For a deterministic refusal (a
  protocol failure on the ask, or a not-found), record it and move on. For a
  transient failure (transport, 5xx), stop the page and retry from the same
  cursor.
- A stored copy of an ask only moves forward: `open` becomes exactly one of
  `answered`, `expired` or `closed`, never back. Two readers of the same ask
  must not store an older copy over a newer one.
- After a `NotOpen` outcome, read the ask to learn which state it is in.
- Use one idempotency key per ask, and store it with the `answeredAt` that was
  sent, so a retry after an ambiguous failure replays the same body.
