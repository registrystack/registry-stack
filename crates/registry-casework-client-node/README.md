# Registry Casework Node binding

This internal napi-rs binding supplies the `casework` module assembled into
`@registrystack/client`. Applications should use that unified package.

Every operation accepts a bearer token and an explicit Casework profile for
that call. Source-reading operations also require an explicit source profile.
The binding does not retain credentials and exposes no browser credential API.

`reviewTasks(token, profile, { ownership: 'assigned-to-me' })` filters the
reviewer inbox before pagination. `supervisoryReviewTasks` provides current
supervisors with bounded task and accountability references for served queues.
Its `state` is a holder-free string. A single decided-task read carries `decisionReceipt` only for the principal
whose decision it records.

`ownReviewDecisions(token, profile, { queue: 'review', limit: 25 }, sourceProfile)`
discovers that caller's retained decisions, newest first, without a saved task
link. Rows carry only task/request ids, queue, producer `requesterReference`
and the own `decisionReceipt`; reopen with `reviewTask`. Author, pinned deciding
profile, membership, queue service, source visibility and result retention are
checked before disclosure. Prior holding is not authorship. Keep the caller,
profiles, queue and own-decisions view unchanged when following `nextCursor`;
on `410 review.result-expired`, refetch without a cursor.

`decisionReceipt.outcomeLabel` is the decision-time pinned policy label, never
the current policy's label. Approval has no outcome or label. The explicit
audited `reviewAccountability` read also returns that receipt through its
independent accountability retention, including after result erasure. A legacy
non-approval selection already erased at upgrade omits the receipt. Own history
and single-task receipts end at result expiry or erasure.

Pass `{ requestId: canonicalRequestUuid, queue: 'review', limit: 25 }` to
`supervisoryReviewTasks` to select a shared request before pagination. Keep
`requestId` unchanged when following `nextCursor`. The UUID is validated before
I/O, and every response row must match it. Unknown or inaccessible requests
produce a neutral empty page under current list semantics. The reference
grants no decision, content, or accountability authority.

Task delegation uses the current human profile for template previews, grant
approval, listing, and revocation. Approval accepts only the template ID and
version, with the item revision and a caller-owned idempotency key. The preview
contains the exact destination, purpose, immutable bounds, derived subjects,
and lifetime; the grant list omits stored subjects. Agent assertion and grant
status calls take only a bearer token and grant ID, without human or source
profile headers. Neither binding retains credentials or resends a mutation
beyond the bounded same-key retry below.

Previews and grant views include `authorizationMode: "deferred"` for a deferred
template; omission means the existing immediate mode. Approval still selects
only the governed template ID and version. Keep the grant ID, original deadline,
and business operation's idempotency key across a delay or restart. Acquire a
fresh assertion when executing; its short credential lifetime does not extend
the approved deadline. See the [task-grant lifecycle](../../products/casework/TASK_GRANTS.md)
for expiry, revocation, and changes that require another approval.

A keyed mutation whose outcome is unknown (a timeout or broken exchange after
it was sent, an unusable answer, or a 5xx) is resent identically under the same
key up to `maxMutationRetries` times: 0 to 2, default 2, and 0 sends it once.
Reads, unkeyed operations, and review request create and cancel are never
resent. When the returned `CaseworkClientError` still reports `outcomeUnknown`,
the mutation may have taken effect: recover by sending it again under the same
key, because a new key could apply it twice. `outcomeUnknown` is false for a
configuration or request defect, a connection never established, and every 4xx
refusal. It is false for `410 idempotency.expired` too, but there an earlier
attempt under the key committed and only its stored response was erased by
retention: reconcile the original operation, by reading the item, review
request, or directory, before choosing a new key.
