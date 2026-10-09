# Registry Casework Node binding

This internal napi-rs binding supplies the `casework` module assembled into
`@registrystack/client`. Applications should use that unified package.

Every operation accepts a bearer token and an explicit Casework profile for
that call. Source-reading operations also require an explicit source profile.
The binding does not retain credentials and exposes no browser credential API.

`reviewTasks(token, profile, { ownership: 'assigned_to_me' })` filters the
reviewer inbox before pagination. `supervisoryReviewTasks` provides current
supervisors with bounded task and accountability references for served queues.
Its `state` is a holder-free string. A single decided-task read carries `decisionReceipt` only for the principal
whose decision it records.

Task delegation uses the current human profile for template previews, grant
approval, listing, and revocation. Approval accepts only the template ID and
version, with the item revision and a caller-owned idempotency key. The preview
contains the exact destination, purpose, immutable bounds, derived subjects,
and lifetime; the grant list omits stored subjects. Agent assertion and grant
status calls take only a bearer token and grant ID, without human or source
profile headers. Neither binding retains credentials or resends a mutation
beyond the bounded same-key retry below.

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
