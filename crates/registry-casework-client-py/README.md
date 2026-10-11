# Registry Casework Python binding

This internal PyO3 binding is assembled into the public
`registry-stack-client` wheel. Use it through `registry_client.casework`:

```python
from registry_client import casework

client = casework.CaseworkClient("https://casework.example.invalid/")
page = client.review_tasks(
    token,
    "staff",
    {"queue": "review", "ownership": "assigned-to-me", "limit": 25},
)
supervised = client.supervisory_review_tasks(
    supervisor_token,
    "supervisor",
    {"queue": "review", "limit": 25},
)
```

The client keeps service configuration, but never a bearer token or selected
profile. Supply those explicitly on each call. Mutations also require the
revision and idempotency key chosen by the caller; the binding never replaces
them. Results use the canonical Rust client's camel-case wire DTOs
inside a `{"kind": "complete", "value": ..., "trace_id": ...}` envelope.

Requester review operations omit a source profile. Officer task reads, claims,
assignment, delegation, drafts, decisions, history, notes, and review clocks
accept an optional source profile when resolving source context. Accountability
and kind discovery remain Casework-owned authorization paths.
Supervisory discovery returns only bounded task and accountability references,
with a holder-free string state.
Its query accepts `{"requestId": canonical_request_uuid, "limit": 25}` to find
a shared request before pagination, optionally combined with `queue`. Keep that
selection unchanged when following `nextCursor`. Invalid UUIDs fail before I/O,
and response rows must match the selection. Unknown or inaccessible requests
produce a neutral empty page under current list semantics. A reference grants
no decision, content, or accountability authority.
A single decided-task read includes `decisionReceipt` only when
`decidedByCaller` is true.

`own_review_decisions(token, profile, {"queue": "review", "limit": 25}, source_profile)`
discovers the caller's retained decisions, newest first, without a saved task
link. Each row has only task/request ids, queue, producer `requesterReference`
and the same own `decisionReceipt` returned by `review_task`. Current deciding
profile, membership, served queue, source visibility and result retention
remain required. Prior holding is not authorship. Keep the caller, profiles,
queue and own-decisions view unchanged when following `nextCursor`; refetch
without a cursor after `410 review.result-expired`.

Receipts carry the optional decision-time pinned `outcomeLabel`, which cannot
follow current policy edits. Approval has no outcome or label. The explicit
audited Supervisor `review_accountability` read includes that receipt through
its independent accountability retention, including after result erasure.
Legacy non-approval selections already erased at upgrade omit the receipt.
Own discovery and single-task receipts end at result expiry or erasure.

`CaseworkClientError` preserves problem codes, status, trace context, validation
details, and original attempt identifiers. Callers can therefore handle cursor
or idempotency expiry explicitly; the binding never replaces a key.

A keyed mutation whose outcome is unknown (a timeout or broken exchange after
it was sent, an unusable answer, or a 5xx) is resent identically under the same
key up to `max_mutation_retries` times: 0 to 2, default 2, and 0 sends it once.
Reads, unkeyed operations, and review request create and cancel are never
resent. When the returned `CaseworkClientError` still reports
`outcome_unknown`, the mutation may have taken effect: recover by sending it
again under the same key, because a new key could apply it twice.
`outcome_unknown` is false for a configuration or request defect, a connection
never established, and every 4xx refusal. It is false for
`410 idempotency.expired` too, but there an earlier attempt under the key
committed and only its stored response was erased by retention: reconcile the
original operation, by reading the item, review request, or directory, before
choosing a new key.

This crate is private and does not publish a standalone Python distribution.

Task delegation uses the current human profile for template previews, grant
approval, listing, and revocation. Approval accepts only the template ID and
version, with the item revision and a caller-owned idempotency key. The preview
contains the exact destination, purpose, immutable bounds, derived subjects,
and lifetime; the grant list omits stored subjects. Agent assertion and grant
status calls take only a bearer token and grant ID, without human or source
profile headers. Neither binding retains credentials or resends a mutation
beyond the bounded same-key retry above.

Previews and grant views include `authorizationMode: "deferred"` for a deferred
template; omission means the existing immediate mode. Approval still selects
only the governed template ID and version. Keep the grant ID, original deadline,
and business operation's idempotency key across a delay or restart. Acquire a
fresh assertion when executing; its short credential lifetime does not extend
the approved deadline. See the [task-grant lifecycle](../../products/casework/TASK_GRANTS.md)
for expiry, revocation, and changes that require another approval.
