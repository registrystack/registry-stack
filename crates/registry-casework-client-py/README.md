# Registry Casework Python binding

This internal PyO3 binding is assembled into the public
`registry-stack-client` wheel. Use it through `registry_client.casework`:

```python
from registry_client import casework

client = casework.CaseworkClient("https://casework.example.invalid/")
page = client.review_tasks(
    token,
    "staff",
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
