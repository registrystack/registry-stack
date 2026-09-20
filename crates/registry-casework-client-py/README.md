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
revision and idempotency key chosen by the caller; the binding does not retry
or replace them. Results use the canonical Rust client's camel-case wire DTOs
inside a `{"kind": "complete", "value": ..., "trace_id": ...}` envelope.

Requester review operations omit a source profile. Officer task reads, claims,
assignment, delegation, drafts, decisions, history, and notes accept an optional
source profile when resolving source context. Accountability and kind discovery
remain Casework-owned authorization paths.

`CaseworkClientError` preserves problem codes, status, trace context, validation
details, and original attempt identifiers. Callers can therefore handle cursor
or idempotency expiry explicitly; the binding does not retry or replace a key.

This crate is private and does not publish a standalone Python distribution.

Task delegation uses the current human profile for template previews, grant
approval, listing, and revocation. Approval accepts only the template ID and
version, with the item revision and a caller-owned idempotency key. The preview
contains the exact destination, purpose, immutable bounds, derived subjects,
and lifetime; the grant list omits stored subjects. Agent assertion and grant
status calls take only a bearer token and grant ID, without human or source
profile headers. Neither binding retains credentials or retries a mutation.
