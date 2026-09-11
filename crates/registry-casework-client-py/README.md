# Registry Casework Python binding

This internal PyO3 binding is assembled into the public
`registry-stack-client` wheel. Use it through `registry_client.casework`:

```python
from registry_client import casework

client = casework.CaseworkClient("https://casework.example.invalid/")
page = client.list_hosted_work_items(
    token,
    "staff",
    {"view": "mine", "limit": 25},
)
```

The client keeps service configuration, but never a bearer token or selected
profile. Supply those explicitly on each call. Mutations also require the
revision and idempotency key chosen by the caller; the binding does not retry
or replace them. Results use the canonical Rust client's camel-case wire DTOs
inside a `{"kind": "complete", "value": ..., "trace_id": ...}` envelope.

Requester hosted operations omit a source profile. Source-backed staff
item operations require one explicitly. Staff operations that can address
hosted or source-backed work accept an optional source profile and preserve the
caller's choice. These are separate authorization paths even when used from the
same client instance.

`CaseworkClientError` preserves problem codes, status, trace context, validation
details, and original attempt identifiers. Callers can therefore handle cursor
or idempotency expiry explicitly; the binding does not retry or replace a key.

This crate is private and does not publish a standalone Python distribution.
