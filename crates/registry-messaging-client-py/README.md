# Registry Messaging Python binding

This internal PyO3 binding is assembled into the public
`registry-stack-client` wheel. Use it through `registry_client.messaging`:

```python
from registry_client import messaging

client = messaging.MessagingClient("https://messaging.example.invalid/")
receipt = client.submit(
    token,
    "reminder-2026-09-25-0001",
    {
        "senderProfile": "reminders-sms",
        "to": {"phone": "+15550100"},
        "template": {"id": "appointment-reminder", "version": "1"},
        "locale": "en",
        "data": {"time": "10:00"},
    },
)
view = client.message(token, receipt["value"]["id"])
cancelled = client.cancel(token, receipt["value"]["id"])
preview = client.preview(
    token,
    "appointment-reminder",
    "1",
    {"locale": "en", "data": {"time": "10:00"}},
)
```

The client keeps service configuration, but never a bearer token. Supply it
explicitly on each call; `health` and `ready` take none. A submission requires
the idempotency key chosen by the caller, 1 to 128 visible ASCII characters;
the binding refuses any other key before a request is sent, and never invents
or replaces a key or retries a submission or a cancellation. A message
identifier, template identifier, or version outside the runtime's grammar is
refused before a request is sent. Results use the canonical Rust
client's camel-case wire DTOs inside a
`{"kind": "complete", "value": ..., "trace_id": ...}` envelope.

`MessagingClientError` preserves the problem code, its pinned title and
detail, the status, and trace context, so a caller handles a reused or
expired idempotency key, a cancellation that lost the race to dispatch, and a
template refusal explicitly. A submission over its access profile's request
rate or daily limit answers `rate-limit.exceeded` or `quota.exceeded` with
status 429, and `retry_after_seconds` carries the wait the runtime asked for,
at most one day; it is `None` on every other failure. The client never waits
or retries.

This crate is private and does not publish a standalone Python distribution.
