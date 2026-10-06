# Registry Scheduling Python binding

This internal PyO3 binding is not published separately. Beginning with Registry
Stack v0.40.0, its namespace and native extension ship inside the public
`registry-stack-client` wheel. Built on its own, it is used like this:

```python
import registry_scheduling_client as scheduling

client = scheduling.SchedulingClient("https://scheduling.example.invalid/")
slots = client.availability(
    token,
    "registry-update-30",
    start="2026-10-05T08:00:00Z",
    end="2026-10-05T12:00:00Z",
)
hold = client.create_hold(
    token,
    "hold-2026-10-05-0001",
    {
        "offering": "registry-update-30",
        "start": "2026-10-05T09:00:00Z",
        "party": {"recipients": 1, "attendees": 1},
        "policyRevision": 3,
        "capabilities": [],
        "prerequisites": [],
    },
)
appointment = client.create_appointment(
    token, "confirm-2026-10-05-0001", {"hold": hold["value"]["holdId"]}
)
```

The client keeps service configuration, but never a bearer token. Supply it
explicitly on each call. `create_hold`, `create_appointment`,
`reschedule_appointment`, and `cancel_appointment` require the idempotency key
chosen by the caller, 1 to 128 visible ASCII characters; the binding refuses
any other key before a request is sent, and never invents or replaces a key.
Offering selectors, hold and appointment identifiers, cursors, page limits,
external references, and instants are checked before a request is sent;
instants are RFC 3339 strings, normalized to UTC. Request documents refuse a
member the contract does not declare. Results use the
canonical Rust client's camel-case wire DTOs inside a
`{"kind": "complete", "value": ..., "trace_id": ...}` envelope.

`SchedulingClientError` preserves the problem code, its pinned title and
detail, the status, and trace context, so a caller handles exhausted capacity,
an expired hold, a stale revision, or a reused idempotency key explicitly. A
code outside the closed catalogue is a protocol failure.

A keyed command (hold, appointment create, reschedule, cancel) whose outcome is
unknown (a timeout or broken exchange after it was sent, an unusable answer,
or a 5xx) is resent identically under the same key up to
`max_mutation_retries` times: 0 to 2, default 2, and 0 sends it once. Reads and
the unkeyed hold release are never resent. When the returned
`SchedulingClientError` still reports `outcome_unknown`, the command may have
taken effect: recover by sending it again under the same key, because a new
key could apply it twice. `outcome_unknown` is false for a configuration or
request defect, a connection never established, and every 4xx refusal. It is
false for `410 idempotency.expired` too, but there an earlier attempt under the
key was answered and may have committed: read an appointment by its external
reference or identifier before choosing a new key. A hold cannot be read and
expires on its own, so start a new request.

This crate is private and does not publish a standalone Python distribution.
