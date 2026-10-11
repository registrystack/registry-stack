# Registry Coordinator Python binding

This internal PyO3 binding is not published separately. Its namespace and
native extension are assembled into the `coordinator` namespace of the public
`registry-stack-client` wheel. Built on its own, it is used like this:

```python
import registry_coordinator_client as coordinator

client = coordinator.CoordinatorClient("https://coordinator.example.invalid/")
started = client.start(
    token,
    "nursing-notice-2026-10-10-0001",
    {"flow": "nursing-notice", "input": {"requestId": "one"}},
)
run_id = started["value"]["runId"]
status = client.status(token, run_id)
inspection = client.inspect(token, run_id)
recovered = client.reconcile(token, run_id, "operator-ticket-4821")
latest = client.list(token, 20)
retried = client.retry_same(token, run_id, "operator-ticket-4822")
cancelled = client.cancel(token, run_id, "operator-ticket-4823")
```

The client keeps service configuration, but never a bearer token. Supply it
explicitly on each call. The binding never acquires a token and never invents
an idempotency key. `start` requires the key chosen by the caller, 1 to 256
visible ASCII characters, and a flow identifier of up to 64 letters, digits,
hyphens, and underscores. The binding refuses any other key, flow, recovery
reason, list limit outside 1 to 100, or run identifier before a request is
sent. Run identifiers are lowercase hyphenated UUIDs. Results use the
canonical Rust client's camel-case wire DTOs inside a `{"kind": "complete", "value": ...}` envelope.
Coordinator defines no trace field, so there is no trace identifier.

Configuration members are keyword arguments: `base_url` (required),
`request_timeout_seconds`, `connect_timeout_seconds`,
`max_response_bytes`, `user_agent`, `trusted_root_certificates`, and
`max_mutation_retries`. Timeouts are seconds, as a finite non-negative `int` or `float`; the response
bound is an `int`. A `bool` is not a number here. An unknown keyword is a Python `TypeError`.

`CoordinatorClientError` preserves the status and the Coordinator's open
problem code, and never carries the server's prose, a token, a key, a URL, or a
request body. Its `kind` is one of `configuration`, `invalid-request`,
`transport`, `problem`, or `protocol`; `protocol_failure` is one of
`header-bounds`, `media-type`, `body`, `problem`, `status`, or `protocol`.

The only resend is the Rust client's bounded same-key retry of `start`. An
admission whose outcome is unknown (a timeout or broken exchange after it was
sent, an unusable answer, or a 5xx) is resent identically under the same key up
to `max_mutation_retries` times: 0 to 2, default 2, and 0 sends it once. A 4xx
answer is never resent. `list`, `status`, `inspect`, `reconcile`,
`retry_same`, and `cancel` send exactly one request; `retry_same` and `cancel`
take no idempotency key, so after an unknown outcome read the run before
asking again. When the returned `CoordinatorClientError` still reports
`outcome_unknown`, the run may have been admitted: recover by sending `start`
again with the same service identity, key, and input, because a new key can
create another run. A key is scoped to the caller and the flow, so the same key
under two flows starts two runs, and an allowed flow the deployment does not
serve is refused with 404 `flow-absent`, a known outcome never resent.
`outcome_unknown` is false for a configuration or request
defect, a connection never established, and every 4xx refusal.

`reconcile` observes the original supported product receipt from the runtime's
saved command. It never resubmits it. A missing or expired receipt remains
uncertain. `cancel` never undoes a product effect. Operator routes are not part
of this binding; `coordinatorctl` owns them.

This crate is private and does not publish a standalone Python distribution.
