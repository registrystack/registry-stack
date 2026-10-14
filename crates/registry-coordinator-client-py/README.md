# Registry Coordinator Python binding

This internal PyO3 binding is not published separately. Its namespace and
native extension are assembled into the `coordinator` namespace of the public
`registry-stack-client` wheel. The public facade is imported as `registry_client.coordinator`. Built on its own, the internal
binding can be used like this, assuming an authorized `permit-notice` Workflow with the shown
input contract:

```python
import registry_coordinator_client as coordinator

client = coordinator.CoordinatorClient("https://coordinator.example.invalid/")
contract = client.workflow(token, "permit-notice")["value"]
# Persist this exact request and key before dispatch, then reuse them for recovery.
request = {
    "workflow": contract["workflow"],
    "workflowRevision": contract["workflowRevision"],
    "input": {"requestId": "one"},
}
started = client.start(token, "permit-notice-0001", request)
run_id = started["value"]["runId"]
status = client.status(token, run_id)
inspection = client.inspect(token, run_id)
recovered = client.reconcile(token, run_id, "operator-ticket-4821")
latest = client.list(token, 20, None, "attention", True)
cursor = latest["value"].get("nextCursor")
next_page = client.list(token, 20, cursor, "attention", True) if cursor else None
retried = client.retry_same(token, run_id, "operator-ticket-4822")
cancelled = client.cancel(token, run_id, "operator-ticket-4823")
```

The computed Workflow revision identifies execution semantics, including the typed input,
graph, declared outcomes, used Operation and Function revisions, and host execution contracts.
Presentation titles and descriptions do not change it. Exact package bytes have a separate
package checksum. Status retains the admitted `workflow` and `workflowRevision` after upgrades.
Inspection adds accepted or unknown `effects` and named completion `waits`, including pinned
revisions, deadlines, next observations, persistent floors, and count/limit. Original inputs,
raw product responses, prepared requests, and protected correlation values remain absent.
The reviewed Workflow declares any terminal output projection.

`coordinatorctl types --project DIRECTORY --language typescript --output FILE` and the equivalent
`--language python` export typed Workflow wrappers over the maintained public generic clients.
Their `start`, `get`, and `cancel` methods pin the compiled revision and check returned workflow
identity and declared outcome names. They add no transport or authorization semantics; runtime
schema checks remain with Coordinator. Regenerate the wrapper when the execution contract changes.

Pass `nextCursor` unchanged with the same caller and filter values. The state
argument accepts one of the eight closed run states. `attention=True` selects
effective state `attention` or `failed`; it can be combined with an exact
state when that is useful.

The client keeps service configuration, but never a bearer token. Supply it
explicitly on each call. The binding never acquires a token and never invents
an idempotency key. `start` requires the key chosen by the caller, 1 to 256
visible ASCII characters, a workflow identifier of up to 64 letters, digits, hyphens, and underscores, and a computed
`workflowRevision` in `sha256:` form with 64 lowercase hexadecimal digits. A fresh start must
match the active revision, or it returns `409 workflow.revision-mismatch`. The binding refuses any other key, workflow, recovery
reason, list limit outside 1 to 100, or run identifier before a request is
sent. Run identifiers are lowercase hyphenated UUIDs. Results use the
canonical Rust client's camel-case wire DTOs inside a `{"kind": "complete", "value": ...}` envelope.
Complete outcome envelopes have no trace field; problem validation still binds the response trace.

Configuration members are keyword arguments: `base_url` (required),
`request_timeout_seconds`, `connect_timeout_seconds`,
`max_response_bytes`, `user_agent`, `trusted_root_certificates`, and
`max_mutation_retries`. Timeouts are seconds, as a finite non-negative `int` or `float`; the response
bound is an `int`. A `bool` is not a number here. An unknown keyword is a Python `TypeError`.

`CoordinatorClientError` preserves the status and the `family.reason` code of
the Coordinator's RFC 9457 problem document, such as `run.not-visible`, and
never carries the problem's title or detail, a token, a key, a URL, or a
request body. A refusal counts as a `problem` only when it is an exact
`application/problem+json` document whose status, type, and trace agree with
the answer; anything else is a `protocol` failure. Its `kind` is one of `configuration`, `invalid-request`,
`transport`, `problem`, or `protocol`; `protocol_failure` is one of
`header-bounds`, `media-type`, `body`, `problem`, `status`, or `protocol`.

The only resend is the Rust client's bounded same-key retry of `start`. An
admission whose outcome is unknown (a timeout or broken exchange after it was
sent, an unusable answer, or a 5xx) is resent identically under the same key up
to `max_mutation_retries` times: 0 to 2, default 2, and 0 sends it once. A 4xx
answer is never resent. `workflow`, `list`, `status`, `inspect`, `reconcile`,
`retry_same`, and `cancel` send exactly one request; `retry_same` and `cancel`
take no idempotency key, so after an unknown outcome read the run before
asking again. When the returned `CoordinatorClientError` still reports
`outcome_unknown`, the run may have been admitted: recover by sending `start`
again with the same service identity, key, workflow, revision, and input, because a new key can
create another run. A key is scoped to the caller and the workflow, so the same key
under two workflows starts two runs, and an allowed workflow the deployment does not
serve is refused with 404 `workflow.not-served`, a known outcome never resent.
`outcome_unknown` is false for a configuration or request
defect, a connection never established, and every 4xx refusal.

`reconcile` observes the original supported product receipt from the runtime's
saved command. It never resubmits it. A missing or expired receipt remains
uncertain. `cancel` never undoes a product effect. Operator routes are not part
of this binding; `coordinatorctl` owns them.

This crate is private and does not publish a standalone Python distribution.
