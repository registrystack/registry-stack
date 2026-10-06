# Registry Scheduling client

`registry-scheduling-client` is the canonical bounded Rust client for Registry
Scheduling. It exposes Scheduling's exact-time and arrival-window HTTP
contract over the wire documents and closed problem vocabulary of
`registry-scheduling-core`. It does not contain the Scheduling runtime, its
PostgreSQL store, or its operator tooling, and it depends on no other
product's runtime or protocol types.

The client takes a borrowed bearer token for each call, the only credential
Scheduling accepts. It never retains the token or follows redirects.
Mutating calls carry a caller-supplied idempotency key, validated against the
pinned bound before any network input or output; the client never generates
one. Responses are read under a bounded byte ceiling, and exactly validated
product problems surface as their typed `ProblemCode`; every other failure
is a caller-side request defect, a transport failure, or a protocol failure.

## Unknown outcomes and the same-key retry

A 5xx answer may follow a commit, and so may a timeout or a broken exchange
after the request was sent. `SchedulingClientError::is_outcome_unknown()`
reports those cases, and an oversized or unparseable answer, as true; it is
false for a request defect, a connection that was never established, and
every typed 4xx refusal such as `idempotency.key-reused` (409) or
`idempotency.expired` (410). A 410 does not run the command again, but there an
earlier attempt under the key was answered and may have committed: read an
appointment by its external reference or identifier before choosing a new key.
A hold cannot be read and expires on its own, so start a new request.

The client resends a keyed command (hold, appointment create, reschedule,
cancel) whose outcome is unknown, with the same key, headers, and body bytes,
at most twice by default, waiting 250 ms and then 500 ms, or the service's
`Retry-After` when that is longer and at most 5 seconds. A longer requested
wait ends the retries. Configure the count with
`SchedulingClientConfig::with_max_mutation_retries` (0 to 2; 0 disables the
resend). Reads and the unkeyed hold release are never resent. Each attempt has
the full request timeout, so a call can take up to three request timeouts plus
the waits.

When the returned error still reports `is_outcome_unknown()`, recover by
sending the same request with the same key, which the service replays or
settles. A new key could apply the command twice. A refusal that answers a
resend does not prove the earlier attempt left no effect, so the client then
returns the earlier unknown-outcome error instead of the refusal.

Appointments and holds may carry typed opaque external record references. The
client can list the authenticated caller's appointments by one exact reference;
Scheduling stores the tuple and never contacts the product it names.
