# Registry Scheduling client

`registry-scheduling-client` is the canonical bounded Rust client for Registry
Scheduling. It exposes Scheduling's exact-time and arrival-window HTTP
contract over the wire documents and closed problem vocabulary of
`registry-scheduling-core`. It does not contain the Scheduling runtime, its
PostgreSQL store, or its operator tooling, and it depends on no other
product's runtime or protocol types.

The client takes a borrowed bearer token for each call, the only credential
Scheduling accepts. It never retains the token, follows redirects, or
retries a mutation. Mutating calls carry a caller-supplied idempotency key,
validated against the pinned bound before any network input or output.
Responses are read under a bounded byte ceiling, and exactly validated
product problems surface as their typed `ProblemCode`; every other failure
is a caller-side request defect, a transport failure, or a protocol failure.
