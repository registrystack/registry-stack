# Registry Coordinator client

A bounded server-side client for Coordinator's controlled pilot HTTP contract.
The public Rust facade exposes it as `registry_stack_client::coordinator`; the
public Node package exposes `coordinator` in explicitly assembled local
candidates. Browser apps call their own authorized server routes.

The four operations are `start`, `status`, `inspect`, and `reconcile`. Each sends
once. Admission requires a caller-chosen idempotency key and `{flow, input}`.
HTTP 200 confirms admission and returns the run's current status. The caller
retains the exact key, flow, input and service identity in durable state before
dispatch and retries admission after a lost reply under the same identity.
Changing the key or the verified issuer/subject can create another run.

Status is protected by current Coordinator policy and ownership. A run started
by a backend is owned by that backend, even when its input mentions a citizen's
record. Applications must independently authorize source-record access and use
their explicit record-to-run correlation before displaying selected progress.

`reconcile` takes a bounded reason reference and observes the original supported
product receipt from the runtime's saved command. It does not resubmit a notice.
A missing or expired receipt remains uncertain. A Messaging acceptance is never
proof of provider delivery.

Configuration validates a fixed HTTPS endpoint, or an explicit loopback HTTP
endpoint for local development. Deployment prefixes are preserved. Shared
transport disables redirects and ambient proxies; body and header limits apply
to successes and failures. The client validates Coordinator's JSON problem
shape, discards remote message text, and reports closed error categories with
the product's code. It does not invent an RFC 9457 or trace contract.

Run `cargo test --locked -p registry-coordinator-client` and
`cargo clippy --locked -p registry-coordinator-client --all-targets -- -D warnings`.
HTTP tests bind disposable loopback sockets. They verify transport behavior;
the combined native nursing journey separately proves product authorization,
one admission and original notice receipt recovery.
