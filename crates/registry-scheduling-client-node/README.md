# Registry Scheduling Node binding

This internal napi-rs binding is not published separately. Beginning with
Registry Stack v0.40.0, its namespace and native addon ship inside
`@registrystack/client`.

Every operation accepts a bearer token for that call. `createHold`,
`createAppointment`, `rescheduleAppointment`, and `cancelAppointment` require a
caller-chosen idempotency key of 1 to 128 visible ASCII characters and refuse
any other key before a request is sent. Offering selectors, hold and
appointment identifiers, cursors, page limits, external references, and
instants are checked before a request is sent; instants are RFC 3339 text,
normalized to UTC. Request documents refuse a member the contract does not
declare. The binding does not retain credentials, never invents an idempotency
key, and never retries a mutation. A refusal is a `SchedulingClientError` whose
`code` is one of the closed Registry Scheduling problem codes; a code outside
that catalogue is a protocol failure.
