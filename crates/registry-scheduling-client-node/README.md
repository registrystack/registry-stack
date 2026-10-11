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
declare. The binding does not retain credentials and never invents an
idempotency key. A refusal is a `SchedulingClientError` whose `code` is one of
the closed Registry Scheduling problem codes; a code outside that catalogue is
a protocol failure.

A keyed command (hold, appointment create, reschedule, cancel) whose outcome is
unknown (a timeout or broken exchange after it was sent, an unusable answer,
or a 5xx) is resent identically under the same key up to `maxMutationRetries`
times: 0 to 2, default 2, and 0 sends it once. Reads and the unkeyed hold
release are never resent. When the returned `SchedulingClientError` still
reports `outcomeUnknown`, the command may have taken effect: recover by
sending it again under the same key, because a new key could apply it twice.
`outcomeUnknown` is false for a configuration or request defect, a connection
never established, and every 4xx refusal. It is false for
`410 idempotency.expired` too, but there an earlier attempt under the key was
answered and may have committed: read an appointment by its external reference
or identifier before choosing a new key. A hold cannot be read and expires on
its own, so start a new request.

`appointmentReceipt` observes a retained original success using the original request and
caller-chosen key with a current token. It makes one receipt request, never
replays the mutation and never retries. `receipt.unresolved` leaves the
original effect unknown; a missing or expired receipt does not prove absence.
The error's `outcomeUnknown` describes this read, not the original effect.
