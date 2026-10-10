# Registry Messaging Node binding

This internal napi-rs binding is not published separately. Beginning with
Registry Stack v0.38.0, its namespace and native addon ship inside
`@registrystack/client`.

Every message operation accepts a bearer token for that call; `health` and
`ready` take none. `submit` requires a caller-chosen idempotency key of 1 to
128 visible ASCII characters and refuses any other key before a request is
sent. `cancel` takes a message identifier and `preview` a template identifier,
version, and `{ locale, data }` request; each refuses a malformed name before a
request is sent. The binding does not retain credentials, never invents an
idempotency key, and never resends a cancellation. A submission over its
access profile's request rate or daily limit fails with `rate-limit.exceeded`
or `quota.exceeded` and status 429, and `retryAfterSeconds` carries the wait
the runtime asked for, at most one day; it is absent on every other failure.
The client never waits on a 429 or retries it.

A submission whose outcome is unknown (a timeout or broken exchange after it
was sent, an unusable answer, or a 5xx) is resent identically under the same
key up to `maxMutationRetries` times: 0 to 2, default 2, and 0 sends it once.
When the returned `MessagingClientError` still reports `outcomeUnknown`, the
submission may have been accepted: recover by sending it again under the same
key, because a new key could send the message twice. `outcomeUnknown` is false
for a configuration or request defect, a connection never established, and
every 4xx refusal. It is false for `410 idempotency.expired` too, but there an
earlier submission under the key was accepted and its message may have been
sent: reconcile that submission before choosing a new key.

`messageReceipt` observes a retained original success using the original request and
caller-chosen key with a current token. It makes one receipt request, never
replays the mutation and never retries. `receipt.unresolved` leaves the
original effect unknown; a missing or expired receipt does not prove absence.
The error's `outcomeUnknown` describes this read, not the original effect.
