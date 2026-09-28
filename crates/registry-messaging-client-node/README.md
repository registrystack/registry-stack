# Registry Messaging Node binding

This internal napi-rs binding supplies the `messaging` module assembled into
`@registrystack/client`. Applications should use that unified package.

Every message operation accepts a bearer token for that call; `health` and
`ready` take none. `submit` requires a caller-chosen idempotency key of 1 to
128 visible ASCII characters and refuses any other key before a request is
sent. `cancel` takes a message identifier and `preview` a template identifier,
version, and `{ locale, data }` request; each refuses a malformed name before a
request is sent. The binding does not retain credentials, never invents an
idempotency key, and never retries a submission or a cancellation. A
submission over its access profile's request rate or daily limit fails with
`rate-limit.exceeded` or `quota.exceeded` and status 429, and
`retryAfterSeconds` carries the wait the runtime asked for, at most one day;
it is absent on every other failure.
