# Registry Messaging Node binding

This internal napi-rs binding supplies the `messaging` module assembled into
`@registrystack/client`. Applications should use that unified package.

Every message operation accepts a bearer token for that call; `health` and
`ready` take none. `submit` requires a caller-chosen idempotency key of 1 to
128 visible ASCII characters and refuses any other key before a request is
sent. The binding does not retain credentials, never invents an idempotency
key, and never retries a submission.
