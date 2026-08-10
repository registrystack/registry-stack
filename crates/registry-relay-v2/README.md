# Registry Relay V2

`registry-relay-v2` compiles one governed Registry contract into an immutable,
read-only runtime model. It owns Relay V2 contract semantics, deterministic
semantic artifacts, offline fixture evaluation, change classification, and
sealed package construction.

The compiler is deliberately independent of SQLite access. Callers inspect a
database through `registry-platform-sqlite`, pass the resulting
`ObservedSourceSchema` to the compiler, and execute the compiler's closed query
plans through that same platform boundary. The crate does not depend on Relay
V1 or Registry Manifest and does not define a generic storage abstraction.

`relay` is the runtime entry point. `relayctl` links this library directly for
authoring workflows, so command-line code must not reproduce validation,
generation, fixture, diff, or packaging rules.
