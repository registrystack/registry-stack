# Signed hook deliveries

Authenticate signed BReg, Scheduling and Coordinator hooks through
`registry-platform-hooks::receiver::verify_delivery`. The canonical HMAC-SHA256
implementation lives in `registry-platform-crypto::delivery_signature`; its
Version 1 signing domain and length-prefixed field order stay wire-compatible.
The JSON fixture at `crates/registry-platform-crypto/tests/fixtures/delivery-signatures.json`
is shared by Rust, Node and Python tests.

Pass the exact method, request target, signed headers and body bytes. The
signature authenticates raw delivery-time bytes before the shared verifier
parses freshness. Valid RFC 3339 fractions such as `.12Z`, `.120Z` and `.000Z`
are accepted. Never normalize the timestamp before comparison: replacing
`.120Z` with `.12Z` changes the signature even though it represents the same
instant. Invalid times, changed signatures and stale deliveries remain refused.

Rust receivers select `DeliveryFreshness::Within { now, skew }`. Node
`breg.verifyWebhookDelivery({method, path, headers, body, key})` and Python
`breg.verify_webhook_delivery(method=..., path=..., headers=..., body=..., key=...)`
return authenticated exact values, including `deliveryTime`/`delivery_time`
and `idempotencyKey`/`idempotency_key`. These existing binding entry points use
caller-enforced freshness: compare that returned instant with your trusted
clock and chosen window, and durably deduplicate before taking an effect.
Verification alone creates no source, schema, recipient or business authority.

Casework completion wakes have their own bearer/named-header receiver contract,
not this hook-signature scheme. See [completion receivers](../casework/COMPLETION-RECEIVERS.md).
