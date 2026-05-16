# EntityRecord v1 VC Fixture

This corpus is intentionally static. The compact VC-JWT in
`credential.jwt` was signed outside `registry_relay` with Node's native
Ed25519 support and verifies only with the public JWK in `did.json`.

The fixture uses `--now 2026-05-16T09:31:00Z` in tests so the validity
window remains deterministic.
