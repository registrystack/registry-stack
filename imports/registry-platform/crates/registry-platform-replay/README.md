# registry-platform-replay

Replay-store primitives for one-time JWT ids and nonce values.

## What It Provides

- `ReplayStore`, an async trait for `insert_once(scope, key, expires_at)`.
- `ReplayScope` helpers for protocol-specific replay namespaces.
- `ReplayKey`, a redacted-debug wrapper for one-time identifiers.
- `ReplayInsertOutcome` for `Inserted` versus `AlreadySeen`.
- `require_insert_once`, a fail-closed helper for routes where replay
  protection is mandatory.
- `InMemoryReplayStore` for tests and single-process development.

## Typical Use

```rust
use std::time::Duration;

use registry_platform_replay::{
    require_insert_once, InMemoryReplayStore, ReplayKey, ReplayScope,
};
use time::OffsetDateTime;

async fn consume_nonce() -> Result<(), Box<dyn std::error::Error>> {
let store = InMemoryReplayStore::new();
let scope = ReplayScope::oid4vci_nonce(
    "tenant-a",
    "https://issuer.example.gov",
    "disability_credential",
)?;
let key = ReplayKey::new("nonce-id-from-request")?;
let expires_at = OffsetDateTime::now_utc() + Duration::from_secs(300);

require_insert_once(&store, &scope, &key, expires_at).await?;
Ok(())
}
```

## Recommended Scopes

- Federation request JWT `jti`: include protocol, flow, tenant, issuer,
  audience, and credential or evaluation profile.
- OpenID4VCI `c_nonce`: include protocol, flow, tenant, credential issuer, and
  credential configuration id.
- Holder proof JWT `jti`: include protocol, flow, tenant, credential issuer,
  credential configuration id, and holder binding key id or DID.
- Future presentation-proof nonces should follow the same pattern: protocol,
  flow, tenant, verifier, audience or relying party, and presentation profile.

Scopes are ordered and structured. Do not concatenate ad hoc strings in
application code when a structured `ReplayScope` can carry the same boundaries.

## Security Notes

- Every replay record requires an absolute UTC expiry.
- `require_insert_once` fails closed: duplicate keys and store errors both deny
  the operation.
- `InMemoryReplayStore` is for tests, local development, and single-process
  deployments only. Production multi-instance or active-active deployments need
  a durable shared backend such as Redis or Postgres.
- Do not store compact JWTs, raw credentials, subject identifiers, holder
  secrets, or token bodies as replay keys. Use a one-time identifier such as a
  `jti`, nonce, or service-owned digest.
- `Debug` output redacts scope values and replay keys so accidental logs do not
  expose identifier material.

## Testing

```sh
cargo test -p registry-platform-replay
```

## License

Apache-2.0.
