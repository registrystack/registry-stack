# Registry Platform STS

Security token service primitives for exchanging a verified subject token for a
Notary-bound transaction token.

This crate intentionally owns protocol validation, rate-limit hooks, token
minting, and the small HTTP adapter needed by Assisted Access. Deployment
wrappers still own process configuration, durable rate-limit stores, audit sink
wiring, and key custody.

The HTTP adapter exposes:

- `POST /oauth/token` for RFC 8693-shaped token exchange.
- `GET /.well-known/oauth-authorization-server` for authorization-server
  metadata.
- `GET /.well-known/jwks.json` for public signing keys.

`POST /oauth/token` accepts the normal token-exchange request plus the
RegistryStack context fields Assisted Access sends today: `client_id`,
`tenant`, `session_id`, `correlation_id`, `subject_id_hash`, `actor_id_hash`,
`delegation_ref`, and `session_binding`. The adapter maps those fields into
`ExchangeContext`; the core service still validates the token profile and signs
the Notary-bound transaction token.

When `session_binding_secret` is configured, `session_binding` must be an
`hmac-sha256:<hex>` value over the session id, correlation id, verified subject,
subject id hash, client id, tenant, actor id hash, and delegation reference.
This prevents a leaked subject token plus arbitrary request-body caller context
from minting a Notary-bound token.

Current limits: the bridge does not yet verify UserInfo JWT continuity and the
binary uses local JWK signing material. Do not claim external OAuth/OIDC/FAPI
certification or production key-custody readiness from this crate alone.

The `registry-platform-sts` binary is a minimal deployment wrapper around the
same library. Required environment variables:

- `REGISTRY_PLATFORM_STS_ISSUER`
- `REGISTRY_PLATFORM_STS_NOTARY_AUDIENCE`
- `REGISTRY_PLATFORM_STS_SIGNING_JWK`
- `REGISTRY_PLATFORM_STS_SUBJECT_ISSUER`
- `REGISTRY_PLATFORM_STS_SUBJECT_AUDIENCE`
- `REGISTRY_PLATFORM_STS_SUBJECT_JWKS_URI`
- `REGISTRY_PLATFORM_STS_SESSION_BINDING_SECRET`
- `REGISTRY_PLATFORM_STS_AUDIT_HASH_SECRET`, at least 32 bytes
- `REGISTRY_PLATFORM_STS_AUDIT_LOG_PATH`

Optional environment variables:

- `REGISTRY_PLATFORM_STS_BIND`, default `127.0.0.1:9090`
- `REGISTRY_PLATFORM_STS_SUBJECT_CLAIM`, default `sub`
- `REGISTRY_PLATFORM_STS_SUBJECT_ALLOWED_TYP`, default `at+jwt,JWT`
- `REGISTRY_PLATFORM_STS_SUBJECT_ALLOWED_ALGS`, default `EdDSA,RS256`

The binary appends token-mint events to a keyed JSONL audit chain and fails the
exchange if the audit append fails. Library callers that construct
`TokenExchangeService` directly must still supply their own `StsAuditSink`.
