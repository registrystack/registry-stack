# registry-evidence

`registry-evidence` is the single-crate Evidence Version 1 runtime. It loads
one immutable operator-controlled bundle, evaluates fixed requirements through
bounded Rhai extraction and derivation, and returns minimum-disclosure
assertion evidence.

The `evidence` binary takes a runtime file and one subcommand:

```text
evidence --runtime <path> check
evidence --runtime <path> evaluate --fixture <bundle-relative path>
evidence --runtime <path> serve
evidence verify --jws <file> --jwks <file> --policy <file> [--at <rfc3339-utc>]
```

`check` validates and compiles the complete immutable bundle. `evaluate` runs
one bundle-owned fixture without source or credential access. `verify`
re-verifies a stored signed response offline against a pinned trusted JWKS
file and a complete relying-procedure policy document, reporting cryptographic
authenticity separately from current validity; it needs no runtime file and
never touches the network. `serve` starts the native HTTP service:

```text
POST /v1/evidence
GET  /v1/evidence-definitions
GET  /health
GET  /openapi.json
GET  /ready
GET  /.well-known/evidence/jwks.json
```

`GET /openapi.json` returns the generated public contract as
`application/openapi+json`. It is unauthenticated and byte-identical to the
released artifact under `products/evidence/generated/`, so it describes no
deployment, definition, or authority.

`POST /v1/evidence` requires a `requestNonce`: the canonical unpadded base64url
encoding of exactly 32 random bytes, freshly generated per request. The runtime
echoes it into the Evidence payload and covers it by the signature. It is never
stored, never uniqueness-checked, and never reaches authorization, rate limits,
Rhai, source requests, logs, metrics, traces, or audit.

Signed flattened JWS (`application/jose+json`) is the mandatory default and the
only later-verifiable format. The exact
`application/vnd.registrystack.evidence-unsigned+json` selects a self-identifying
unsigned envelope, and only when both the bundle and the one complete matched
grant permit that format. Signing failure never falls back to unsigned output.

The normative product contracts and verification commands live under
`products/evidence/`. Evidence is independent from Registry Notary and has no
credential, replay, policy-engine, document, federation, worker, or OOTS
subsystem.
