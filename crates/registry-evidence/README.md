# registry-evidence

`registry-evidence` is the single-crate Evidence Version 1 runtime. It loads
one immutable operator-controlled bundle, evaluates fixed requirements through
bounded Rhai extraction and derivation, and returns minimum-disclosure
assertion evidence. It depends on
[`registry-evidence-verifier`](../registry-evidence-verifier/README.md) for the
response formats, the Evidence payload contract, and relying-party verification,
and serves those items at its own paths.

The `evidence` binary takes a runtime file and one subcommand:

```text
evidence check --runtime-config <path> [--format human|json] [--require-runtime-dependencies]
evidence evaluate --runtime-config <path> --fixture <bundle-relative path>
evidence serve --runtime-config <path>
evidence verify --jws <file> --jwks <file> --policy <file> [--at <rfc3339-utc>]
evidence check-policy --verification-policy <file> | --holder-bound-policy <file> [--format human|json] [--deny-warnings]
```

`check` validates and compiles the complete bundle and the runtime file's
bindings offline: it reads no secret material, contacts no service, and
reports every problem it finds with its file, line, column, and code, exiting
`0`, `1` when refused, `2` on a usage error, and `3` when an input could not be
read. `--require-runtime-dependencies` adds, on the target host, what startup
proves: read-only inputs, secret material, extract freshness, audit
writability, signer readiness, source credentials, and access-token JWKS
reachability. `evaluate` runs
one bundle-owned fixture without source or credential access. `verify`
re-verifies a stored signed response offline against a pinned trusted JWKS
file and a complete relying-procedure policy document, reporting cryptographic
authenticity separately from current validity; it needs no runtime file and
never touches the network. `check-policy` reads one verification policy, or
one holder-bound policy, exactly as `verify` or `verify-presentation` reads
it, and reports every problem with its line and column instead of the closed
`malformed` class those commands return. `serve` starts the native HTTP
service:

```text
POST /v1/evidence
GET  /v1/evidence-definitions
GET  /health
GET  /openapi.json
GET  /ready
GET  /.well-known/evidence/jwks.json
```

`GET /openapi.json` returns the generated public contract as
`application/json`. It is unauthenticated and byte-identical to the
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
