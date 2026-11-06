# Registry Render

Render turns registry data into **governed, byte-stable PDF documents** —
receipts, notices, certificates, letters, ID/member cards (photo, QR,
duplex), tags and labels — using [Typst](https://typst.app) embedded as a
library.

> Give Render a verified template package and validated record data. Render
> returns the identical PDF every time, with the hashes and audit events an
> institution needs to stand behind the printed artifact.

Render is a **pure function**: data in, PDF out, with no database. The optional
HTTP adapter validates resource-bound access tokens through the shared OIDC
verifier or uses an explicit legacy API key. Only the adapter fetches issuer
metadata and keys; CLI and library rendering remain offline. It runs three ways
with the same rendering guarantees:

- **CLI** — `registry-render compile --bundle … --data … --issued-at … --output …`,
  offline, zero config: branch printing, template authoring, CI.
- **Service** — `registry-render serve`: one POST endpoint (`/v1/render/{type}`),
  resource-token or legacy API-key auth, supervised workers, and value-free audit entries
  written before every render and before every response.
- **Seal** (optional): with a `signing` block in the runtime file, `serve`
  adds `POST /v1/seal/{type}`, which returns the rendered document with a PAdES
  signature (see [Seal documents](#seal-documents)).
- **Library** — `registry_render::render(bundle, document, request)` for
  embedding.

## The 10-minute path

```bash
cargo run -p registry-render -- init ./my-bundle
# write data.json with {reference, body, footer-note}
cargo run -p registry-render -- compile --bundle ./my-bundle --type letter \
  --data data.json --issued-at 2026-01-01T00:00:00Z --output letter.pdf
cargo run -p registry-render -- package --bundle ./my-bundle \
  --output ./my-package --revision "$(git rev-parse HEAD)"
```

The scaffold compiles offline out of the box: the binary embeds a baseline
Latin font set. Scripts beyond Latin (Arabic, Hebrew, …) need a bundle font
(see `registry-render init`'s note) and `registry-render check` names the gap.

## Where to read next

- [CONCEPT.md](CONCEPT.md) — product boundary and design rules.
- [PAYLOAD.md](PAYLOAD.md) — what a template receives (the one page every
  template author needs).
- [EVIDENCE.md](EVIDENCE.md) — the merge gate (library ≡ Typst CLI) and
  the golden-hash record.
- `bundles/` — three immutable packaged examples: a bilingual RTL receipt, a
  PDF/A-4 certificate, and an ID-1 duplex card with a photo. Formal PDF/A
  conformance validation (for example veraPDF) is not run; the evidence
  records only that the `pdfaid:part` marker is present. Use them with
  `check`, `compile`, or `serve`; start editable source with
  `registry-render init`.
- `integrations/` — the OpenFn job and App Kit wiring sketches.
- `schemas/`: JSON Schemas for `manifest.yaml`, `labels/<locale>.yaml`, and
  the `serve` runtime file, generated from the types Render reads. Regenerate
  them with `cargo run -p registry-render --features schema --example
  render-schema -- --output products/render/schemas`; `examples/runtime.yaml`
  is a minimal runtime file they accept.

## Exit codes

Every CLI failure is one closed vocabulary (`ProblemKind`), and each kind
has one stable exit code — scripts branch exactly. With `--format json`, the same
failure prints one RFC 9457 problem document on stdout. 0 is success; the
failure codes are 2-30 (clap's own usage errors also exit 2, and a panic
exits 101):

| Code | Kind | Meaning |
|---|---|---|
| 2 | `invalid-argument` | malformed CLI or request argument |
| 3 | `manifest-invalid` | bundle manifest missing or structurally invalid |
| 4 | `bundle-tampered` | package files do not match the shared `SHA256SUMS` envelope |
| 5 | `package-checksums-missing` | runtime package lacks `SHA256SUMS` |
| 6 | `unknown-document` | requested document type or locale not in the bundle |
| 7 | `labels-invalid` | label table missing, invalid, or key sets diverge across locales |
| 8 | `font-invalid` | bundle font cannot be loaded, or label script uncovered |
| 9 | `data-invalid` | request data violates the document schema (pointers attached) |
| 10 | `asset-invalid` | asset missing, oversized, or not JPEG/PNG |
| 11 | `issued-at-missing` | `issuedAt` absent (or `--issued-at`/`--now` missing) |
| 12 | `compile-failed` | Typst compile or PDF export failed (file/line where resolvable) |
| 13 | `strict-warnings` | `--strict` refused reported warnings |
| 14 | `output-too-large` | rendered PDF exceeded the output cap |
| 15 | `render-timeout` | render exceeded its wall-clock budget and was killed |
| 16 | `render-panicked` | render worker panicked; the worker is recycled |
| 17 | `unauthorized` | missing or invalid bearer credential (serve, HTTP 401) |
| 18 | `rate-limited` | as many seals as render slots are already in flight (serve, HTTP 429) |
| 19 | `audit-failed` | audit destination refused or failed (fail closed) |
| 20 | `runtime-invalid` | serve runtime configuration invalid, a seal that cannot load at startup included |
| 21 | `internal` | internal invariant broke; never carries data |
| 22 | `body-too-large` | request body over the configured ceiling (serve, HTTP 413) |
| 23 | `forbidden` | verified credential lacks `render:render` (`render:seal` on the seal route), or the legacy API key calls the seal route (serve, HTTP 403) |
| 24 | `authentication-unavailable` | verifier cannot reach a verdict (serve, HTTP 503) |
| 25 | `not-found` | route is not exposed by the adapter (HTTP 404) |
| 26 | `signing-unavailable` | the seal's key provider cannot sign now (serve, HTTP 503) |
| 27 | `seal-certificate-invalid` | the seal certificate is outside its validity, or cannot sign, when a seal is requested (serve, HTTP 503) |
| 28 | `timestamp-failed` | the timestamp authority gave no usable token; never falls back to B-B (serve, HTTP 502) |
| 29 | `document-not-sealable` | the document type names no seal (serve, HTTP 400) |
| 30 | `seal-client-not-allowed` | the verified client is not in the seal's `allowedClients` (serve, HTTP 403) |

## Authenticate the serving adapter

Choose exactly one non-null authentication mode. For OIDC, replace `authentication` in
`examples/runtime.yaml` with:

```yaml
authentication:
  oidc:
    issuer: https://issuer.example.invalid
    audience: urn:example:render
    allowedClients: [portal]
```

The shared verifier checks signature, expiry, issuer, resource audience membership
and the configured client binding. Tokens need `render:render`, and `render:seal`
for the seal route; an audience array
may contain the configured resource alongside other audiences. Unrelated signed
task-grant claims confer no Render authority. OIDC discovery and JWKS fetches
belong to the serving adapter; deployments may instead configure a URI or static
JWKS through the shared issuer block. Omitted unused secret providers are allowed;
any provider declared in the runtime is validated. Legacy `authentication.apiKeyRef` remains
available, with the existing secret-provider and entropy checks. Do not configure
both modes or use null as an absent member.

Invalid credentials return `401` with a Bearer challenge. A verified token without
scope returns `403`; an issuer-key outage with no usable cached keys returns `503`.
`/ready` checks the same key source, including the shared bounded cache/outage
tolerance, plus audit readiness. All HTTP problems carry the shared six members
and optional bounded pointers, fixed guidance, response trace context, and
`Cache-Control: no-store`. Detailed package, request and compiler diagnostics
remain available through local operator commands.

The audit `caller` is the canonical fingerprint of the exact verified credential,
not a durable person identifier. The same token correlates across calls; a newly
issued token for the same principal has a different fingerprint. Raw tokens,
issuer, subject and client claims are absent from audit events.

The internal Rust, Node and Python serving clients use this HTTP contract and the
JSON PDF representation. Their source is ready for local candidates only; Render's
release-client hold remains in place. A lost response does not establish that a
render failed. Clients expose transport uncertainty and perform no automatic retry;
retaining identical inputs preserves byte determinism when the caller repeats it.

## Seal documents

Sealing is optional and off unless the runtime file has a `signing` block.
A document type opts in with `seal: <id>` in `manifest.yaml`, and the runtime
file binds each id to key material:

```yaml
signing:
  seals:
    ministry:
      privateKeyRef: secret:file/seal.jwk
      certificateChainFile: /etc/registry-render/seal/chain.pem
      timestampAuthority:
        url: https://tsa.example.org/tsr
      allowedClients: [records-service]
```

- `privateKeyRef` is a secret reference to one ES256, ES384, RS256 or RS384
  private JWK. `certificateChainFile` is an absolute PEM path, the seal
  certificate first, then each issuer. A render worker that gained code
  execution runs as the serving user and can read a `secret:file` key; keep
  a production seal key off such a host until HSM or managed-key custody
  lands.
- `timestampAuthority` (an RFC 3161 authority; `https`, or `http` on loopback
  only; `attemptTimeoutMilliseconds` 1000 to 60000, default 10000; an
  optional `caBundleRef` naming a PEM CA bundle that verifies the authority
  in place of the platform's trusted roots) makes the
  seal PAdES baseline B-T. `withoutTimestamp:
  seal-stops-validating-when-certificate-expires` makes it B-B and states the
  consequence. Declare exactly one.
- `allowedClients` is required, lists named OIDC clients, and refuses
  `unrestricted` and wildcards. Signing needs `authentication.oidc`; the legacy API key
  never seals. `trust: test-only` marks a test certificate so the template can
  print the seal as a test seal (the `init` scaffold does). The answer, the
  `/ready` entry and the audit say `testOnly: true` too, the PDF answer adds
  `X-Registry-Seal-Test-Only: true`, and `serve` warns once per test-only
  seal at startup.
- The route needs the `render:seal` scope, which `render:render` does not
  imply. It returns the sealed PDF with `X-Registry-Document-Digest` (the
  first revision, Render's rendered document) and
  `X-Registry-Signed-File-Digest` (the whole file), or JSON with `pdfBase64`,
  `documentDigest`, `signedFileDigest` and a `seal` object. Every digest is
  labelled, `sha256:<hex>`, and there is no `pdfDigest`. Both carry the
  package digest (`X-Registry-Package-Digest`, `packageDigest`) in the form
  `package.expectedDigest` takes, so a sealing client needs no
  `render:render` to pin the package.
  `/v1/documents` names each sealable document type's seal as `seal`.
- `/ready` adds a `signing` member per seal and stays ready while a seal is
  unavailable. Audit entries add `sealId`, `documentDigest`,
  `signedFileDigest`, `certificateDigest` and `timestampTokenDigest`, never a
  subject. A `timestamp-failed` response entry adds `reason`, the value-free
  name of the failing check, which a `seal refused` log warning repeats.
- The seal is a certification signature (DocMDP permission 2) in an invisible
  field. Templates read the payload's `signing` member (see
  [PAYLOAD.md](PAYLOAD.md)) to print a visible seal block.
  `compile --preview-seal test-only` (or `production`) renders that variant
  offline, with `--signer-name` as the certificate's display name, and
  signs nothing.
- `registry-render check --environment` reads each chain file and reports
  errors and warnings, including a certificate that expires within 30 days.
  Whether the key matches the certificate is checked when `serve` starts.

The boundary, the residual risks and what sealing does not claim are in
[CONCEPT.md](CONCEPT.md#sealing) and [SECURITY-MATRIX.md](SECURITY-MATRIX.md)
(rows 24-29). Render makes no eIDAS qualification claim.

## Linux worker execution on Apple Silicon

A v0.43.0 adopter probe recorded a worker failure (`early eof`) while running
its released Linux amd64 binary through Docker's `linux/amd64` emulation on
Apple Silicon, in a mutable `debian:bookworm-slim` base. That response used
`data: {}`. The probe's full scaffold request also returned HTTP 500, but its
response body was not retained. The [reported failure](https://github.com/registrystack/registry-stack/issues/2366)
therefore needs those two observations kept distinct.

A separate [native Linux amd64 release check](https://github.com/registrystack/registry-stack/actions/runs/39652049834/job/119446529176)
used the exact same v0.43.0 binary (SHA-256
`5ee7a42a4e3429b69a97ab23ec38c504f8652bdd1cd8328345633211e094c2e4`)
and wrote a 13,049-byte PDF through the supervised compile worker. Its freshly
generated package, request, issuance timestamp and native Ubuntu environment
differed from the emulator probe. The original full request, package and
container were not reproduced on native Linux. The cause remains unresolved;
these observations establish neither a general Render defect nor a universal
emulation limitation.

The maintained native platform checks are the
[release candidate's packaged scaffold render](../../.github/workflows/release-candidate.yml)
and [Render's golden and serving tests](../../crates/registry-render/tests/),
selected by the [main CI workflow](../../.github/workflows/ci.yml). An image
version check or a CLI argument refusal before worker execution does not prove
that a worker can render.

## Guarantees, mechanistically

- **Byte-stable**: for fixed (package hash, type, locale, canonical data,
  `issuedAt`) the PDF bytes are fixed — fresh Typst world and library per
  render, deterministic font order, the RFC 8785 canonical envelope is
  exactly the string injected into the template and exactly the bytes
  hashed as `dataDigest`. The Typst pin **and the deflate stack** are
  lockfile-pinned to the Typst release; upgrades are reviewed golden diffs.
- **Path-safe**: a template's world contains exactly the bundle, the
  request's decoded assets (`assets/<name>`), and vendored packages —
  enforced by lexical checks and exact lookups in an immutable bundle
  snapshot, not by template discipline. Package loads bind the shared
  checksum envelope to that snapshot, and Typst consumes those exact
  verified bytes.
- **Resource-bounded**: serves render in a supervised worker process,
  killed at the timeout, memory-capped on Linux, recycled on panic. The
  worker starts from an empty environment (only the dynamic loader's search
  paths are kept), so tune it through the runtime configuration, not through
  environment variables.
- **Auditable**: value-free events (hashes, versions, caller fingerprint,
  trace/correlation ids, never data) written through the shared Registry
  Stack audit writer. A render writes a `request` entry before the worker
  starts and a `response` entry with the outcome before the document leaves,
  both failing closed; a refusal before any render is one `response` entry.
  A call that ends before its outcome is written, such as a disconnected
  caller, writes an `unfinished` response, so every `request` entry is
  paired while the process runs; a process that stops while a write is in
  flight can leave one unpaired. Each line is the envelope `{schema, eventId, time, phase,
  correlation, record}` with schema `render.registrystack.org/audit/v1`;
  `correlation` is a random id the server draws for every call, and the
  caller's `Idempotency-Key` is echoed only as the record's `correlationId`,
  since two calls may carry the same key. The
  runtime's `audit` block names a `file` (the default, with `path` and
  optional `rotateBytes` and `retentionDays`) or `stdout` destination. The log
  carries no hash chain or signature, so it is not tamper-evident on the
  host; ship it to append-only storage when that matters.
