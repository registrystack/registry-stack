# Registry Render

Render turns registry data into **governed, byte-stable PDF documents** —
receipts, notices, certificates, letters, ID/member cards (photo, QR,
duplex), tags and labels — using [Typst](https://typst.app) embedded as a
library.

> Give Render a sealed template bundle and validated record data. Render
> returns the identical PDF every time, with the hashes and audit events an
> institution needs to stand behind the printed artifact.

Render is a **pure function**: data in, PDF out. Two secret files in serve
mode (caller API key, audit chain key), no database, no outbound calls. It
runs three ways with the same guarantees:

- **CLI** — `render compile --bundle … --data … --issued-at … --out …`,
  offline, zero config: branch printing, template authoring, CI.
- **Service** — `render serve`: one POST endpoint (`/v1/render/{type}`),
  API-key auth, supervised worker processes, a keyed hash-chained audit
  ledger appended before every response.
- **Library** — `registry_render::render(bundle, document, request)` for
  embedding.

## The 10-minute path

```bash
cargo run -p registry-render -- init ./my-bundle
# write data.json with {reference, body, footer-note}
cargo run -p registry-render -- compile --bundle ./my-bundle --type letter \
  --data data.json --issued-at 2026-01-01T00:00:00Z --out letter.pdf
cargo run -p registry-render -- seal --bundle ./my-bundle     # when ready
```

The scaffold compiles offline out of the box: the binary embeds a baseline
Latin font set. Scripts beyond Latin (Arabic, Hebrew, …) need a bundle font
(see `render init`'s note) and `render check` names the gap.

## Where to read next

- [CONCEPT.md](CONCEPT.md) — product boundary and design rules.
- [PAYLOAD.md](PAYLOAD.md) — what a template receives (the one page every
  template author needs).
- [DEFINITION-OF-DONE.md](DEFINITION-OF-DONE.md) — the acceptance contract.
- [EVIDENCE.md](EVIDENCE.md) — the merge gate (library ≡ Typst CLI) and
  the golden-hash record.
- `bundles/` — three coequal example bundles: a bilingual RTL receipt, a
  PDF/A-4 certificate, an ID-1 duplex card with a photo. Copy them.
- `integrations/` — the OpenFn job and App Kit wiring sketches.

## Exit codes

Every CLI failure is one closed vocabulary (`ProblemKind`), and each kind
has one stable exit code — scripts branch exactly. With `--json`, the same
failure prints an RFC 9457 problem document on stderr. Codes 0 and 1 are
success and "unmapped failure"; 2-22:

| Code | Kind | Meaning |
|---|---|---|
| 2 | `invalid-argument` | malformed CLI or request argument |
| 3 | `manifest-invalid` | bundle manifest missing or structurally invalid |
| 4 | `bundle-tampered` | sealed bundle hashes do not match the manifest |
| 5 | `bundle-unsealed` | operation requires a sealed bundle |
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
| 17 | `unauthorized` | missing or wrong API key (serve, HTTP 401) |
| 18 | `rate-limited` | caller exceeded a limit (reserved; HTTP 429) |
| 19 | `audit-failed` | audit ledger refused or failed (fail closed) |
| 20 | `runtime-invalid` | serve runtime configuration invalid |
| 21 | `internal` | internal invariant broke; never carries data |
| 22 | `body-too-large` | request body over the configured ceiling (serve, HTTP 413) |

## Guarantees, mechanistically

- **Byte-stable**: for fixed (bundle hash, type, locale, canonical data,
  `issuedAt`) the PDF bytes are fixed — fresh Typst world and library per
  render, deterministic font order, the RFC 8785 canonical envelope is
  exactly the string injected into the template and exactly the bytes
  hashed as `dataSha256`. The Typst pin **and the deflate stack** are
  lockfile-pinned to the Typst release; upgrades are reviewed golden diffs.
- **Path-safe**: a template's world contains exactly the bundle, the
  request's decoded assets (`assets/<name>`), and vendored packages —
  enforced by the world (lexical checks + canonicalize-then-contain), not
  by template discipline.
- **Resource-bounded**: serves render in a supervised worker process,
  killed at the timeout, memory-capped on Linux, recycled on panic.
- **Auditable**: one value-free event per service render (hashes, versions,
  caller fingerprint, trace/correlation ids — never data), appended before
  the response, failing closed. `render audit-verify` proves the chain.
