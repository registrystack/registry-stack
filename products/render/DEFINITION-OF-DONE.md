---
title: "Registry Render — Definition of Done"
doc_type: definition of done
date: 2026-09-19
status: acceptance contract; the merge-gate and golden rows are already evidenced (see EVIDENCE.md)
scope: Version 1 of `registry-render` (crate + `registry-render` CLI + serve mode); the standard OPERATIONS.md beta checklist applies additionally at release
---

# Registry Render — Definition of Done

## Completion rule

Registry Render Version 1 is done only when every required row below passes
on the same revision. A working `registry-render compile`, one golden hash,
or a green subset of tests is not completion. Before the DoD applies, the
**library-mode spike must pass as the crate's merge gate** (first table):
library-mode renders reproduce the CLI spike's golden hashes under the same
pin, or the spec is revised before any crate code merges.

No required behavior may remain as a stub, TODO, undocumented manual step,
disabled test, or follow-up issue. Batch/list rendering, client crates, OIDC
callers, TLS termination, imposition, e-signatures, MRZ/PKI encoding, and
cross-document workflows are outside this Definition of Done.

## Merge gate: library-mode equivalence

**Status: passed 2026-09-17 for all three bundles — see
[EVIDENCE.md](EVIDENCE.md) for the procedure, hashes, and the deflate-stack
pinning finding.**

| Claim | Gate |
|---|---|
| Same bytes as CLI | Library-mode render of the receipt and card example inputs reproduces the CLI spike's sha256s under the same Typst pin, on the same machine. |
| Two clocks | Both `World::today()` and `PdfOptions::timestamp` derive from `issuedAt`; a rendered document is byte-identical when `issuedAt` is fixed and changes when it changes. |
| No network | No network code path exists in the world; an unvendored package import fails as a compile problem. |
| Closure capture | The renderer's world wrapper records the exact file closure per render, equal to the CLI `--deps` output for the same bundle. |
| PDF standards & ident | `PdfOptions::standards` renders PDF/A variants deterministically; the `ident` policy is fixed (derived or `Auto`) with two-OS golden evidence. |
| Findings folded | Any library-mode divergence found is written back into the spec before the crate merges. |

## Coequal acceptance documents

Three example bundles are coequal acceptance definitions. None is a demo
extra; none is privileged in production code:

| Bundle | Required shape | What it must prove |
|---|---|---|
| Bilingual receipt (A5) | Arabic primary + French, RTL justified text, Latin amounts and identifiers inline, QR, plain PDF | Mixed-script bidi layout and mixed-family typography are correct by construction, warnings-clean, and byte-stable. |
| Archival certificate (A4) | Monolingual (or bilingual non-RTL), validity dates, seal text, `pdfStandard: a-4` | A PDF/A document type renders, validates as PDF/A, and stays byte-stable under the standards profile. |
| ID card (ID-1 duplex) | Photo from request assets, QR, Arabic/French, two pages | Fixed card geometry with a data-carried image; asset decoding, hashing, and virtual-file path rules hold. |

All three use the same lib, world construction, validation, audit vocabulary,
and problem model. A tag/label document is covered by the card row's
mechanisms (small fixed page, QR) and is not a fourth project.

## Definition of Done

| Area | Done when |
|---|---|
| Product boundary | One crate `registry-render` and one binary `registry-render` (`init`, `check`, `validate`, `seal`, `compile`, `serve`, `healthcheck`, `audit-verify`) implement the product. Render is a deterministic document renderer: not a document store, e-signature, credentials-issuance, HTML converter, or imposition engine. No `renderctl`, no client crates, no new artifact family. |
| Pure runtime | The render path performs no network I/O, no filesystem access outside the bundle and the virtual `assets/` namespace, and holds no mutable cross-request state. `serve` holds exactly two secrets (caller API key, audit chain key), both via `secret:file/…` refs; `compile` holds none. |
| Bundle format | A closed, versioned manifest (`render.registrystack.org/v1alpha1`, unknown fields rejected) defines document types (id, version, entry, schema, labels, pdfStandard) and per-file hashes. `registry-render seal` writes hashes; each load captures the bundle once and verifies the seal over that immutable snapshot before labels, schemas, fonts, templates, or packages consume it; `serve` refuses an unsealed or hash-mismatched bundle with a named problem; `compile`/`--watch` run unsealed with a one-line notice. |
| Template payload contract | `sys.inputs.data` is exactly the RFC 8785 canonicalization of `{data, assets}` whose sha256 is `dataSha256`, wrapped in the specified envelope (`data`, `assets`, `labels`, `locale`, `issuedAt`, `document`). The renderer version appears nowhere in the envelope, the PDF bytes, or the hashes. |
| Fonts and scripts | The world contains only bundle fonts plus the binary's baseline set (typst-assets), deterministically ordered; host font discovery is never called. `registry-render check` fails when a document's label locales need a script not covered by bundle+baseline fonts. Missing-glyph and other Typst warnings are returned in `rendered.warnings`; `--strict` fails on them. |
| Determinism | For fixed (bundle hash, type, locale, canonical data+assets, issuedAt), bytes are identical: fresh `World` + `Library` per render, sorted font book, `comemo::evict()` per render, deterministic `PdfOptions::ident`. Golden tests pin expected sha256s for all three bundles and run on two OSes in CI; a dependency bump that changes golden hashes is a reviewed diff, never a silent pass. |
| Issued time | `issuedAt` is required on HTTP and fails with a problem document when absent; CLI requires `--issued-at` or an explicit `--now`. No code path renders with a wall-clock default. |
| Assets | Request assets are base64, media-type checked (jpeg/png by magic bytes), and capped at code level (per-asset 2 MiB, per-request 8 MiB — a reviewed constant, not per-document schema declaration); decoded by the renderer and exposed only as virtual `assets/<name>` files; `dataSha256` covers their exact bytes. Oversized or wrong-type assets fail validation with a data-path pointer. (Wording amended 2026-09-17 to match the implementation.) |
| Path safety | World-enforced: `read`/`image`/package resolution reject `..` and absolute paths, then require an exact key in the immutable bundle snapshot or the request-local `assets/` namespace. Symlinks are refused while sealing and loading. Negative tests cover traversal, absolute paths, symlinks, virtual-namespace escape, and path replacement after seal verification. |
| Resource enforcement | `serve` renders in a supervised worker process: killed at the configured timeout, memory-capped by rlimit, recycled after a panic (`catch_unwind` in-process backstop → 500 problem + audit), bounded concurrency (documented max, CPU-capped pool), graceful shutdown draining in-flight renders. A pathological-template test proves kill → problem → audit, repeatedly, without degrading the service. CLI uses bounded worker threads with the same timeout semantics. |
| Validation and errors | All failure classes — schema violations (with JSON pointers), bundle drift (with offending hash), compile errors (file/line), missing labels, unvendored imports, timeout, panic, oversize output — are RFC 9457 problem documents on HTTP and typed exit codes under CLI `--json`. No stack trace or raw Typst diagnostic escapes to a caller. `registry-render validate` dry-runs data against the schema without rendering. |
| HTTP contract | `GET /v1/documents`; `POST /v1/render/{type}` with required `issuedAt`; `Accept: application/pdf`/`*/*`/absent returns PDF bytes + `X-Registry-Pdf-Sha256`/`X-Registry-Data-Sha256`/`X-Registry-Document-Version`; `Accept: application/json` returns `{pdfBase64, pdfSha256, dataSha256, documentVersion}`. `Idempotency-Key` is an opaque correlation id: echoed and audited, never dedupe. `/health`, `/ready` (audit readiness included), static `/openapi.json`. Listener defaults to loopback/private; no TLS code. |
| Authentication | API key from a secret file, ≥32 bytes, constant-time compare (authcommon); malformed and missing keys get indistinguishable `401` problems; `401`s are audited. No OIDC in v1. |
| Audit | Keyed HMAC chain (`production_from_secret_bytes`), `DurableSegmentedJsonlSink` (sealed segments, never deleted). One event per service render, appended **before** the response and failing closed; failures (validation, timeout, panic, 401) are audited too; events carry type/version/bundle/renderer+Typst pin/hashes/caller/trace/correlation and no data values or asset bytes. `registry-render check --require-audit-under` and `registry-render audit-verify` work on a real chain. |
| DX budget | `registry-render init` scaffolds a bundle (manifest, template, schema, label files, starter fonts, fixture) that compiles offline without edits; templates are plain Typst usable with upstream tooling; example bundles double as golden fixtures; the payload contract is one documented page; errors per the validation row are the default path, not an opt-in. |
| Domain neutrality | Production code, manifests, CLI options, and schemas contain no deployment-, program-, or client-specific terms; Arabic/French, receipt, certificate, and card vocabulary appears only in example bundles, fixtures, and docs. |
| Operability | Startup runs the same verification as `check` before listening; graceful shutdown drains; structured value-free lifecycle logs (fixed dimensions: method class, route template, status, latency, trace id); no `/metrics` route in v1; `--version` reports `DISPLAY_VERSION` plus the Typst pin. |
| App Kit journey | The kit's documents capability uses an `APP_DOCUMENTS_FILE` mapping to loopback destinations with credential files (taskDispatch precedent); the bundle lives under `project/deployment/render/bundle/`; the document field list and QR destination are `agreed` brief rows before the template is written. Done only when a staff user prints a receipt from a record, the PDF attaches to breg with matching sha256 fields, and the QR verify page resolves, closed by a kit-gate record of `COMPLETED with 0 flags` produced in the App Kit repository. **Status: not yet walked** — the kit-side documents capability does not exist yet; ACCEPTANCE.md records the deferral and sizing, and `integrations/app-kit/README.md` is the stack-side contract that capability will implement. |
| OpenFn journey | A job in the kit's tested idiom (bridge envelope destructured, config validated, `parseAs: "json"`, status checked, minimized return) reads record data back through a least-privilege breg reader profile whose readable fields equal the template data contract, renders via `Accept: application/json`, and delivers the PDF; a dead-letter replay produces byte-identical output. Walked end to end without the App Kit in the picture. |
| Dependency policy | cargo-deny passes with a reviewed, explained Typst-tree delta (licenses/sources); `Cargo.lock` pins typst/typst-pdf/typst-kit/typst-assets; no git or vendored source dependencies. |
| Verification evidence | Formatting, `cargo check/test/clippy -D warnings --locked`, dependency policy, golden-hash drift, closure drift (manifest hashes vs captured closure), value-free canary scans for audit and logs, and the two-OS golden job pass on one revision. Every security row above has a named threat, enforcement point, and executable negative test (security-invariant matrix in the product repo). |

## Stop boundary (explicitly not in v1)

Batch/list endpoints and multi-document requests; client crates and generated
OpenAPI; OIDC or multi-tenant callers; TLS termination; imposition/N-up
layout; e-signatures, seals, or verifiable credentials; MRZ/chip/PKI card
encoding; hot reload or runtime bundle editing; per-tenant rate limiting;
metrics route; any document-type-specific behavior in production code.

## Completion evidence

Before the product can be called complete, the repository must contain and
CI must invoke:

- the three coequal example bundles with golden sha256 fixtures, run on two
  OSes;
- the security-invariant matrix (`SECURITY-MATRIX.md`) mapping every
  security row to an enforcement point and an executable negative test
  (path escape, asset abuse, timeout kill, panic recycle, unsealed serve,
  tampered bundle, audit tamper, 401 handling, value-free logs/audit canary
  scans);
- the lib-mode equivalence record (merge-gate results, folded into the
  product docs) — see `EVIDENCE.md`;
- drift checks: golden hashes, manifest closure, static OpenAPI;
- worked-journey records for the App Kit print journey and the OpenFn
  delivery journey (kit-gate style: `COMPLETED with 0 flags`). The OpenFn
  record exists (`integrations/openfn/JOURNEY.md`); the App Kit record is
  produced when the kit-side capability exists.

One new gate is introduced — the two-OS golden-hash job. Invariant:
byte-stability across machines as promised in the spec §5.3. Owner: the
Render product. Scope: it runs on PRs that touch Render's paths, on merge
queues, and on pushes to main through its own `paths:` filter; it is not
(as of 2026-09-17) a branch-protection required context — making it one is
a repository-settings decision that sits outside this tree, so until then
a change that slips past the filter can merge without a golden run and a
Typst-pin or lockfile bump must be treated as requiring one manually.
Removal/review condition: the gate stops being required if the spec
deliberately narrows the byte-stability promise to same-machine
reproducibility; until then a Typst-pin upgrade that changes golden output
is a reviewed diff, never a silent pass.

Release follows the standard beta checklist (protected-main CI, exact
source/version, manifests, checksums, digests, vulnerability decision, one
install/first-run smoke, accurate notes) per OPERATIONS.md when Render joins
the roster — nothing in this DoD adds to or overrides it.
