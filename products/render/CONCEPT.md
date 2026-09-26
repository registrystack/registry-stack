# Registry Render Product Concept

Status: implemented candidate against [DEFINITION-OF-DONE.md](DEFINITION-OF-DONE.md)
Date: 2026-09-17

## Executive position

Render publishes governed registry data onto physical media — paper and
cards — with the same discipline the rest of Registry Stack applies to
APIs. It is a pure rendering function (bundle + validated data in,
byte-stable PDF + hashes out), a sealed governed template bundle as its
content unit, and a value-free audit log as its issuance record.
No database, no outbound calls, no engine changes in any other product.

## Document families

Transactional (receipts, acknowledgements, notices), attestations
(certificates, extracts, letters), credentials (ID/member/licence cards
with photo and QR, duplex), tags and labels (QR + short text). Lists are
deferred; the CLI covers most of that shape today.

## Boundary

Render is not: a document store (attachments live in the owning registry),
an e-signature or seal, a credentials-issuance system (no keys, chips, or
MRZ), an HTML converter, an imposition engine, or offline-branch
synchronization. Printed QR verification belongs to the app that owns the
record (the App Kit `registry-public-check` pattern), optionally backed by
an Evidence definition; Render mints nothing and does nothing at scan time.

## Runtime anatomy

One crate (`crates/registry-render`), one binary (`registry-render`),
following the
house product anatomy: `init`/`check`/`validate`/`seal`/`compile`/`serve`/
`healthcheck`; a strict runtime YAML
(`render.registrystack.org/v1alpha1`) for deployment-local bindings; the
`registry-platform-*` primitives (config secrets, httpsec layers and
problems, the shared audit writer, authcommon key handling, buildinfo, canonical
JSON) reused rather than reinvented.

The rendering engine is Typst in library mode, pinned at 0.15.1 with a
lockfile matched to the Typst release — including the deflate stack,
because compressed-stream bytes are part of the byte contract. The
[EVIDENCE.md](EVIDENCE.md) merge gate proves library ≡ Typst CLI byte
equality; the two-OS golden CI job keeps it proven.

## Trust rules

- Templates are governed input: reviewed, sealed (per-file hashes), and
  verified at startup and by `check`. Not treated as hostile — sized for
  accidents, with kill-at-timeout supervision for the pathological case.
- Request data is less trusted than templates: strict JSON Schema
  validation with pointers, size and media-type caps on assets, inert
  injection, world-enforced path containment.
- Paper is a disclosure surface: which fields appear on a document is an
  agreed decision recorded before a template is written (see the App Kit
  skill sketch in `integrations/`).
- Issuance integrity lives in three already-trusted places: the record's
  hash fields, the attachment bytes, and the audit log. Render adds no
  new store to defend.

## Consumers

- **App Kit hosts** — a documents route block over loopback (the
  `taskDispatch` config precedent); see `integrations/app-kit/`.
- **OpenFn jobs** — plain HTTP with API-key auth and a JSON response
  variant built for `util.request`; deterministic rendering makes
  at-least-once redelivery safe; see `integrations/openfn/`.
- **Standalone CLI** — offline, zero-config; branches, print runs, CI.
