# Registry Render Product Concept

Status: implemented candidate
Date: 2026-09-17

## Executive position

Render publishes governed registry data onto physical media — paper and
cards — with the same discipline the rest of Registry Stack applies to
APIs. It is a pure rendering function (bundle + validated data in,
byte-stable PDF + hashes out), a governed template package as its
content unit, and a value-free audit log as its issuance record.
No database or rendering-path network calls, and no engine changes in any other
product. Only the optional HTTP adapter uses OIDC discovery/JWKS networking.

## Document families

Transactional (receipts, acknowledgements, notices), attestations
(certificates, extracts, letters), credentials (ID/member/licence cards
with photo and QR, duplex), tags and labels (QR + short text). Lists are not a
supported family.

## Boundary

Render is not: a document store (attachments live in the owning registry),
a qualified e-signature or seal service (see Sealing below for the optional
seal it does apply), a credentials-issuance system (no keys, chips, or
MRZ), an HTML converter, an imposition engine, or offline-branch
synchronization. Printed QR verification belongs to the app that owns the
record through an app-owned public check route and an Evidence-backed relying
service. The app owns the bounded answer and its disclosure policy; Render
mints nothing and does nothing at scan time.

Version 1 has no batch or multi-document request, client crate, TLS
termination, per-tenant rate limiting, metrics route, or hot reload or runtime
bundle editing, and no document-type-specific behavior in production code.

## Sealing

Sealing is optional and off unless the runtime file declares `signing.seals`.
With it, `POST /v1/seal/{type}` renders a document and returns it with a PAdES
signature made with the institution's own key. A document type opts in by
naming a seal in the bundle manifest (`seal: <id>`); the caller never chooses
the seal.

The boundary:

- Render seals only what it just rendered from a verified package, never bytes
  a caller supplies. There is no route that accepts a PDF to sign.
- The private key is loaded in the serving (parent) process and never sent
  to the render worker. The render worker receives no key; it renders the first revision and writes an empty signature
  field the parent fixed. The parent checks the field's shape by byte offsets
  and checks the package hash, signs, optionally timestamps, and splices the
  signature in.
- The seal is a certification signature (DocMDP permission 2) in an invisible
  field. A template can print a visible seal block from the payload's
  `signing` member, which exists only on the seal route.
- Sealing needs OIDC. The `render:seal` scope is separate from `render:render`,
  and each seal names the clients allowed to use it. The legacy API key never
  seals.
- A seal is PAdES baseline B-T by default (an RFC 3161 timestamp from the
  configured authority). B-B, with no timestamp, is a named choice that stops
  validating when the certificate expires. A failing timestamp fails the
  request; it never falls back to B-B.

An institution may sign elsewhere instead, with a tool of its own, as long as
the tool saves incrementally, so the signed file starts with the exact bytes
Render produced. One check, with `render.pdf` the Render output and
`signed.pdf` the result:

```sh
head -c "$(wc -c < render.pdf)" signed.pdf | cmp - render.pdf && echo "signed file starts with the Render bytes"
```

What sealing does not do:

- It makes no qualification claim. Whether a seal is advanced or qualified
  under eIDAS, or recognised under any other scheme, depends on the
  certificate, its issuer and the key custody, not on this encoding. Render
  writes the signature to the PAdES baseline B-B and B-T levels;
  [EVIDENCE.md](EVIDENCE.md) records the pyHanko, EU DSS and veraPDF runs on
  sealed files `serve` answered, and what those runs do not show.
- It embeds no revocation data and no document security store, so there is no
  B-LT or B-LTA level.
- It does not support external signatures yet: the key is a local JWK
  reached through a secret reference. Local key files suit development and
  pilots only: a render worker that gained code execution runs as the
  serving user and can read one.
- It does not pin the timestamp authority's identity or decide trust. The
  authority is reached over TLS with the host's roots, and validators decide
  whether the seal certificate and the timestamp authority are trusted.
- veraPDF has passed sealed PDF/A-1b, PDF/A-2b, PDF/A-4 and PDF/UA-1 files
  that `serve` answered ([EVIDENCE.md](EVIDENCE.md)). No validator run covers
  a seal under PDF/A-1a, A-2a, A-2u, A-3a, A-3b, A-3u, A-4e or A-4f; `check`
  and `serve` warn about a document type sealed under one
  (`render.bundle.seal-standard-unverified`).

## Runtime anatomy

One crate (`crates/registry-render`), one binary (`registry-render`),
following the
house product anatomy: `init`/`check`/`validate`/`package`/`compile`/`serve`/
`healthcheck`; a strict runtime YAML
(`id.registrystack.org/formats/render/runtime/v1alpha1`, read by the shared
runtime configuration loader) for deployment-local bindings; the
`registry-platform-*` primitives (config loader and secrets, httpsec layers and
problems, the shared audit writer, authcommon key handling, buildinfo, canonical
JSON) reused rather than reinvented.

The rendering engine is Typst in library mode, pinned at 0.15.1 with a
lockfile matched to the Typst release — including the deflate stack,
because compressed-stream bytes are part of the byte contract. The
[EVIDENCE.md](EVIDENCE.md) merge gate proves library ≡ Typst CLI byte
equality; the two-OS golden CI job keeps it proven.

## Trust rules

- Templates are governed input: reviewed, built into the shared package
  envelope, and verified at startup and by each worker. They are not treated as hostile — sized for
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

- **App Kit hosts**: an app-owned route through the existing host-route seam;
  author `bundle/`, package it into verified `package/`, and serve that output.
  See `integrations/app-kit/`.
- **OpenFn jobs**: HTTP with resource-token or legacy API-key auth and a JSON response
  variant built for `util.request`; deterministic rendering makes
  at-least-once redelivery safe; see `integrations/openfn/`.
- **Standalone CLI** — offline, zero-config; branches, print runs, CI.
