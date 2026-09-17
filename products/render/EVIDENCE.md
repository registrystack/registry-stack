# Registry Render evidence record

Status: living evidence for the acceptance contract in `DEFINITION-OF-DONE.md`
Date of first entry: 2026-09-17
All hashes below were produced on macOS (aarch64) with the workspace lockfile
in this tree; the two-OS CI golden job re-proves them on Linux for every
change.

## Merge gate: library mode ≡ Typst CLI (2026-09-17)

The Definition of Done's merge gate: a library-mode render must reproduce the
pinned Typst CLI's sha256 for the same inputs — the same bundle, the same
canonical envelope bytes, the same creation timestamp — on the same machine.

Pinned CLI: typst 0.15.1 (aarch64-apple-darwin, sha256
`7c4a136b377f3689400afe37b4f0fe3528d50faaa55cbb1106ac8a128f86ba1a`).

Procedure (per bundle, all commands from the repo root):

1. `target/debug/render compile --bundle <bundle> --type <doc> --data
   fixtures/data.json [--asset photo=fixtures/photo.b64] --issued-at
   2026-09-16T10:32:00Z --emit-envelope env.json --out lib.pdf`
2. typst CLI with the exact envelope bytes and matching world:
   `typst compile --root <bundle> --ignore-system-fonts [--font-path
   <bundle>/fonts] --package-path <bundle>/packages --creation-timestamp
   1789554720 [--pdf-standard a-4] --input data="$(cat env.json)"
   <bundle>/templates/<entry> cli.pdf` (the card gate ran against a temp
   copy with the photo decoded to `<bundle>/assets/photo` — the library
   serves the same bytes from the request's virtual `assets/` namespace).
3. `cmp lib.pdf cli.pdf`.

Results (all identical, byte for byte):

| Bundle | sha256 | Notes |
|---|---|---|
| receipt | `ce939b77f78cadda7183ad6ea9207c366a7b579c01cbff73a42f44293b356398` | bilingual RTL, QR, plain PDF |
| certificate | `ffead2dad8f698dd137e2447aaadd6976c82a270de177a772cf8d9db5b173e1b` | PDF/A-4 (`pdfaid:part` present in output), baseline fonts only |
| beneficiary-card | `ce588994f2cdb11d22e4e848b7d40ad2a228e7b978eaff8d361253477c9f72b9` | ID-1 duplex, photo from request assets, QR |

Closure check: the library's per-render closure and the CLI's `--deps`
output list the same file set (template + the four zebra package files);
the library records them in package-spec form (`@preview/zebra:0.1.0/…`)
and the CLI in path form (`packages/preview/zebra/0.1.0/…`) — same files,
deterministic identifiers, verified 2026-09-17.

Findings folded back into the product (the gate's purpose):

1. **The deflate stack is part of the byte contract.** Library and CLI
   produced PDFs identical in every decompressed stream and object except
   one stream's compressed encoding. Root cause: our lockfile had resolved
   `zlib-rs 0.5.5` while the Typst 0.15.1 release pins `0.5.1`; deflate
   output changed between those patches (`flate2 1.1.9 → 1.1.2`,
   `miniz_oxide 0.8.9 → 0.8.5` aligned too, matching the Typst release
   lockfile). The workspace lockfile now pins
   `flate2 1.1.2 / zlib-rs 0.5.1 / libz-rs-sys 0.5.1 / miniz_oxide 0.8.5`.
   Consequence, now a rule: **deflate-stack upgrades are golden-hash
   diffs**, reviewed like a Typst pin change. The two-OS golden gate
   enforces this for every change.
2. Font book order (baseline set before bundle fonts, mirroring the CLI)
   did not change these documents — no fallback overlaps here — but the
   order stays fixed as part of the world construction rules regardless.
3. Typst virtualizes absolute template paths as project-root-relative, so
   containment is enforced twice: typst's normalization and the world's
   canonicalize-then-contain check (see the `data_paths_cannot_escape_the_
   bundle` test).
4. `PdfOptions` must match the CLI defaults exactly (`ident: Auto`,
   `tagged: true`, `pretty: false`) — Auto derives the document ID from
   content, which the golden hashes pin. (Amended 2026-09-17, PR review
   item 12: `creator` is now the fixed, version-free string
   `registry-render` instead of `Auto`, so the Typst version no longer
   appears in PDF bytes; `ident` stays `Auto`. The Typst CLI stamps its
   own version into `/Creator`, so library output intentionally differs
   from CLI output by that field from here on.)

## Golden record

`golden.json` pins, per bundle: PDF sha256, envelope (`dataSha256`)
sha256, warnings (empty), bundle hash. Issued time fixed at
`2026-09-16T10:32:00Z`. Regenerate only via the documented command and only
as a reviewed diff:

```sh
cargo test -p registry-render --test golden   # fails with the drift first
```

The two-OS CI job (see `.github/workflows/render-golden.yml`) runs the
golden test on macOS and Linux; identical hashes across both are the
cross-machine byte-stability proof the DoD requires.

**Regenerated 2026-09-17** (PR review item 12, fixing the PDF creator
string; same procedure — drift observed by the golden test first, then the
pinned values updated as the reviewed diff):

| Bundle | sha256 |
|---|---|
| receipt | `994d0f28e1bba12887ef83b53374c05063cfd1547a553870fa86dabb85824f2b` |
| certificate | `636daae8c1cd2fba01f0d0d60244073d468827fc993cc514b75868660e7552e8` |
| beneficiary-card | `8f36c070da1d322664d46ad2b1423ce35eac7c380c1b199a7b99ff4c327f1ec8` |

`dataSha256` and bundle hashes are unchanged; the byte delta is the
`/Creator`/XMP `CreatorTool` metadata only. The Typst pin bump burden
improves with this change: a pin bump now changes golden bytes only when
layout changes, not when the Typst version string does.

## Implementation review round (2026-09-17)

Two adversarial expert reviews ran against the working tree (systems/
security and adopter-experience). Findings fixed in the same revision:

- **Per-request seal enforcement** — serve workers now load sealed and the
  response bundle hash must equal the startup hash; the seal invariant is
  no longer startup-only.
- **`/v1/documents` authenticated** (it previously leaked the inventory
  unauthenticated, contradicting the crate's own OpenAPI).
- **Audit-ledger write hardening** — caller-controlled route parameters
  are bounded and kebab-validated before any audit append, including
  pre-auth 401 events.
- **Hash coverage** — only the root manifest is exempt from sealing; nested
  `manifest.yaml` files are governed content, and any symlink refuses
  sealing (the world would refuse it at render, so a seal that hashed its
  target could verify-but-not-render).
- **Auth moved to a layer before body buffering**; the API-key file is
  rejected with leading/trailing whitespace (a silent always-401 footgun).
- **`audit-verify` verified the wrong path** (the directory, hence an
  empty view — the happy-path test had passed vacuously); it now proves
  the real ledger, and a tampered-ledger negative test keeps that honest.
- **Request lifecycle logs** (method class, route template, status,
  latency, trace id) via middleware; 401 audit-append failures are
  logged, not swallowed.
- **`check --require-audit-under <root>`** added (with `--runtime`).
- **Verify-then-seal ordering** in `check --seal`; a broken bundle never
  gains a seal.
- **Scaffold honesty** — non-Latin `--labels` scaffold compiles with zero
  edits (full label key set seeded, template bound to the declared
  locale), the QR package is vendored into every scaffold, a data fixture
  is written, the unsealed notice prints on compile, and edit-after-seal
  names `render seal` as recovery.
- **OpenAPI drift** corrected (413 documented, unimplementable 429
  removed) and pinned by a serve test.
- Dead code removed; font-order doc fixed to match the implementation
  (baseline set first, mirroring the Typst CLI).

Documented residuals live in `SECURITY-MATRIX.md` (bundle-directory
TOCTOU with the read-only-content assumption, macOS without `RLIMIT_AS`,
post-export size check, code-level asset caps).

Test totals after the round: 36 (7 unit, 11 golden, 9 serve end-to-end,
9 scaffold/CLI), all green with `--locked`; `cargo fmt --check`,
`clippy -D warnings`, and `cargo deny check` pass on the same revision.

## Two-OS golden gate: first proof (2026-09-17)

PR #1113 run 35177001158 — `Registry Render golden gate` green on both
`ubuntu-24.04` and `macos-14` (golden hashes, determinism suite, serve
end-to-end), on revision `8e06eca6a`. The same PR registers
`registry-render` in the CI classifier's Rust shard inventory (new
`render` shard), so ordinary Rust-workspace routing also covers the
crate; the classifier's own test suites (111 tests) pass with the new
shard.

## PR #1113 review round (2026-09-17)

An adversarial review of the PR (three blockers, should-fix list, docs-vs-code
audit) was triaged and fixed item by item on this branch, TDD where a test
could express the finding. Behavior changes:

- **Caller API key files**: exactly one trailing line ending is trimmed
  (the platform's shared normalization, now exported from authcommon);
  any other whitespace refuses startup instead of arming a key no caller
  can present while `/health` stays green.
- **Compile diagnostics carry virtual paths only**: world `NotFound`
  errors name root-relative virtual spellings, a redaction pass replaces
  any residual host bundle root with `<bundle>`, and a golden test pins
  the behavior.
- **The DoD no longer claims the App Kit journey was walked**; it is the
  acceptance requirement, with the deferral and sizing in ACCEPTANCE.md.
- **Serve workers load sealed per request** (the `requireSealed` flag was
  dead); tamper- and unseal-after-startup are both refused with their
  named problems.
- **`datetime.today(offset)` shifts the issuance instant** (22:30Z + 3h is
  the next day), and an unrepresentable offset yields `None`, not a panic.
- **Manifest `schema:` paths get the entry containment rule.**
- **PDF export runs inside the panic boundary.**
- **CLI renders are bounded**: `compile` (and each `--watch` iteration)
  render through the supervised worker with a `--timeout` flag (serve's
  default), so a pathological template costs its timeout, never an
  unbounded hang.
- **Shutdown drains inside the graceful-shutdown window**; renders past the
  grace are abandoned (which kills their worker).
- **The body ceiling moved inside authentication**: unauthenticated
  oversized bodies are 401s, never buffered; authenticated ones get an
  audited `body-too-large` problem (413, exit 22), with the tower stream
  limit as the backstop.
- **`server.bind` defaults to `127.0.0.1:8080`** and public or
  all-interfaces binds refuse startup.
- **The PDF creator is the fixed, version-free string `registry-render`**
  (goldens regenerated — see the golden-record section).
- **`registry-platform-httputil` removed** (declared, unused, and quietly
  supplying tokio's `io-util` via feature unification); the inert
  `serve-tests` feature removed with it.
- **Worker stderr is piped and drained**, never inherited.
- **`/health` reports bundle and renderer versions** (value-free).
- **`--now` announces the instant it chose; `--json` failures are
  RFC 9457 problem documents on stderr; `validate` gained `--json`.**
- **Label key sets must agree across locales** at `render check` and serve
  startup — which caught both example bundles (receipt and card locales
  diverged; now aligned with real translations and re-sealed).
- **File closures are pinned per bundle in `golden.json`** and every
  non-virtual dep must be manifest-governed (the closure-drift gate).
- **The golden workflow** runs the scaffold suite on both OSes, triggers on
  the eight `registry-platform-*` path dependencies, and no longer cancels
  the second OS when the first fails.
- **The Noto fonts ship with `OFL.txt`**; `load_fonts` loads only font
  files by extension so licenses can live beside fonts.
- **`render init` scaffolds real starter fonts** (Noto Sans + Noto Naskh
  Arabic + OFL.txt) instead of an empty `fonts/`.
- Docs now match shipped behavior throughout; exit codes 2-22 are
  documented in README.md; the OpenAPI drift test parses the served
  document and compares paths/methods/statuses structurally; `TYPST_PIN`
  is tied to the linked typst by a unit test.

Test totals after the round: 55 (15 unit, 13 golden, 13 serve end-to-end,
14 scaffold/CLI), all green with `--locked`.
