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
   `creator: Auto`, `tagged: true`, `pretty: false`) — Auto derives the
   document ID from content, which the golden hashes pin.

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
