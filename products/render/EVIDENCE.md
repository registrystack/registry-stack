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

1. `target/debug/registry-render compile --bundle <bundle> --type <doc> --data
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

Results, re-run 2026-09-17 against the current example corpus (the bundles were
rewritten to name no real programme; see **Golden record** below).

Finding 4 below fixed `creator` to the version-free string `registry-render`,
while the Typst CLI stamps its own version into `/Creator`. Library and CLI
bytes are therefore no longer equal, by design, and the gate is now the sharper
claim: they differ *only* in that field and in what the PDF writer derives from
it.

| Bundle | library sha256 | pinned CLI sha256 | Notes |
|---|---|---|---|
| receipt | `3f31d7fdc1492471259754a9acc9435c6c6475c9aa08f30a9ddcb04c8cab1519` | `c473c6d302493c305fbfb8f1064d0e4800b5dc6ea8bde206c48df27ded35b985` | bilingual RTL, QR, plain PDF |
| certificate | `252d40678919cb8496950101efa7fa4984ccd6825655679cca6dead05c7696c0` | `653995645aa51a52f978a3bae2e858f4f0a81db82e36a3c16338357887f7f5d6` | PDF/A-4 (`pdfaid:part` present in output), baseline fonts only |
| beneficiary-card | `cf607a3b82a2027abfb4345377b1b84cd2e616da7376e18f29355ca790c3da2f` | `99c23bd1c71ff2a4d3e5a6afc6bd3ef9bac0e351767eaca2691c9e8e4d6ab62d` | ID-1 duplex, photo from request assets, QR |

The library column is exactly what `golden.json` pins, so this gate and the
golden test prove the same bytes.

Divergence, enumerated exhaustively (every stream in both files inflated and
compared object by object, step 3 above):

1. `/Creator` and `xmp:CreatorTool`: `registry-render` against `Typst 0.15.1`.
2. The metadata stream's `/Length`, three bytes shorter on the CLI side,
   derived from 1.
3. The content-derived document identifier (trailer `/ID`, `xmpMM:DocumentID`,
   `xmpMM:InstanceID`) on the two non-PDF/A documents: `ident: Auto` derives it
   from document content, and that content includes the creator string. The
   PDF/A-4 certificate's identifier is byte-identical on both sides, which is
   what shows the derivation is the only reason the other two move.
4. xref byte offsets, derived from 2.

Everything else matches byte for byte: every page content stream, every embedded
font, the card's image, and every other object (receipt 29 streams, certificate
15, card 35, all equal once the four items above are normalized). A difference
outside that list is the regression this gate exists to catch.

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
3. Typst virtualizes absolute template paths as project-root-relative; the
   world then applies lexical checks and requires an exact immutable snapshot
   key (see the `data_paths_cannot_escape_the_bundle` test).
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

**Regenerated 2026-09-17, example corpus made generic.** The three example
bundles named one real programme, its institution, its jurisdiction and its
religious levy scheme. They were rewritten to name none of that while keeping
every technical property the corpus exists to exercise: Arabic/RTL primary with
French secondary, bidirectional text with embedded Latin, a ten-digit identifier
pattern, a currency (now `XTS`, the ISO 4217 code reserved for testing), a region
field, an embedded photo, and an offline QR. Content changed in all three
bundles, so all three were re-sealed and every pinned value moved. The document
versions were deliberately *not* bumped (receipt stays v3, certificate and
beneficiary-card v1): nothing has been released, and a bump would imply an
earlier version existed in the wild.

This entry supersedes the earlier same-day regeneration rounds (the PDF creator
fix, the cross-locale label key alignment, and adding `fonts/OFL.txt`); their
values are no longer reachable from this tree, and their causes are recorded in
the findings above.

| Bundle | pdf sha256 |
|---|---|
| receipt | `3f31d7fdc1492471259754a9acc9435c6c6475c9aa08f30a9ddcb04c8cab1519` |
| certificate | `252d40678919cb8496950101efa7fa4984ccd6825655679cca6dead05c7696c0` |
| beneficiary-card | `cf607a3b82a2027abfb4345377b1b84cd2e616da7376e18f29355ca790c3da2f` |

Envelope (`dataSha256`) and bundle hashes moved with them and live in
`golden.json`: receipt envelope
`8ab91deaf04f2ab9634da9fe45e63615f285c936659f8d839f413f647641b33a` / bundle
`96d199d20c94b39d4947168a84337277db1f01e86bb8907d0614d211855b0e26`; certificate
envelope `cccb32e6fdcf4db99a556ede3abedcc4f46b94575b20a4b5ce361edfd1ac555a` /
bundle `3bb68569252cd621f0b6992b329de04524c29d02995c14056892f177ac9e6dff`;
beneficiary-card envelope
`c595a3670a9b83327a8e16ef403b8253039d6d548b3388875930850d0f41fa18` / bundle
`4dd435c0bed4c80f4408dc87173b0f72887071ca78f734441bed979cabfe7d88`. The
per-render dependency closures are unchanged. Every warning list is empty.

The Arabic strings in the rewritten fixtures are plausible modern standard
Arabic written for this corpus; they want a native read before anything ships
to a reader as example copy.

The Typst pin bump burden improves with this change: a pin bump now
changes golden bytes only when layout changes, not when the Typst
version string does.

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
  sealing (sealed loads also reject symlinks while capturing their immutable
  render snapshot).
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
  locale), a data fixture is written, the unsealed notice prints on
  compile, and edit-after-seal names `registry-render seal` as recovery.
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
end-to-end); the run record pins the revision, which this branch's
history does not survive. The same PR registers
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
- **Label key sets must agree across locales** at `registry-render check` and serve
  startup — which caught both example bundles (receipt and card locales
  diverged; now aligned with real translations and re-sealed).
- **File closures are pinned per bundle in `golden.json`** and every
  non-virtual dep must be manifest-governed (the closure-drift gate).
- **The golden workflow** runs the scaffold suite on both OSes, triggers on
  the eight `registry-platform-*` path dependencies, and no longer cancels
  the second OS when the first fails.
- **The Noto fonts ship with `OFL.txt`**; `load_fonts` loads only font
  files by extension so licenses can live beside fonts.
- **`registry-render init` scaffolds real starter fonts** (Noto Sans + Noto Naskh
  Arabic + OFL.txt) instead of an empty `fonts/`. They are embedded in the
  binary, which costs about 850 KiB: the price of a scaffold that renders
  Latin and Arabic offline with zero edits.
- Docs now match shipped behavior throughout; exit codes 2-22 are
  documented in README.md; the OpenAPI drift test parses the served
  document and compares the declared paths and the render route's
  documented statuses structurally; `TYPST_PIN`
  is tied to the linked typst by a unit test.

Test totals after the round: 55 (15 unit, 13 golden, 13 serve end-to-end,
14 scaffold/CLI), all green with `--locked`.

### Staff-engineer second pass (2026-09-17)

A second review of the fix round found four completions, all fixed with
failing tests first:

- **SIGTERM exit is bounded.** The drain held the door but nothing
  bounded connection teardown — executed proof: a render past a 3s grace
  held exit open 57.5s. The stop signal is now broadcast once; the drain
  gets one grace, connection teardown a second, and dropping the serve
  future at the bound abandons stragglers (their workers are killed). A
  unix test drives a beyond-grace render through SIGTERM.
- **Chunked bodies are refused up front.** A chunked stream that trips the
  stream limit mid-body cannot be answered at all (broken request stream),
  so it produced a plain 413 and no audit event; chunked transfer is now
  refused before the first body byte as an audited problem naming
  Content-Length. SECURITY-MATRIX row 18 records the mid-stream residual.
- **`today(offset)` honors fractional hours** at full-second precision —
  `Duration::hours()` is f64 total hours, and rounding +5h30m to 6h
  crossed midnight for an 18:15Z issuance.
- The golden-record note above now attributes each bundle's delta
  correctly (creator fix vs label alignment + OFL re-seal); the earlier
  "dataSha256 unchanged" claim was false for receipt and card.

Also from that review: wrong methods on the render route answer the
problem vocabulary with an audit event (the route takes any method; the
old dead branch produced axum's bare 405), `registry-render audit-verify` warns
when zero records verify against a non-empty ledger (a running writer
holds the active segment), the `load_fonts` doc comment matches the
baseline-first order, and the README exit-code intro no longer claims an
"unmapped failure" code nothing emits (clap usage errors also exit 2; a
panic exits 101).

Test totals after the second pass: 63 (18 unit, 13 golden, 17 serve
end-to-end, 15 scaffold/CLI), all green with `--locked`. The second
pass's own total line understated this: two later commits in the same
round (comma-separated `--labels`, runtime-relative path anchoring) added
tests without updating it.

### Third pass (2026-09-17)

A third review, of the second pass's fixes, confirmed them and found
seven more, each fixed with a failing test first except where noted:

- **Schema refusals echoed request data.** The validator's message quotes
  the offending value, so a payer identifier or a name left the process in
  the problem detail. Refusals now name the field pointer and the schema
  rule it violated, plus the absent property for a `required` failure
  (that name comes from the schema, not the request).
- **Per-request bundle-load problems carried host paths.** Serve reloads
  the sealed bundle in every worker, so a refused symlink or an unreadable
  manifest sent the deployment's real path to the caller. The bundle root
  is now redacted to `<bundle>` in both its given and canonical spelling.
- **Problem details were unbounded.** An undeclared locale and a badly
  named asset are named back to the caller, who chooses their length.
  Details are capped at 2048 characters with an explicit marker.
- **`shutdownGraceSeconds` was unvalidated.** Zero dropped renders in
  flight on SIGTERM, and a value near the integer ceiling panicked the
  shutdown path where it adds the grace twice. The range is now 1 to 3600.
- **The SIGTERM handler was installed inside the spawned signal task**,
  where its only failure mode was a panic that killed that task alone and
  turned SIGTERM into an immediate exit. Installation now happens before
  the server accepts and refuses startup on failure. This one carries no
  test: the failure cannot be provoked from a test process.
- **A refused bind left state behind.** Opening the audit ledger creates
  its directory, and that ran before the bind was validated. The address
  is settled first.
- **Two CLI argument combinations silently did nothing**: `compile
  --watch --emit-envelope` entered the watch loop and never wrote the
  envelope, and `init --labels en,en` scaffolded one label file twice
  before failing on the directory that already existed. Both are usage
  errors now.

Test totals after the third pass: 71 (22 unit, 13 golden, 19 serve
end-to-end, 17 scaffold/CLI), all green with `--locked`.

## Immutable bundle snapshot hardening (2026-09-19)

Sealed loads now capture the complete bundle through held directory
descriptors, refusing symlinks and non-regular files without a pathname reopen.
The manifest hash map is verified over those captured bytes, and the same
immutable snapshot supplies the manifest, labels, schemas, fonts, templates,
package sources, and other project/package files consumed by Typst.

Executable proof covers both sides of the former verified/use gap:

- `bundle::tests::assembly_uses_captured_bytes` changes the manifest, entry,
  labels, schema, and font paths after capture; assembly still consumes the
  captured bytes.
- `golden::sealed_template_and_package_bytes_are_bound_to_the_loaded_snapshot`
  replaces the template, a package source, and a non-source file after sealed
  load; every render remains byte-identical under the original bundle hash.
- The existing per-render serve drift test still refuses drift present before
  a worker captures its snapshot.

On the hardened revision, all 73 Registry Render tests pass (23 unit, 14
golden, 19 serve end-to-end, 17 scaffold/CLI), along with locked all-target
check, clippy with warnings denied, and formatting.

### Scaffold contents (2026-09-17)

The scaffold vendors no third-party Typst package. The generated template
never imported one: every `init` wrote 136K into the new bundle, 113K of
it a WASM plugin, for files `seal` then hashed and nothing read, and the
binary carried the same bytes through `include_bytes!`. The scaffold's
template and README now say where a package lives and that none is
fetched at render time. The three example bundles keep their vendored
copy, which is what the golden hashes cover, and remain the worked
example.
