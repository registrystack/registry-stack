# Registry Render evidence record

Status: living evidence for the merge gate and the golden record
Date of first entry: 2026-09-17
All hashes below were produced on macOS (aarch64) with the workspace lockfile
in this tree; the two-OS CI golden job re-proves them on Linux for every
change.

## Document seals: external validators (2026-11-06)

Three external validators checked sealed files that `serve` answered on this
branch. The ignored test `write_served_seal_samples` in
`crates/registry-render/tests/serve_seal.rs` writes them: it serves the
`tests/fixtures/sealed-notice` bundle with an ES256 seal key and an RFC 3161
test authority, each under its own test root generated at test time, and
writes each sealed file, its `documentSha256` and both roots.

```sh
REGISTRY_SEAL_SAMPLE_DIR=<existing directory> \
  cargo test -p registry-render --test serve_seal write_served_seal_samples -- --ignored
```

| Sample | Document type | Level | PDF standard |
|---|---|---|---|
| `notice-b-t.pdf` | `notice` | B-T | none |
| `notice-b-b.pdf` | `notice` | B-B | none |
| `archive-1b-b-t.pdf` | `archive-1b` | B-T | PDF/A-1b |
| `archive-b-t.pdf` | `archive` | B-T | PDF/A-2b |
| `archive-4-b-t.pdf` | `archive-4` | B-T | PDF/A-4 |
| `accessible-b-t.pdf` | `accessible` | B-T | PDF/UA-1 |

**pyHanko 0.38.1**, through `products/render/scripts/validate-seal.py`
(`uv run --offline --script`, both roots as `--trust-root`, the answer's
`documentSha256` as `--document-sha256`, no fetching, soft-fail revocation):
all six files returned `ok: true`. Each B-T file passed twelve checks:
`one-signature`, `intact`, `valid`, `trusted`, `not-revoked`,
`covers-entire-file`, `certification-docmdp-p2`, `docmdp-ok`,
`subfilter-cades-detached`, `no-signing-time-attribute`,
`signature-timestamp-valid` and `first-revision-sha256`. The B-B file passed
the same checks less `signature-timestamp-valid`. A copy of `notice-b-t.pdf`
with one byte flipped at offset 4096 returned `ok: false`, failing `intact`,
`trusted` and `first-revision-sha256`.

**veraPDF 1.30.3**, from
`verapdf/cli@sha256:d74b7026c18a0f171e73c153b617fe6520e1511feb24ca98a348b2bb897669fb`
run with `--platform linux/amd64 --network none`: PASS for each sealed file
and for its first revision (the sealed file cut at the rendered length), eight
runs in all: `archive-1b` against `1b`, `archive` against `2b`, `archive-4`
against `4` and `accessible` against `ua1`.

**EU DSS 6.5.1**, the `dss-pades-pdfbox` library with its default validation
policy, both roots as trusted certificates, revocation checking for untrusted
chains off, run under a macOS sandbox profile that denies network access:

- Format `PAdES-BASELINE-T` for the five B-T files and `PAdES-BASELINE-B` for
  `notice-b-b.pdf`.
- Indication `INDETERMINATE`, sub-indication
  `CERTIFICATE_CHAIN_GENERAL_FAILURE`, for every file.
- No constraint failed in format checking (`BBB_FC`), identification of the
  signing certificate (`BBB_ICS`), cryptographic verification (`BBB_CV`) or
  signature acceptance validation (`BBB_SAV`).
- The constraints that failed (`ADEST_ROBVPIIC`, `ARCH_IRTVBBA` on the B-T
  files only, `ARCH_LTVV`, `BBB_XCV_IRDPFC`, `BBB_XCV_SUB`, `LTV_ABSV`,
  `QUAL_CERT_TRUSTED_LIST_REACHED`) and warned (`BBB_XCV_AIA_PRES`,
  `BBB_XCV_REVOC_PRES`, `BSV_IXCVRC`, `QUAL_IS_ADES`) ask for revocation data,
  an authority information access extension or an EU trusted list. The test
  roots have none of these, and Render embeds no revocation data (no B-LT or
  B-LTA).

What these runs do not show:

- No run used a production certificate chain or a public timestamp authority,
  so no DSS run reached a passed indication, and `trusted` in pyHanko means
  only that the test roots were supplied.
- No ETSI conformance checker or plugtest was run.
- No run covers a seal under PDF/A-1a, A-2a, A-2u, A-3a, A-3b, A-3u, A-4e or
  A-4f; `check` and `serve` warn about one
  (`render.bundle.seal-standard-unverified`).
- None of this is an eIDAS qualification claim.

## Configuration conventions (2026-10-08)

The bundle manifest and the label tables are read by the shared
configuration reader. The manifest opens with
`apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1` and names
its files with `entryFile` and `schemaFile`; each label table opens with
`apiVersion: id.registrystack.org/formats/render/labels/v1alpha1` and
`kind: RenderLabels` and holds its keys under `labels`. The template still
receives each table as the same flat key-to-text map, so every golden PDF
hash and every request envelope (`dataSha256`) hash is unchanged. The three
maintained examples were rewritten to the new spellings and repackaged, so
their package digests moved:

| Package | digest |
|---|---|
| receipt | `sha256:e8cb42fe6b0aff240d3968d9022ae7968fa5e35f10c667835af15d37ab47c164` |
| certificate | `sha256:9d736a3fb21fd02f4e048b5e3782ce4fb710cf63f222aa4c91cc7ac9607ae9d6` |
| beneficiary-card | `sha256:9c3f33af90d412a189090e5c1d8590174df93f75d943a1441c1692b30eb03577` |

`golden.json` pins these digests; `cargo test -p registry-render --test
golden` reproduces them with the unchanged PDF and envelope hashes.

## Shared package migration (2026-09-26)

Render now uses the Registry Stack package envelope instead of embedding
per-file hashes in `manifest.yaml`. `registry-render package` validates raw
authoring source, copies the exact validated files into a new directory, and
writes sorted `SHA256SUMS` plus optional `REVISION`. The three maintained
examples were current packages. On that date their package digests were:

| Package | digest |
|---|---|
| receipt | `sha256:a4109d91fe340fd054c09f1b3b0d857332f964dd853265b13b014f248d7a2d38` |
| certificate | `sha256:66e42dd1232470c8153411d16a9099ddb50727e76df57153f63c799fcade2051` |
| beneficiary-card | `sha256:6089a24558875d34a015cd09e207d4b5fd6bec62716fbd5075576398343cd6ac` |

Startup verifies `package.root`, applies optional `package.expectedDigest`,
captures the package through held descriptors, and binds every captured byte
and the captured sum file back to the shared verification result before any
Render validation or consumer construction. Every serve worker repeats that
process and the parent requires its digest to match startup. This covers lazy
Typst template imports, vendored package source, fonts, schemas, labels, and
`read()` calls rather than proving only startup metadata.

Executable proof covers successful repeatable packaging with an optional
revision, raw authoring checks, current-package check/validate/compile,
missing/changed/extra file refusals by name, matching and mismatching digest
pins, no-pin serving, path replacement between shared verification and product
capture, and drift before a later render. The focused migration run passed 34
unit tests, 14 golden tests, 19 scaffold/CLI tests, and 20 serve tests, followed
by clippy for all Render targets with warnings denied.

The dated entries below preserve the evidence history of the retired manifest
seal. Where they use “seal” or old test names, this section
describes the replacement contract.

## Merge gate: library mode ≡ Typst CLI (2026-09-17)

The merge gate: a library-mode render must reproduce the
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

`PdfOptions` (item 4 of the world-construction rules below) fixes `creator` to the version-free string `registry-render`,
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
   content, which the golden hashes pin. (`creator` is the fixed, version-free string
   `registry-render` instead of `Auto`, so the Typst version no longer
   appears in PDF bytes; `ident` stays `Auto`. The Typst CLI stamps its
   own version into `/Creator`, so library output intentionally differs
   from CLI output by that field.)

## Golden record

`golden.json` pins, per bundle: PDF sha256, request envelope (`dataSha256`)
sha256, warnings (empty), and package hash. Issued time fixed at
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
bundles, so all three were rebuilt and every pinned value moved. The document
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

Envelope (`dataSha256`) and package hashes live in
`golden.json`: receipt envelope
`8ab91deaf04f2ab9634da9fe45e63615f285c936659f8d839f413f647641b33a` / package
`a4109d91fe340fd054c09f1b3b0d857332f964dd853265b13b014f248d7a2d38`; certificate
envelope `cccb32e6fdcf4db99a556ede3abedcc4f46b94575b20a4b5ce361edfd1ac555a` /
package `66e42dd1232470c8153411d16a9099ddb50727e76df57153f63c799fcade2051`;
beneficiary-card envelope
`c595a3670a9b83327a8e16ef403b8253039d6d548b3388875930850d0f41fa18` / package
`6089a24558875d34a015cd09e207d4b5fd6bec62716fbd5075576398343cd6ac`. The
per-render dependency closures are unchanged. Every warning list is empty.
The package digests have moved since; the configuration conventions entry
above gives the current ones.

The Arabic strings in the rewritten fixtures are plausible modern standard
Arabic written for this corpus; they want a native read before anything ships
to a reader as example copy.

The Typst pin bump burden improves with this change: a pin bump now
changes golden bytes only when layout changes, not when the Typst
version string does.

## Immutable bundle snapshot hardening (2026-09-19; package binding updated 2026-09-26)

Package loads capture the complete directory through held directory
descriptors, opening every component in the configured root spelling and every
descendant with `NOFOLLOW`, and refusing symlinks and non-regular files without
a pathname reopen.
The manifest is opened and parsed first through the secured root descriptor, so
a missing or malformed manifest is refused before any descendant is read. Its
exact bytes are retained in the snapshot. The shared package verification is
bound to the captured file set and digests, and the same immutable snapshot supplies the
manifest, labels, schemas, fonts, templates, package sources, and other
project/package files consumed by Typst. Authoring capture and package loading
use the same root traversal, so neither accepts a root or ancestor symlink.

Executable proof covers both sides of the former verified/use gap:

- `bundle::tests::assembly_uses_captured_bytes` changes the manifest, entry,
  labels, schema, and font paths after capture; assembly still consumes the
  captured bytes.
- `bundle::tests::bundle_root_and_ancestor_symlinks_are_refused_for_every_spelling`
  covers a root symlink with a trailing slash and a symlinked ancestor during
  snapshot loading.
- `bundle::tests::source_load_checks_the_manifest_before_capturing_descendants`
  places a refused symlink beside missing and malformed manifests;
  each manifest result wins before descendant capture.
- `bundle::tests::package_load_refuses_bytes_replaced_after_shared_verification`
  deterministically replaces a verified file before product capture and proves
  the consumed-byte binding refuses it.
- `golden::verified_template_and_typst_package_bytes_are_bound_to_the_loaded_snapshot`
  replaces the template, a package source, and a non-source file after package
  load; every render remains byte-identical under the original package hash.
- The existing per-render serve drift test still refuses drift present before
  a worker captures its snapshot.

On the hardened revision, all 76 Registry Render tests pass (26 unit, 14
golden, 19 serve end-to-end, 17 scaffold/CLI), along with locked all-target
check, clippy with warnings denied, and formatting.

### Shared audit writer (2026-09-25)

Render's audit moved off the keyed hash chain onto the platform audit
writer that every Registry Stack product shares. The `audit` runtime block
is now `{destination, path, rotateBytes, retainDays}`; `directory`,
`integrityKeyRef`, and `maxSegmentBytes` are refused as unknown fields, and
`serve` holds one secret, the caller API key. Each line is the envelope
`{schema, eventId, time, phase, correlation, record}` with schema
`render.registrystack.org/audit/v1`; the record keeps its field set, with
`outcome` absent on the request entry.

A render previously wrote one event after the worker finished. It now
writes a `request` entry that must be accepted before the worker starts,
then a `response` entry that must be accepted before the document leaves.
`registry-render audit-verify` and its tampered-ledger test are gone: the
log carries no chain to verify. `check --require-audit-under` proves the
audit file's location and refuses a `stdout` destination. The 401 and 413
audit-append failures now log at error level.

### Scaffold contents (2026-09-17)

The scaffold vendors no third-party Typst package. The generated template
never imported one: every `init` wrote 136K into the new bundle, 113K of
it a WASM plugin, for files `seal` then hashed and nothing read, and the
binary carried the same bytes through `include_bytes!`. The scaffold's
template and README now say where a package lives and that none is
fetched at render time. The three example bundles keep their vendored
copy, which is what the golden hashes cover, and remain the worked
example.
