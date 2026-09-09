# Registry Docs

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Registry Docs is the canonical documentation website for the registry project
family.

It explains the map: which project owns which responsibility, which standards
claims are supported by evidence, which machine contracts are stable enough for
integrators, how Registry Notary federation fits into the stack, and how to run
the smallest end-to-end demo.

## Develop

```sh
npm ci
npm run dev
```

## Validate

```sh
npm run check
```

The check command validates frontmatter, generated data, Markdown structure,
prose style, OpenAPI snapshots, SVG accessibility, Astro types, the static
build, and generated Redoc API pages. It checks the current site only. Published
release archives are immutable bundles and are not rebuilt during routine docs
work.

To verify the complete deployable tree, including the three archived releases
in the publication window:

```sh
npm run check:archives
```

`src/data/archive-lock.yaml` is append-only. New entries bind one archived
docset to the SHA-256 of its deterministic bundle, canonical-root tree, and
version-prefixed tree. Historical single-tree entries remain valid.
Existing entries must never be edited or removed. `npm run
check:archive-lock -- --base-ref origin/main` enforces that invariant.
Historical archives retain their sealed search output. New release archives
carry Pagefind and machine-readable discovery files built once by the release
workflow.

Archives outside the publication window are not restored or link-checked by
routine CI. Their immutable lock metadata and release assets remain available
for explicit audit or recovery work.

To prepare a new archived docset, follow the
[canonical archive preparation procedure](../../release/OPERATIONS.md#prepare-the-documentation-archive-lock).
It builds committed inputs in a fresh Ubuntu 24.04 Linux x64 checkout with
Node 22.12.0 and the locked npm dependencies. The archive builder stages its
owned generated inputs from the docset's source ref. Historical refs supply
committed outputs; refs with `generate:source` rebuild them in a clean source
export using that ref's dependency lock. The fresh checkout also excludes
unrelated ignored `public` assets. Pagefind's platform packages can
contain different WebAssembly payloads, so normalized gzip metadata does not
establish identical archive bytes across macOS and Linux.

The rehearsal verifies the prepared lock on Ubuntu. The candidate builds and
verifies its archive from the accepted protected-main source. Publication
promotes that candidate's `registry-docs-vX.Y.Z.tar.gz` with the other signed,
SBOM-covered, SLSA-provenanced release files, without rebuilding it.
The archive metadata binds the release tag, version path, and both tree digests,
not a future merge commit. The Pages workflow authenticates that one public
asset and copies its canonical-root and version-prefixed trees unchanged to `/`
and `/v/X.Y.Z/`; protected `main` is built at `/dev/`.

## Published layout

The production site uses one indexable namespace:

- `/` serves the latest released documentation with self-canonical URLs and the public sitemap.
- `/dev/` serves unreleased documentation built from `main` with `noindex,follow`.
- `/v/<version>/` serves the newest three semantic release archives with `noindex,follow`.
- `/preview/` keeps old links working by redirecting matching pages to `/`.

The Pages workflow verifies the selected release archive against
`src/data/archive-lock.yaml` and copies the separately built trees to their
bound destinations without rewriting either one. The immutable
`/v/<version>/` trees inside the publication window and their release assets are not changed.
Older release assets remain attached to their GitHub Releases, but Registry Docs does not expand
them into the Pages artifact. Earlier Pages-only fallback bundles age out with their expanded routes.
`published_archive_limit` in `src/data/docsets.yaml` sets the window. Search data and
machine-readable corpora are sealed into the canonical-root release tree, so the canonical site does
not depend on unreleased `/dev/` content.

## Content Sources

Data-backed reference tables are generated from:

- `src/data/projects.yaml`
- `src/data/contracts.yaml`
- `src/data/standards.yaml`
- `src/data/openapi-sources.yaml`
- `products/evidence/contracts/{bundle,runtime}.schema.yaml`, read by
  `scripts/generate-evidence-configuration.mjs` for the Evidence configuration reference

Run `npm run generate` after editing these files. Relay V2 publishes no generated
configuration reference: `relayctl` compiles a project rather than exposing a schema
catalog, and each deployment generates its own OpenAPI description at
`GET /openapi.json`. The generators read committed schemas and reviewed product-owned
material only. They never read a country workspace, runtime configuration, environment
value, or secret.

## Generated references

Commit the source definitions, authored pages, and generators. The CLI pages in
`src/content/docs/reference/cli/` and JSON in `src/data/generated/` are ignored
build artifacts, like fetched OpenAPI files and synced product docs. A change to
one command can change the whole CLI catalog digest; those rendered copies no
longer enter PR diffs or Git merges.

`npm run dev`, `npm run build`, `npm test`, and `npm run check` generate their
inputs automatically. Generation requires Rust/Cargo for the public Clap catalog
and uses the workspace lockfile. To inspect just the generated references, run
`npm run generate`, then open the local files or use `npm run dev`.
`npm run check:cli-reference` compares existing local output with the current
command definitions. The collector's determinism, schema validation, and explicit
human review metadata remain checked; generation does not publish draft CLI pages.

The v3 CLI publication record separates reviewed command content from release
identity. A workspace-version-only bump needs no new editorial review: the
record keeps its original `last_reviewed`, `reviewed_source_version`, and
`reviewed_catalog_sha256`. Generated pages still identify the current source
version and full catalog digest. Any change to commands, help, defaults,
environment bindings, or constraints requires review and updated values from
`npm run cli-reference:digest`, including `reviewed_content_sha256`.
Use the actual review date, never the release date merely because it changed.

To migrate a legacy v2 record, run `npm run cli-reference:digest -- --migrate`.
It proves the current commands match the old full digest at the recorded review
version, then adds the content digest without changing the review date or source
provenance. It also works after a version-only bump. If content differs, migration
fails without editing the record; review the changed reference before updating
its review fields. Repeating migration validates v3 without rewriting it.
Historical release source trees and published archives retain their own records.

When updating an older branch, resolve authored source conflicts first. If Git
reports modify/delete conflicts under either generated directory, accept the
removal from version control and run `npm run generate` after resolving sources.
Keep product-owned generated schemas and release artifacts tracked under their
existing contracts.
