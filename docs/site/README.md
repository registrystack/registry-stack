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

`src/data/archive-lock.yaml` retains every archive entry. Each entry binds one
archived docset to the SHA-256 of its deterministic bundle, canonical-root tree,
and version-prefixed tree; historical single-tree entries remain valid.
Published and historical entries are immutable. Before publication, only the
entry for the current prepared workspace release may be refreshed, and only
when its manifest and candidate docset match and the exact tag is proven absent
from the authoritative Registry Stack origin. Tag lookup failures stop the
check. Entries may never be removed. `npm run check:archive-lock -- --base-ref
origin/main` enforces these rules.
Historical archives retain their sealed search output. New release archives
carry Pagefind and machine-readable discovery files built once by the release
workflow.

Archives outside the publication window are not restored or link-checked by
routine CI. Their immutable lock metadata and release assets remain available
for explicit audit or recovery work.

To prepare a new archived docset, follow the
[canonical archive preparation procedure](../../release/OPERATIONS.md#prepare-the-documentation-archive-lock).
It builds committed inputs in a fresh Ubuntu 24.04 Linux x64 checkout with
Node 24.11.0 and the locked npm dependencies. The archive builder stages its
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

## Optional visit tracking

Canonical released pages and the public `/dev/` tree offer optional tracking shared
with the main website.
The hidden main-origin bridge owns the version-2 consent choice and native Mautic
identity. Documentation sends minimized public page views and cannot request an
identifier. Rejection, expiry, privacy signals, or a blocked bridge keep optional
tracking off. Ordinary local builds, versioned archives, and error pages do not take
part. Aggregate Umami analytics remains limited to canonical released pages.
Tracking acceptance does not subscribe anyone to marketing email.

The website and docs copies of `src/lib/shared-tracking-client.mjs` and
`src/lib/tracking-protocol.mjs` must stay identical. Coordinate changes with the
website's bridge before publishing a new docs-bearing release. The Pages workflow
updates `/dev/` when docs source changes merge. It cannot change the sealed
canonical-root release asset. The `build:dev` command checks the built
tracking controls and 404 output, requiring shared tracking and forbidding Umami.

Run the docs tests and build checks, then the website repository's
`scripts/check-marketing-tracking.mjs` with `DOCS_TRACKING_DIST` set to the
canonical docs build directory. Set `TRACKING_BROWSERS=chromium,firefox,webkit`
for the complete browser matrix. That check intercepts network requests and
verifies the built website to docs to starter request journey. Native Mautic
acceptance is a separate isolated fixture check in the website repository.

## Content Sources

Data-backed reference tables are generated from:

- `src/data/projects.yaml`
- `src/data/contracts.yaml`
- `src/data/standards.yaml`
- `src/data/openapi-sources.yaml`
- `products/evidence/contracts/{bundle,runtime}.schema.yaml`, read by
  `scripts/generate-evidence-configuration.mjs` for the Evidence configuration reference

Run `npm run generate` after editing these files. The generators read committed schemas and reviewed product-owned
material only. They never read a country workspace, runtime configuration, environment
value, or secret.

## Generated references

Commit the source definitions, authored pages, and generators. The CLI pages in
`src/content/docs/reference/cli/` and JSON in `src/data/generated/` are ignored
build artifacts, like fetched OpenAPI files and synced product docs. A change to
one command can change the whole CLI catalog digest; those rendered copies no
longer enter PR diffs or Git merges.

`npm run dev`, `npm run build`, `npm test`, and `npm run check` generate their
inputs automatically. To inspect just the generated references, run
`npm run generate`, then open the local files or use `npm run dev`.
`npm run check:cli-reference` compares existing local output with what the
generator renders now.

The CLI pages render the committed command catalog
`crates/registry-cli-docs/catalog.json` and the workspace version from the root
`Cargo.toml`, so generation needs no Rust toolchain. The catalog omits that
version: a version-only bump changes the version and catalog SHA-256 the pages
state, not the catalog. The `registry-cli-docs` snapshot test holds the catalog
to the public Clap trees. When a command, its help, defaults, environment
bindings, or constraints change, that test fails until
`cargo run --locked -p registry-cli-docs -- --write` regenerates the catalog,
and its diff is what review reads. `src/data/cli-reference.yaml` records only
the publication `status` and the `last_reviewed` date; use the actual review
date, never the release date merely because it changed. A `draft` record keeps
the CLI pages out of the site. Historical release source trees and published
archives retain their own records and generators.

When updating an older branch, resolve authored source conflicts first. If Git
reports modify/delete conflicts under either generated directory, accept the
removal from version control and run `npm run generate` after resolving sources.
Keep product-owned generated schemas and release artifacts tracked under their
existing contracts.
