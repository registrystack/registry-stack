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
npm install
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

To verify the complete deployable tree, including every locked release archive:

```sh
npm run check:archives
```

`src/data/archive-lock.yaml` is append-only. Each entry binds one archived
docset to the SHA-256 of its deterministic bundle and extracted site tree.
Existing entries must never be edited or removed. `npm run
check:archive-lock -- --base-ref origin/main` enforces that invariant.
Archived builds omit Pagefind because its generated index differs by host
platform; current documentation keeps search enabled.

To publish a new archived docset, build only that docset and create its bundle:

```sh
DOCS_DOCSET=vX.Y.Z npm run build:archive
npm run archive:snapshot -- vX.Y.Z --write-lock
npm run generate
npm run check:archive-lock -- --base-ref origin/main
```

The release workflow repeats those steps from the exact annotated tag and
publishes `registry-docs-vX.Y.Z.tar.gz` with the other signed, SBOM-covered,
SLSA-provenanced release files.

## Content Sources

Data-backed reference tables are generated from:

- `src/data/projects.yaml`
- `src/data/contracts.yaml`
- `src/data/standards.yaml`
- `src/data/openapi-sources.yaml`

Run `npm run generate` after editing these files.
