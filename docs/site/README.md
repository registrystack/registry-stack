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

`src/data/archive-lock.yaml` is append-only. New entries bind one archived
docset to the SHA-256 of its deterministic bundle, canonical-root tree, and
version-prefixed tree. Historical single-tree entries remain valid.
Existing entries must never be edited or removed. `npm run
check:archive-lock -- --base-ref origin/main` enforces that invariant.
Historical archives retain their sealed search output. New release archives
carry Pagefind and machine-readable discovery files built once by the release
workflow.

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
The archive metadata binds the release tag, version path, and both tree digests,
not a future merge commit. The Pages workflow authenticates that one public
asset and copies its canonical-root and version-prefixed trees unchanged to `/`
and `/v/X.Y.Z/`; protected `main` is built at `/dev/`.

## Published layout

The production site uses one indexable namespace:

- `/` serves the latest released documentation with self-canonical URLs and the public sitemap.
- `/dev/` serves unreleased documentation built from `main` with `noindex,follow`.
- `/v/<version>/` serves immutable release archives with `noindex,follow`.
- `/preview/` keeps old links working by redirecting matching pages to `/`.

The Pages workflow verifies the selected release archive against
`src/data/archive-lock.yaml` and copies the separately built trees to their
bound destinations without rewriting either one. The immutable
`/v/<version>/` tree and its release asset are not changed. Search data and
machine-readable corpora are sealed into the canonical-root release tree, so
the canonical site does not depend on unreleased `/dev/` content.

## Content Sources

Data-backed reference tables are generated from:

- `src/data/projects.yaml`
- `src/data/contracts.yaml`
- `src/data/standards.yaml`
- `src/data/openapi-sources.yaml`
- `registryctl authoring reference` for the five project-authoring schemas and the generated Relay
  and Notary runtime schemas
- `registryctl authoring reference --coverage` for reviewed field-intent coverage

Run `npm run generate` after editing these files.
Generation refuses to publish the authoring reference when any reachable schema path lacks reviewed
intent or when the reference and coverage contracts disagree. The generator reads committed schemas,
typed field knowledge, and reviewed product-owned intent sidecars. It never reads a country workspace,
runtime configuration, environment value, or secret.
