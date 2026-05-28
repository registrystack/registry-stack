# Registry Legend

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Registry Legend is the canonical documentation website for the registry project
family.

It explains the map: which project owns which responsibility, which standards
claims are supported by evidence, which machine contracts are stable enough for
integrators, how Registry Witness federation fits into the stack, and how to run
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
build, and generated Redoc API pages.

## Content Sources

Data-backed reference tables are generated from:

- `src/data/projects.yaml`
- `src/data/contracts.yaml`
- `src/data/standards.yaml`
- `src/data/openapi-sources.yaml`

Run `npm run generate` after editing these files.
