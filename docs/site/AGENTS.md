# Registry Docs agent guidance

This is an Astro and Starlight documentation site. Use `npm`; the current site
is English-only (`locale: en`).

## Writing and evidence

Read [the style guide](docs/style-guide.md) before editing pages. It owns voice,
page structure, frontmatter, how a lead addresses its reader, how a page's depth
follows its sidebar position, claim levels, procedures, diagrams, and the
technical and writing reviews. Use the live sidebar in `astro.config.mjs` for
placement.

Anchor product-behavior claims in code, tests, fixtures, OpenAPI, or standards.
Mark missing evidence with a `TODO[evidence]` MDX comment and propose a weaker
claim rather than asserting unsupported behavior. Run `npm run check:evidence-anchors`
when claims or cited source paths change. The [anchor reference](docs/evidence-anchors.md)
explains syntax, resolution, and checker limits; [evidence link policy](docs/evidence-link-policy.md)
covers the contract and standards registers.

Show command output only when it was run and observed. Procedures need observable
success, failure recovery, and warnings at actions that lose data, expose secrets,
or cannot be undone. Use synthetic examples without real records, tokens, or
production hostnames. Follow the repository's `SECURITY.md` for suspected vulnerabilities.

## Generated content and assets

- Change reference data in `src/data/*.yaml`, then run `npm run generate`.
- `scripts/check-draft-links.mjs` is not a standalone check. Run
  `npm run generate` first so its draft-page links can resolve synced product
  pages and generated example assets.
- The generated CLI reference renders the committed command catalog
  `crates/registry-cli-docs/catalog.json`, which omits the workspace version.
  A command, help, default, environment, or constraint change fails the
  `registry-cli-docs` snapshot test until
  `cargo run --locked -p registry-cli-docs -- --write` regenerates the catalog;
  review that diff as the reference change. `src/data/cli-reference.yaml` holds
  only the publication `status` and `last_reviewed` date; set the date when you
  review a catalog diff, and leave it alone for a version-only bump. Setting the
  record back to `draft` hides every CLI page from the site; do that only
  deliberately.
- For `src/content/docs/products/**`, edit the owning source and metadata listed
  in `src/data/repo-docs.yaml`. The sync script generates the site copies.
- `src/content/docs/reference/cli/**`, `src/data/generated/**`, and fetched
  `openapi/*.openapi.json` are generated. Change their source or generator.
  Identify configuration and API sources through `package.json`, `astro.config.mjs`,
  and the generator before editing.
- Keep SVG illustrations in `public/images/` with `<title>`, `<desc>`, and
  `role="img"`. Follow the style guide for captions and nearby text.

## Verification

Use the checks in `package.json` that cover the change, then `npm run check` when
practical. Inspect the applicable tutorial runner before claiming execution
coverage: a dry run checks extraction or classification, not successful execution.
For publication and immutable archive behavior, follow [README.md](README.md).
