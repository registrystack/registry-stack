# Registry Legend Agent Guidance

This repo is an Astro and Starlight documentation site.

- Use `npm` for JavaScript commands.
- Keep v0 English-only. Add French only after the English site is approved.
- Keep reference tables data-driven. Update `src/data/*.yaml`, then run
  `npm run generate`.
- Do not hand-maintain generated files under `src/data/generated/`.
- Keep OpenAPI reference content in `openapi/*.openapi.json`; Redoc output is
  generated into `public/api/`.
- Keep SVG illustrations in `public/images/` and include `<title>` and `<desc>`.
- Before completion, run the narrowest relevant check and then `npm run check`
  when practical.

## Writing

Read `docs/style-guide.md` before drafting or editing any page. It covers voice,
structure, frontmatter, page types, the banned-word list, claim levels for
standards, and the GitLab rules we adopt, adapt, or skip. The visual design
language is recorded separately in `../design-registry-legend.md`.

Every factual claim about a source repo must be anchored in code, tests,
fixtures, OpenAPI, or an upstream standard. When evidence is missing, mark the
claim inline with a `TODO[evidence]` MDX comment and propose a weaker claim
level, rather than deleting the claim or asserting it.
