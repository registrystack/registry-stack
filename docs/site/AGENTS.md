# Registry Docs Agent Guidance

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
structure, frontmatter, page types, the banned-word list, the rules for pages
that ask the reader to run something, claim levels for standards, and the GitLab
rules we adopt, adapt, or skip. The visual design language is recorded
separately in `design-registry-docs.md`, maintained alongside the repository,
not published in it; the binding visual rules for diagrams are summarized in the
style guide's "Images and diagrams" section.

Every factual claim about a source repo must be anchored in code, tests,
fixtures, OpenAPI, or an upstream standard. When evidence is missing, mark the
claim inline with a `TODO[evidence]` MDX comment and propose a weaker claim
level, rather than deleting the claim or asserting it.

A procedure carries more than its commands: the reason for a step whose reason is
not visible in the command, what an irreversible step forecloses, what failure
looks like and the next move, and a `caution` or `danger` at every action that
loses data, exposes a secret, or cannot be undone. Show command output only when
you ran the command and read what came back; otherwise describe what happens in a
sentence. Do not ask a reader to paste guards, `exit 1`, or assertions that exist
for this project's own test harness.

The docs gate runs the commands the tutorials document and deliberately does not
police prose. Wording, added reasons, and added recovery paths cannot break it, so
the writing review in the style guide is a judgement, not a word check: whether a
reader with only that page could finish the task and tell success from failure.
