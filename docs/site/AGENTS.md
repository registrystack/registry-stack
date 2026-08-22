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

`npm run check` resolves those anchors and fails when one does not. A cited
path must exist, a cited line reference must fall inside its file, and a cited
symbol must occur in at least one path the same anchor cites. A citation that
has drifted is a merge blocker, not a wart, so check an anchor when you move
the code it points at. Run `npm run check:evidence-anchors` alone for the fast
version. A token that resolves to no repository path is read as prose and
skipped, so naming a file the repo does not own is still fine. Several files in
one directory may be cited in the compact brace form,
`crates/registry-relay-v2/src/{api,startup}.rs`, which is read as one citation
per entry, so each file it names has to exist on its own. A bare name ending in
a slash continues the directory cited before it, `deployment-projects/ then
protected-read-evidence/`, and has to exist under it. After a filename there is
no directory to continue, so `governed/` beside `package.rs` stays prose: it
names a directory the package writes, not one the repo holds.

The check reads a symbol by its shape: `snake_case`, `SCREAMING_SNAKE_CASE`,
`UpperCamelCase`, `lowerCamelCase`, a name spelled with empty parentheses such as
`router()`, and an all-capital wire value carrying a digit such as `ES256`. A
qualified name is checked segment by segment, so a typo in the type that
qualifies it is caught too. A dotted configuration or wire key path is read the
same way, segment by segment, once one of its segments carries a shape:
`evidence_data_request.transport_absences.credentials` is checked down to its
leaf, and a `*` standing for any key is skipped rather than looked up.

Anything outside those shapes is prose, which leaves two gaps worth knowing. An
all-capital wire value with no digit, `EdDSA`, is not checked, because the only
shape that reaches it also pulls in `OpenAPI`, `OpenCRVS`, and every acronym the
prose spells, which would fire on correct anchors. A key path no segment of
which carries a shape, `sources.*.authentication.kind`, is not read either: its
segments are among the commonest words in the tree, so a check on them would
pass on any file that happens to mention them. Both gaps are deliberate. Spell
such a value or key beside a symbol the check can see.

Two things the check deliberately allows. Bare `path:start-end` citations still
pass: `--strict-line-refs` rejects them, but it stays off while a backlog of
them remains, and the check prints how many are left. Prefer citing a symbol
over a line range in new writing, because a symbol survives the next edit above
it. Prescriptive guidance that tells an operator to set a value is also
untouched, since the check reasons about claims describing what code does, not
about advice.

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
