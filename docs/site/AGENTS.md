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
version. Root CI runs it twice: once inside the docs job, and once in a job of
its own that runs on every pull request, because the anchors cite source all
over the workspace and the docs job only runs for a changed path it recognizes.
A bare filename beside a cited path is read as prose when nothing resolves, so
naming a file the repo does not own, an adopter's `origins.yaml` or a path a
generated package writes, is still fine. A bare `.rs` sibling is the exception:
only this repository writes Rust into the stack, so a Rust filename has to
resolve, and deleting the file one names fails the check. Several files in
one directory may be cited in the compact brace form,
`crates/registry-relay-v2/src/{api,startup}.rs`, which is read as one citation
per entry, so each file it names has to exist on its own. A bare name ending in
a slash continues the directory cited before it, `deployment-projects/ then
protected-read-evidence/`, and has to exist under it. After a filename there is
no directory to continue, so `governed/` beside `package.rs` stays prose: it
names a directory the package writes, not one the repo holds.

The check reads a symbol by its shape: `snake_case`, `SCREAMING_SNAKE_CASE`,
`UpperCamelCase`, `lowerCamelCase`, a name spelled with empty parentheses such as
`router()`, and an all-capital wire value carrying a digit such as `ES256`.
`UpperCamelCase` covers a name with an initialism run into it, `OAuthErrorCode`,
once that name carries two lower-case runs and one capital run of two or more. A
qualified name is read segment by segment: the last segment is read whatever its
shape, and each segment that qualifies it is read once it carries a shape of its
own. A dotted configuration or wire key path is read the same way, segment by
segment, once one of its segments carries a shape:
`evidence_data_request.transport_absences.credentials` is checked down to its
leaf, and a `*` standing for any key is skipped rather than looked up.

Anything outside those shapes is prose, which leaves three gaps worth knowing. A
one-word name is not checked, because `UpperCamelCase` asks for two capitalized
chunks: the only shape that would reach `Visibility` also reaches every
sentence-initial word an anchor writes, `Evidence`, `Relay`, and `The` among
them. Spell a one-word type or variant qualified when you want it checked,
`AccessRule::Public` or `contract::Visibility`, since the last segment of a
qualified name is read whatever its shape. A qualifier is still read by shape, so
`Command::Check` puts `Check` under the check and leaves `Command` outside it. A
name nothing separates from an acronym the prose spells is not checked either: an
all-capital wire value with no digit, `EdDSA`, and a capitalized name carrying
one lower-case run, `SDMXProfile`. The only shape that reaches either also pulls
in `OpenAPI`, `SQLite`, `OpenCRVS`, and every other acronym the prose spells,
which would fire on correct anchors. A key path no segment of which carries a
shape, `sources.*.authentication.kind`, is not read at all: its segments are
among the commonest words in the tree, so a check on them would pass on any file
that happens to mention them. All three gaps are deliberate. Spell such a value
or key beside a symbol the check can see.

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
