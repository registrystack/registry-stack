# Registry Docs writing style guide

**Status:** current
**Last reviewed:** 2026-08-19
**Applies to:** every page under `src/content/docs/` and every contributor or agent that writes them.

This guide tells you how to write for Registry Docs. It is short on purpose. When in doubt, prefer clarity over cleverness, evidence over assertion, and the reader's task over the writer's voice. Borrowed from GitLab's documentation style guide, then trimmed and adapted to a 20-page institutional docs site.

If a rule here conflicts with `design-registry-docs.md`, follow the design doc for anything visual (typography, color, components) and this guide for anything textual (voice, structure, evidence).

## Principles

1. **Documentation is the source of truth** for user-visible behavior. If the docs and the code disagree, one of them is wrong, and the docs page must say which.
2. **Evidence before claim.** Every factual statement points to code, fixtures, tests, OpenAPI, or an upstream standard. If you cannot point, mark the claim with a TODO and demote it to a weaker claim level. Pointing binds the writer; it does not oblige the reader to read the pointer. How much of the pointer belongs in the reader's sentence is settled in "Code, commands, paths".
3. **Reader first.** State the page's goal in the first paragraph. Put the next action at the end. Everything in between earns its place.
4. **Scannable beats narrative.** Short sections, descriptive headings, parallel lists, generated tables. A user landing from search should orient in 10 seconds.
5. **Concise.** A clear sentence beats a clear paragraph. A clear paragraph beats a clear section. Concision cuts words, not the reason for a step, the consequence of a step, or the recovery from a step.
6. **Scanning is for finding. Procedures are for doing.** Principle 4 governs reference pages, landings, and anything a reader reaches from search. A reader part-way through a procedure with a terminal open is not scanning: that reader needs why the step exists, what it forecloses, and what to do when it fails, even when those cost a sentence each. Trimming a procedure until it scans well is how a page stops working.

## Voice and tone

- Use second person (`you`) for actions the reader takes, and keep using it to the end. A procedure that addresses the reader in the prerequisites and then goes impersonal for nine steps has stopped talking to anyone.
- Use the project name (`Registry Relay`, not `we`) for system behavior.
- Use active voice. Exception: when the actor is unimportant or obvious from context.
- Institutional, calm, technical. More operating manual than marketing copy, and an operating manual is written to the operator.
- Do not manage the reader's emotions. No "don't worry", "easy", "no problem". Calm is not distance: that a step is destructive, that a mistake here cannot be undone, or that a command runs for ten minutes is information the reader needs, and withholding it is not restraint.
- Say what a thing does before what it does not. A negation closes a door the reader would otherwise walk through, so use one where a door is open. A run of sentences that all open with a negation tells the reader everything except what to do.
- Do not promise future features. If a capability is unbuilt, link to the issue or say `not yet supported`.

## Page structure

- H1 is the page topic, not the brand name. Title is set in frontmatter; do not write `#` H1 in MDX.
- One lead paragraph directly under H1. No second lead.
- The lead names who the page is for wherever the page has a narrower reader than someone using this product: an adopter deploying it, an operator on call, a contributor changing it. A tutorial that opens without naming its reader is usually written for whoever wrote it. Reference and specification pages are exempt, because their reader is whoever holds the contract.
- Increment heading levels by one. Do not skip from H2 to H4.
- Max depth is H4. If a page wants H5, split the page.
- Sentence case for all headings. `Architecture overview`, not `Architecture Overview`.
- One topic per page. If the page has two unrelated sections, it is two pages.
- End a long page with a short `Next` list of 3 to 5 links.

## Frontmatter

Every page declares:

```yaml
---
title:
description:
status: draft | current | historical | deprecated
owner:
source_repos:
last_reviewed:
doc_type: tutorial | how-to | explanation | reference | decision
locale: en
standards_referenced:
---
```

- `description` is one sentence, used by search snippets and `llms.txt`.
- `source_repos` lists the repos whose state this page documents. If it lists none, the page is meta.
- `last_reviewed` is the date a human last checked the page against source. Bump it on real review, not on formatting changes.
- `standards_referenced` lists the standards this page mentions by ID, matching `src/data/standards.yaml`.

## Page-type patterns

Each page belongs to exactly one `doc_type`. The pattern is enforced by the type.

**Tutorial.** Goal, prerequisites, estimated time, ordered steps, how the reader knows each step worked, what to do when it did not, cleanup, next page. The reader can finish the tutorial in one sitting. "How the reader knows it worked" is a statement about observable state, not a mandatory transcript block: a line the command prints, a file that now exists, a status code, a key the reader can list. Show a transcript only under the rules in "Code, commands, paths".

**How-to.** When to use it, prerequisites, ordered steps, verification, troubleshooting. Scoped to one task. Verification, output, and recovery follow the same rules as a tutorial.

**Explanation.** Context, model, boundaries, tradeoffs, related docs. No steps. No commands. The reader leaves with a mental model, not a finished artifact.

**Reference.** Contract status (`current` / `historical`), source of truth, generated-or-manual marker, version or commit, examples only where they clarify the contract. Do not write narrative.

**Decision.** Date, status, decision, context, consequences, `superseded-by` if applicable. One decision per page.

## Word list

Banned. Rewrite if you find these in a draft.

| Avoid                     | Why                                                  | Use instead                                          |
| ------------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| `simply`, `just`, `easy`  | Hides complexity; condescending if reader struggles  | Delete, or describe the actual step                  |
| `obviously`, `clearly`    | Same                                                 | Delete                                               |
| `should` (as a promise)   | Ambiguous between obligation and prediction          | `must`, `will`, or `is expected to` with context     |
| `e.g.`, `i.e.`            | Hard to translate; reads as filler                   | `for example`, `that is`                             |
| `etc.`                    | Hides what is left out                               | Name the items or write `among others`               |
| `since` (causal)          | Reads as time, not cause                             | `because`                                            |
| `above`, `below`          | Breaks when page reflows or on screen readers        | Link to the section by name                          |
| `here` (as link text)     | Loses meaning out of context                         | Use the linked page's title                          |
| `please`                  | Marketing tone, not docs tone                        | Delete                                               |
| em dashes                 | Project preference                                   | Commas, colons, semicolons, parentheses, periods     |
| typographer's quotes      | Breaks copy-paste                                    | Straight quotes                                      |
| `we`, `our`               | Hides the actor                                      | The project name, or `you`                           |
| ambiguous `it`            | Confuses non-native readers                          | Repeat the noun                                      |

Preferred terms.

| Domain                | Preferred                                            |
| --------------------- | ---------------------------------------------------- |
| Product family        | `registry stack` (lowercase) for the concept; `Registry Docs` for the site and repo |
| Formal product names  | `Registry Platform`, `Registry Manifest`, `Registry Relay`, and `Evidence Gateway` (Title Case); `Registry Mint` is a supporting service, not one of the four |
| Retired product       | `Registry Notary` keeps its Title Case name, but only where the page says in the same block that it is retired |
| External adopter demo | `Solmara Lab` (Title Case); not a formal Registry Stack product |
| Repo slugs            | `registry-platform`, `registry-manifest`, `registry-relay`, `registry-evidence`, and `registry-mint`; `solmara-lab` for the external adopter demo (monospace) |
| Legacy identifiers    | `registry-evidence-gateway-pdp/v1` is a Relay PDP profile identifier. It does not name or connect to the Evidence Gateway product. |
| Legacy repo paths     | `registry_relay` and `decentralized-evidence-demo` appear only in historical pages or `rename_status` fields. Never in prose on a `current` page without explicit rename context. |
| Standards             | Use the official acronym after spelling on first use. `DCAT`, `SHACL`, `OGC API Records`, `SD-JWT VC`, `CCCEV`. Never translate. |

## Lists

- Ordered list for steps that must run in sequence. Unordered list for items with no order.
- All items start with a capital letter.
- Parallel structure for a list of like things: options, fields, products, sources. All items are noun phrases, or all are imperative verbs. Do not mix.
- Steps in a procedure are not a list of like things. Write them as sentences and let them differ in shape. Forcing every step into one frame is how a page ends up repeating an opener nobody chose.
- No period if every item is a fragment. Period on every item if any item is a complete sentence. The fragment preference does not apply to procedure steps.
- Use the Oxford comma in prose: `Manifest, Relay, and Evidence Gateway`.
- Do not use bold inside list items for keywords. Reserve bold for UI labels.

## Code, commands, paths

- Inline backticks for: file paths, env vars, route paths, schema versions, media types, command flags, identifiers, short literal values, repo slugs, HTTP status codes.
- Fenced code blocks for multi-line commands, configuration, request/response payloads, and example output. Always declare a language: ` ```sh `, ` ```yaml `, ` ```json `, ` ```http `, ` ```text `.
- One blank line above and below a fenced block.
- Use `<placeholder>` for values the reader replaces, in code blocks too: `curl https://<host>/evidence/...`.
- Do not paste real secrets, tokens, or production hostnames. Use `example.com` and the fake-token convention.
- For keyboard shortcuts, use backticks: `Ctrl+C`. Inline HTML, including `<kbd>`, fails the markdownlint gate (MD033).
- Show output only if you ran the command and read what came back. An unobserved transcript is a claim without evidence, and Principle 2 applies to it exactly as it applies to prose. If you cannot run the command, write a sentence for what happens instead: "the command prints the key ID and exits 0".
- Never invent a banner, a log line, a progress message, or a version string. If nobody has seen the software print it, it is not output.
- When real output is long, quote the lines the reader checks against and say plainly that the rest is omitted. When it varies per reader, replace the varying parts with `<placeholder>` and name what varies: timestamps, identifiers, host names, absolute paths.
- Repo paths such as `crates/registry-evidence/` and `products/evidence/` address a contributor with the repository checked out. An adopter has a terminal and a released binary. Keep repo paths out of reader-facing prose in tutorials, how-tos, and start pages: put them in an author-facing MDX comment, in a page whose reader is a contributor, or in a pinned link so a reader without a clone can still open the file.
- Paths the reader creates, edits, or passes on their own machine are not repo paths. Write those in full and say where they come from.

## Procedures

This applies to `tutorial` and `how-to` pages, and to any page that asks the reader to run something.

- Give the reason for a step wherever the reason is not visible in the command itself. One clause carries it, and `because` is on the preferred side of the word list for this purpose. A reader who knows why a step exists can adapt it and recover from it. A reader who does not can only start over.
- A step that cannot be undone, or that forecloses an option the reader may want later, states what it forecloses in the same block as the command, not in a later section. Name the consequence in the reader's terms: "a key created with these settings can never leave this cluster, so losing the cluster loses the signing identity".
- Say what failure looks like wherever failure is plausible: what the reader sees, and the next move. A procedure that documents only the success path is half written, and the half it omits is the half the reader reads under pressure.
- Do not make the reader paste the project's own scaffolding. Guards, `exit 1`, assertions, and one-command-per-fence ceremony exist so a harness can extract and run a page; the reader is typing into their own shell, where `exit 1` closes it. Give the command the reader would type, and let the harness hold the scaffolding.
- Never quote scaffolding back as output. A guard's own `printf` is not what the software printed.

## Links

- Internal links: relative paths to the `.mdx` file. `[architecture overview](../explanation/architecture/)`.
- External links: full URL.
- Link text describes the target page. Do not write `click [here](...)` or `see [this page](...)`.
- Do not capitalize the target page's title inside link text unless it is a proper noun.
- A link earns its place when the reader would otherwise have to search for the target. A paragraph so dense with links that it cannot be read aloud is a list that has not admitted it yet.
- Link to upstream standards bodies first, then to mirrors or summaries.
- Pin links to code to a release tag (`v0.8.3`) or a commit SHA, never a branch, when the claim depends on the code state.

## Tables

- Use tables for matrix data: two or more dimensions per row. For one-dimensional data, use a list.
- Sentence case for headers. No empty cells; write `None` or `n/a`.
- Tables in `reference/` and `map/` are generated from `src/data/*.yaml`. Do not hand-edit those tables in MDX.
- For a generated table, include an author-facing note naming the source data file and the generation command: `<!-- generated from src/data/standards.yaml. Run npm run generate. -->`
- A hand-written table fits in fewer than 10 rows and fewer than 5 columns. Larger tables move to data files.

## Admonitions

- Allowed: `note`, `tip`, `caution`, `danger`.
- Scarcity applies to `note` and `tip`. A page with three of those usually has structural problems: that context belongs in the prose.
- `caution` and `danger` are required, not rationed. Use one wherever an action loses data, exposes a secret, or cannot be undone, as many times as the page does those things. On a page about key custody or production cutover, carrying none is under-marking, not discipline.
- `note` is for context the reader can skip without harm. `caution` is for an action the reader can recover from with effort. `danger` is for one the reader cannot recover from at all.
- Never stack two admonitions in a row. Where two consecutive steps each need a warning, attach each warning to its own step rather than merging them into one paragraph that covers neither precisely.
- Do not put an admonition immediately under H1. The lead paragraph carries the framing.

## Images and diagrams

- SVG only for conceptual diagrams. PNG only if the image is a real screenshot of a real artifact.
- Every image has `alt` text or a visible caption that conveys the essential information. A reader who cannot see the image gets the same facts from the surrounding HTML.
- Important labels in a diagram also appear in nearby HTML. Machine contracts must not live only inside an image.
- Diagrams follow the design doc: Blue France plus greys, Public Sans labels, flat lines, no decoration.
- Filename: lowercase, descriptive, no spaces. `registry-family-map.svg`, not `family map.svg`.

## Acronyms

- Spell out on first use per page: `OGC API Records (the Open Geospatial Consortium API specification for records)`.
- Common project acronyms can be referenced in the glossary instead of re-explained per page.
- Avoid acronyms in page titles unless the acronym is more recognizable than the expansion.

## Markdown specifics

- Source line length ~100 characters. Do not split URLs.
- New sentence, new line, for long paragraphs. Makes diffs reviewable.
- Blank line between every block-level element.
- Use fenced code blocks with language identifiers. `plaintext` if no better choice.
- HTML inside MDX is allowed only when MDX has no equivalent. Document why with an `<!-- -->` comment.
- MDX comments (`{/* ... */}`) for author-facing notes. Do not hide content in comments; delete it instead.
- Do not use blockquotes for prose. Use a sub-section or a `note` admonition.

## Status and review

- A page's `status` is an editorial state: `current` is the default, `historical` is visibly marked, `deprecated` is linked from the index of replacements only. `status: draft` does not hide a page by itself.
- Starlight's `draft: true` frontmatter key is what removes a page from the built site, and it applies to every docset including archives. Treat it as load-bearing: removing it is a publish decision, not a frontmatter cleanup (verified 2026-07-07, when removing it from one page broke four archived docsets' link check).
- Bump `last_reviewed` only when a human reads the page against source and confirms the claims.
- A `current` page with `last_reviewed` more than 180 days old appears in the stale-pages report.

## Evidence and claim levels

This applies to every page that touches a standard or a contract.

- Use the claim levels from the plan: `implements`, `emits`, `maps_to`, `aligns_with`, `inspired_by`, `compares_against`.
- A claim is only as strong as its evidence. If the evidence is a README sentence, the claim is `aligns_with`. If the evidence is a test or a fixture, the claim is `emits` or `implements`.
- Do not invent claims. Do not propagate claims from this site to another. The data files are downstream of the source repos.
- When you cannot find evidence for an existing claim, mark it inline with a TODO and propose a demotion:

  ```mdx
  Registry Evidence implements Example Credential Profile.
  {/* TODO[evidence]: no conformance fixture found in crates/registry-evidence/.
       Suggest demoting to `aligns_with` until a fixture lands. */}
  ```

  Also flag the corresponding row in `src/data/standards.yaml` with `evidence_gap: true`.

## What we explicitly do not do

- No emojis anywhere on the site.
- No marketing copy. No "powerful", "seamless", "robust".
- No animated GIFs or videos in v0.
- No screenshots as the only source of instructions.
- No real user data, real production hostnames, or real tokens, even in `example` blocks.
- No relative links into source repos. Use full URLs pinned to a release tag or commit SHA.
- No nested admonitions. No admonition immediately under H1.
- No anchor links into other pages; link to the page and use the sidebar's on-this-page index.
- No `should` as a promise. Either it does or it does not.

## Rules from GitLab we adopt verbatim

- Sentence case for headings.
- Active voice as default.
- "You" for the reader, project name for system behavior.
- New sentence, new line.
- Spell out acronyms on first use.
- Banned word list (see above).
- No emojis in the rendered output.
- Generated content names its source and its regeneration command.

## Rules from GitLab we adapt

- **Version macros.** GitLab supports `**Tier:** Free, Premium, Ultimate` annotations on every feature mention. Registry Docs has no commercial tiers. Use a simple `status:` field in frontmatter and explicit `since v0.4` in body text when a feature is version-gated.
- **Issue links.** GitLab writes `[issue 12345](url)`. We write `[GH#123](url)` for GitHub and link to the actual issue title in text.
- **Screenshot rules.** GitLab requires PNG, 1000×500, ≤100 KB, with red `#EE2604` callout arrows. We use SVG for diagrams and use screenshots rarely.
- **Tabs and collapsible panels.** GitLab uses Hugo shortcodes. We do not use tabs in v0. If a page needs tabs, it is probably two pages.
- **Admonition scarcity.** GitLab keeps admonitions rare across all four types. Registry Docs keeps `note` and `tip` rare and requires `caution` or `danger` at every action that loses data, exposes a secret, or cannot be undone. Consecutive admonitions stay disallowed. See the Admonitions section.

## Rules from GitLab we skip

- Product availability matrices (Free / Premium / Ultimate badges).
- `disclaimer` admonitions for unreleased features. We link to issues instead.
- `flag` admonitions for feature flags. We have no public feature flags in v0.
- Deep release-process governance. Reviews and freshness gates are listed in `AGENTS.md`.
- The GitLab-specific Vale dictionary. We maintain a project vocabulary in
  `styles/config/vocabularies/RegistryDocs/` and focused local rules in `.vale.ini`.

## Tooling

- **markdownlint** validates Markdown structure. Config at `.markdownlint-cli2.yaml`.
- **Vale** validates prose against the banned-word list, project vocabulary, and a few
  stylistic rules. Config at `.vale.ini`; vocabulary at
  `styles/config/vocabularies/RegistryDocs/`. Spelling is staged through that vocabulary,
  but remains disabled until frontmatter and technical terms are fully covered. Vale
  suggestions and warnings run in CI so style drift is visible before v0 ships.
- **Link check** runs in CI.
- **Tutorial gates** run the commands a tutorial documents, in a clean container, and fail when a documented command stops working. They prove the procedure, not the prose: they do not parse sentences, count sections, or require a page to keep a particular wording. Rewording a step, adding its reason, or adding a recovery path cannot break them, so edit wording freely and let the gate check the commands.
- **Astro build** and **Redocly lint** must pass.
- **Standards register validation** asserts that every `current` standards entry has an `official_url`, a `claim_level`, a `used_by` list, and at least one `evidence_docs` link.

## Review

Two reviews per change:

1. **Technical correctness review.** Does the page agree with the source repo at the cited commit? Are claim levels defensible? Are generated tables in sync with their data files?
2. **Writing review.** Read the page as the reader it was written for, with nothing else open, then answer:
   1. Could that reader finish the task with only what this page gives them, and tell success from failure when they get there? If they would have to guess at either, the page is not finished.
   2. Does every step whose reason is not obvious give its reason, and does every step that forecloses something say what it forecloses?
   3. Is every transcript on the page one that somebody ran and read?
   4. Does the page read as written to a person, or assembled against a checklist? Second person through the whole procedure, cause where there is cause, a plain sentence where a fragment would hide the point.
   5. Do the mechanics hold: clear lead, descriptive headings, banned words gone, scannable where scanning is what the reader is doing?

A page is `current` only after both reviews pass and `last_reviewed` is bumped.
