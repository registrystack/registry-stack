# Evidence anchors

Author-facing MDX comments tie product-behavior claims to repository sources.
Use the form `{/* Evidence: ... */}` with a repository path and the symbol,
test, constant, or key that supports the adjacent claim. Prefer symbols to line
ranges, because symbols survive edits above the cited code.

Run the checker from `docs/site`:

```sh
npm run check:evidence-anchors
```

It also runs within `npm run check`. A cited path must exist, a line reference
must fall inside its file, and a cited symbol must occur in at least one path
the same anchor cites. A drifting citation fails the check. Update anchors
when moving the source they cite.

The implementation and its cases are in
`scripts/check-evidence-anchors.mjs` and `scripts/check-evidence-anchors.test.mjs`.
The checker validates references, not whether the cited implementation proves
the prose claim. That judgment remains part of technical review.

## Paths and line references

Every anchor needs at least one resolvable repository path. Pair an upstream
standard with the file implementing the claim rather than citing only the
standard. The repository roots recognized by the parser are listed in
`REPOSITORY_ROOTS` in the checker.

Paths such as `src/`, `tests/`, and `schemas/` may continue the crate or product
cited earlier in the same anchor. A shared root such as `schemas/` resolves
against that crate or product first, then the repository root. Symlinks leading
outside the checkout are refused.

A line reference is spelled `:12` or `:12-14`. Malformed forms such as `:abc`,
`:1foo`, and `:1.5` fail; a sentence-ending full stop is punctuation. Line-only
citations remain accepted by the normal check, which reports their count. The
optional `--strict-line-refs` flag rejects them:

```sh
npm run check:evidence-anchors -- --strict-line-refs
```

Several files sharing a directory may use brace syntax, such as
`crates/registry-relay-v2/src/{api,startup}.rs`. Each expanded file must exist.

A bare filename beside a cited path is prose when it does not resolve. This
allows references to adopter-created configuration or generated package files
when the anchor also cites repository evidence. A bare `.rs` filename is the
exception: the checker treats it as repository source and requires it to resolve.

A bare name ending in `/` continues the last resolved directory:
`deployment-projects/` followed by `protected-read-evidence/` must name a child
directory. After a file, such a name remains prose: `governed/` after `package.rs`
or `output/` after `release/scripts/registry-release` can describe generated
directories instead of repository paths.

## Symbols and keys

The checker recognizes symbols by shape:

- `snake_case` and `SCREAMING_SNAKE_CASE`
- `UpperCamelCase` and `lowerCamelCase`
- Names with an initialism and multiple lower-case runs, such as `OAuthErrorCode`
- Names followed by empty parentheses, such as `router()`
- All-capital wire values containing a digit, such as `ES256`

Qualified names are checked segment by segment. The last segment is checked
regardless of shape; qualifiers are checked when their own shape identifies
them as symbols. Thus `AccessRule::Public` checks both names, while
`Command::Check` checks `Check` and leaves the one-word qualifier outside the
symbol check.

Dotted keys are checked segment by segment when at least one segment has a
recognized shape. For `evidence_data_request.transport_absences.credentials`,
the leaf is checked too. A `*` wildcard is skipped.

## Deliberate limits

The parser leaves common prose and acronyms alone to avoid treating every
sentence-initial word as a symbol. These forms need care during review:

- A one-word name such as `Visibility` is not checked on its own. Qualify it
  as `contract::Visibility` when the anchor should check it.
- Values such as `EdDSA` and `SDMXProfile` do not match the symbol shapes.
  Spell them beside a symbol the checker can resolve and review the value.
- A dotted key whose segments lack symbol shapes, such as
  `sources.*.authentication.kind`, is not checked. Pair it with a checked
  symbol and verify the key in the source.

Prescriptive operator advice is outside this check's scope. Passing the checker
does not verify an instruction's safety or execute a documented procedure.
