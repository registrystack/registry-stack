# Evidence link policy

The contract and standards data files support current documentation claims.
Their evidence links must remain reproducible without trusting a moving branch
or making network requests during verification.

## Scope

This policy applies to:

- `source_of_truth.url` in `src/data/contracts.yaml`
- every `evidence_docs[].url` in `src/data/standards.yaml`

It does not apply to `official_url`. Those links identify an external standards
body or specification and are not presented as locally verified source
evidence.

## Accepted evidence links

Repository evidence must use an absolute
`https://github.com/registrystack/registry-stack/blob/<ref>/<path>` or
`https://github.com/registrystack/registry-stack/tree/<ref>/<path>` URL. The
reference must be either a semantic-version tag or a full 40-character commit
SHA. Branch names and abbreviated SHAs are not stable evidence identifiers.

A link to a current Registry Stack documentation page must be root-relative,
such as `/explanation/dpi-safeguards-alignment/`. Do not embed the current
documentation hostname in an evidence field.

Evidence fields must not point to other hosts. An external source can be listed
as `official_url`, but a current Registry Stack claim needs locally verifiable
repository or documentation evidence.

## Enforcement

Run the checker from `docs/site`:

```sh
npm run check:evidence-links
```

The checker reads only local files and Git objects. It verifies that:

- source YAML evidence URLs match the checked-in generated JSON
- every tag or commit exists in the local repository
- every linked repository path exists at that exact tag or commit
- every root-relative documentation route exists at the selected source commit

The release workflow passes its resolved tag commit with `--source-ref`, so
current-documentation routes are verified against the same source that the
release uses. The checker has no network fallback. A shallow or incomplete
checkout must fetch the required Git history before running it.
