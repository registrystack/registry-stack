# Evidence source recipes

This catalog distributes reviewed source integration assets through the existing
`source-export.json` contract. Each recipe imports as an ordinary Source,
selector profile, and pair of bounded Functions. It supplies no assertion
meaning, caller grant, connection origin, credential, installer, or provider
service.

| Recipe | Sanitized contract represented | Compatibility basis |
| --- | --- | --- |
| [DHIS2 Tracker](dhis2-tracker/README.md) | Tracker 2.43 tracked-entity collection, page 1 with two-record ambiguity detection | The pinned fields, filters, pager, and attribute shape exercised by the repository's sanitized reference adapter |
| [OpenCRVS event search](opencrvs-event-search/README.md) | OpenCRVS v2 `/events/search` result shape used by the pinned reference implementation | The pinned request body, EventIndex result, and configured parent-reference fields exercised by the repository's sanitized reference adapter |

These are reusable starting points, not claims that every release or deployment
of either provider is compatible. Review the recipe README, replace its fixed
technical identifiers when your deployment differs, run the synthetic fixture
project, and perform a separate read-only compatibility check against the exact
provider deployment before relying on it.

Import and maintain a recipe with the normal local lifecycle:

```sh
evidencectl source import ./dhis2-tracker --project ./evidence
evidencectl source diff ./dhis2-tracker-next --project ./evidence
evidencectl source update ./dhis2-tracker-next --project ./evidence
evidencectl source detach dhis2-tracker ./evidence
```

The manifest inventories every portable asset by exact SHA-256 checksum. A
checksum mismatch is refused before authored files change. The sibling
`fixture-validation/` project is deliberately outside the export: it contributes
synthetic assertion semantics, target bindings, grants, and evaluator fixtures
only for local validation.

Run both validation projects with matching installed `evidencectl` and
`evidence` binaries. The harness creates and removes only its own temporary
project, performs no provider request, and resolves no configured credential:

```sh
bash ./run-fixtures.sh
```

Set `EVIDENCECTL_BIN` or `EVIDENCE_BIN` to absolute paths when the matching
binaries are not selected from the same installation or `PATH`.

The catalog and its downloadable contents are licensed under the Apache
License 2.0 in [`LICENSE`](LICENSE).
