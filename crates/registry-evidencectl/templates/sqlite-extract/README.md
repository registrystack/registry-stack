# Evidence authoring project

`evidencectl init` created a normalized synthetic project for local development. Every identifier and value is a placeholder. Replace them with the institution's reviewed model before deployment.

## Files

| File | What it holds |
| --- | --- |
| `evidence.yaml` | The single `EvidenceProject`: stable selector profile, Function, Source, AssertionDefinition, output, and grant-ceiling IDs. |
| `queries/record-status.sql` | The fixed SQLite statement. Caller values bind as parameters and never become statement text. |
| `functions/extract-record-status.rhai` | The `source-extract/v1` Function that turns a bounded response into private facts. |
| `functions/derive-record-status.rhai` | The `assertion-derive/v1` Function that maps facts to declared outputs. |
| `fixtures/record-status.yaml` | Synthetic offline cases for `evidencectl test`. |
| `local-target.yaml` | A disposable `EvidenceTarget` with local service, OIDC, source connection, signer, limits, and generated paths. |
| `dev-authority.yaml` | Complete local AccessProfiles and grants bounded by the AssertionDefinition ceilings. |
| `.generated/secrets/` | Owner-only disposable development key material ignored by Git. |

## Next commands

```sh
evidencectl check . --target local-target.yaml
evidencectl test . --target local-target.yaml --explain
```

Review the project, Functions, query, fixtures, target, and authority together. Source acquisition produces private facts only. An AssertionDefinition grants no downstream write or review authority.

## Documentation

- Author a project from a SQLite extract: <https://docs.registrystack.org/tutorials/connect-a-sqlite-extract/>
- Build and deploy a project: <https://docs.registrystack.org/tutorials/build-and-deploy-evidence-project/>
- Every configuration key: <https://docs.registrystack.org/reference/evidence-configuration/>
- `evidencectl` commands: <https://docs.registrystack.org/reference/cli/evidencectl/>
