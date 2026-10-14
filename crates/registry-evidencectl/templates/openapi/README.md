# Evidence authoring project

`evidencectl init` retained the API description byte for byte and created a normalized synthetic project beside it. The synthetic Source and AssertionDefinition are reviewable placeholders, not inferred policy.

## Files

| File | What it holds |
| --- | --- |
| `evidence.yaml` | The single `EvidenceProject` with stable IDs for selector profiles, Functions, Sources, AssertionDefinitions, and outputs. |
| `source.openapi.yaml` | The retained API description used by `evidencectl source suggest`. |
| `functions/` | Named Function assets referenced by `evidence.yaml`. |
| `fixtures/` | Synthetic offline cases for `evidencectl test`. |
| `local-target.yaml` | The disposable normalized local target. |
| `dev-authority.yaml` | Complete local AccessProfiles and grants. |
| `.generated/secrets/` | Owner-only disposable development keys ignored by Git. |

## Next commands

```sh
evidencectl source suggest source.openapi.yaml --project . --source-id <id> --operation '<METHOD /path>'
evidencectl check . --target local-target.yaml
```

`source suggest` adds one named Source and its preparation and extraction Functions to `evidence.yaml`. Review selector bindings, transport bounds, private facts, and any AssertionDefinition that acquires the Source.

## Documentation

- Author a project: <https://docs.registrystack.org/configure/evidence/>
- Build and deploy a project: <https://docs.registrystack.org/tutorials/build-and-deploy-evidence-project/>
- Every configuration key: <https://docs.registrystack.org/reference/evidence-configuration/>
- `evidencectl` commands: <https://docs.registrystack.org/reference/evidencectl/>
