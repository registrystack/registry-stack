# Evidence authoring starter

`evidencectl init <destination> --starter <starter-dir> --profile local` copied bounded starter assets from `functions/`, `queries/`, `fixtures/`, and `codelists/`. It also created the one normalized project and a disposable local target. Starter input cannot add a second authored grammar.

## Files

| File | What it holds |
| --- | --- |
| `evidence.yaml` | The single normalized `EvidenceProject`. |
| `functions/` | Named preparation, extraction, and derivation Functions. |
| `queries/` | Fixed statements used by Sources when needed. |
| `fixtures/` | Synthetic offline cases. |
| `codelists/` | Bounded static lookup data when supplied. |
| `local-target.yaml` | The disposable normalized local target. |
| `dev-authority.yaml` | Complete local AccessProfiles and grants. |
| `.generated/secrets/` | Owner-only disposable development keys ignored by Git. |

## Next commands

```sh
evidencectl check . --target local-target.yaml
evidencectl test . --target local-target.yaml --explain
```

Review the copied assets and every reference in `evidence.yaml` before adding live credentials or creating a deployment package.
