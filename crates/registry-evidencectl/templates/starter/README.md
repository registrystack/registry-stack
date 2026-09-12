# Evidence authoring starter

`evidencectl init <destination> --starter <starter-dir> --profile local` copied reviewed starter files into this editable Evidence project. It did not import an OpenAPI document, source export, live credential, runtime file, target, production extract, or deployment bundle.

The copied files are ordinary authoring files. Edit them the same way as any other Evidence project, and keep each question, source, schema, derivation, and fixture consistent as you change the starter.

## Files

| File | What it holds |
| --- | --- |
| `evidence-project.yaml` | The project marker every authoring command reads. |
| `selectors/` | Caller selector profiles, when the starter provides them. |
| `sources/` | Source boundaries, request bounds, projections, and extraction files. |
| `queries/` | Fixed statements for starter sources that use them. |
| `schemas/` | Closed response and fact shapes. |
| `adapters/` | Bounded extraction code. |
| `questions/` | Requests, subject bindings, answer declarations, disclosure, and governance. |
| `derivations/` | Bounded answer derivation code. |
| `fixtures/` | Synthetic offline cases that prove the project before live credentials. |
| `targets/` | Optional reviewed target settings supplied by the starter. |
| `secrets/` | Disposable local key material. It is owner-only, unbound, and ignored by Git. |

## Next command

```sh
evidencectl check .
evidencectl test . --explain
```

Run fixtures before adding live credentials or building a deployment candidate. If the starter includes target settings, create the target with `evidencectl target new <target-dir> --settings <file> --signing-public-key <public-jwk>`, then run fixtures again with `--target <target-dir>`.
