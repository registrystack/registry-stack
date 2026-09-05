# Evidence authoring project

`evidencectl new` wrote this project around the API description it retained. It
is a starting point rather than an example: the directories below are empty on
purpose, because only the operation you select can decide what they hold.

## Files

| File | What it holds |
| --- | --- |
| `evidence-project.yaml` | The project marker. Every command that takes `--project` looks for it, and every path below is read relative to it. |
| `source.openapi.yaml` | The API description, retained exactly as it was read. Question authoring reads it; nothing rewrites it. |
| `selectors/` | Selector profiles: the exact caller input a question accepts, field by field, with a byte bound on each. |
| `sources/` | Sources: which operation is called, which caller field binds to it, and the bounds the call runs under. |
| `adapters/` | Bounded extraction: it turns a source response into the facts a question reasons over. |
| `schemas/` | The shapes a source response and an extraction must have before the next stage reads them. |
| `questions/` | Questions: one fixed request each, with the answers it may disclose and the governance the assertion carries. |
| `derivations/` | Bounded derivation: it turns facts into the answers a question declares, and nothing else. |
| `fixtures/` | The synthetic cases `evidencectl fixtures run` replays offline, with no network. |
| `secrets/` | Disposable local key material. It is owner-only, unbound, and never a deployment key; `.gitignore` keeps it out of version control. |

## Next commands

```sh
evidencectl source suggest --project . --source-id <id> --operation '<METHOD /path>'
```

`source suggest` drafts one editable source from the retained description for
the operation you name. It selects that operation and nothing else, and it
writes a draft you review rather than a source you deploy.

A question, its schemas, its extraction, its derivation, and its fixtures are
written after the source. Each one bounds the next, so a change to any of them
is a change to what the assertion may say. `evidencectl fixtures run` replays
them offline once they exist.

`evidencectl build` compiles this project and one deployment target into a
candidate, and `evidencectl doctor` reads that candidate. Neither reads an
editable project, so both come after the fixtures pass.

## Documentation

- Author a project: <https://docs.registrystack.org/configure/evidence/>
- Build and deploy a project:
  <https://docs.registrystack.org/tutorials/build-and-deploy-evidence-project/>
- Every configuration key:
  <https://docs.registrystack.org/reference/evidence-configuration/>
- `evidencectl` commands: run `evidencectl --help`, or read
  <https://docs.registrystack.org/reference/evidencectl/>
