# Evidence authoring project

`evidencectl new` wrote this project. It is a working example, not a blank
page: every identifier is a placeholder chosen to be obviously synthetic, and
every file carries comments saying what a block does and what you change.

## Files

| File | What it holds |
| --- | --- |
| `evidence-project.yaml` | The project marker. Every command that takes `--project` looks for it, and every path below is read relative to it. |
| `selectors/record-reference-v1.yaml` | The selector profile: the exact caller input this question accepts, field by field, with a byte bound on each. |
| `sources/record-status.yaml` | The source: which extract is read, how old it may be, which statement runs, which caller field binds to its parameter, and the bounds the statement runs under. |
| `queries/record-status.sql` | The one fixed statement the source runs. A caller never sends SQL, and no caller value becomes statement text. |
| `adapters/record-status-extract.rhai` | Bounded extraction: it turns the statement result into the facts the question reasons over, or reports no match or ambiguity. |
| `schemas/record-status-response.schema.yaml` | The shape the statement result must have before extraction reads it. |
| `schemas/record-status-facts.schema.yaml` | The shape extraction must produce before the derivation reads it. |
| `questions/record-status.yaml` | The question: one fixed request, the subject it selects, the source it reads, the answers it may disclose, and the governance the assertion carries. |
| `derivations/record-status.rhai` | Bounded derivation: it turns the facts into the answers the question declares, and nothing else. |
| `fixtures/record-status.yaml` | The synthetic cases `evidencectl fixtures run` replays offline, against a database built from the fixture text, with no network. |
| `secrets/` | Disposable local key material. It is owner-only, unbound, and never a deployment key; `.gitignore` keeps it out of version control. |

## What the example models

One question, `record-status`, answers whether a synthetic record satisfies a
reviewed condition. The caller sends one reference and nothing else. The source
reads a published extract, runs one statement bound to that reference, and
hands extraction a single count. The derivation turns that count into one
boolean, and the disclosure list lets the assertion carry the boolean alone:
the reference, the count, and every row value stay out of it.

Replace this model with your own. The names are deliberately generic so that
nothing here reads as advice about what your question should ask.

## Next commands

```sh
evidencectl fixtures run --project . --explain
```

`fixtures run` replays the synthetic cases through the evaluator the runtime
uses. They cover true and false answers, no match, ambiguity, the row bound,
extract age, source failure, parameter binding, statement refusal, hostile
selector text, the output gate, and anti-reconstruction. `--explain` reports
the stage each case reached without printing selector or source values.

Edit the source, statement, schemas, extraction, derivation, and fixtures
together. Each one bounds the next, so a change to any of them is a change to
what the assertion may say.

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
