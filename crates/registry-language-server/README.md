# Registry Stack language server

`registry-language-server` adds Registry Stack project semantics to YAML editors through the
Language Server Protocol. It provides go to definition, find references, workspace symbols, document
symbols, and errors for missing, duplicate, or ambiguous references. It deliberately leaves syntax,
schemas, completion, hover, and formatting to the editor's YAML language server.

## Two document families

The server reads two unrelated authoring surfaces and keeps them apart. Each root belongs to exactly
one family, and a diagnostic names the family that produced it in its `source` field, so a workspace
holding both can be read without guessing which tool is talking.

| Family | A directory is a root when it holds | Diagnostic source |
|---|---|---|
| Relay | `registry-stack.yaml` | `registry-stack` |
| Evidence | `evidence-project.yaml`, or both `source.openapi.yaml` and a `questions/` directory | `evidence` |

Evidence accepts the second marker because an authoring project has always carried one OpenAPI
description and a directory of questions. A project written before the marker file existed is still
an authoring project, and requiring a migration before an editor would open it would be a demand
made of authors for the editor's convenience.

A symbolic link declares nothing at either name. A link is how a directory borrows a shape it does
not have, and a borrowed shape must not anchor a root the loader will then read files from.

### Relay

- registry, integration, entity, service, consultation, fixture, and environment definitions;
- integration and entity aliases across the project manifest, their definition files, and
  environment files;
- consultation integration references, records-service entity references, and environment
  integration and entity bindings.

### Evidence

The edges below are the names one authoring document writes and another spells back. Each one is
navigable in both directions and reported when the name has nothing behind it.

| Written in | Field | Resolves to |
|---|---|---|
| `questions/<id>.yaml` | `id` | the question itself, which has to be the file stem |
| `questions/<id>.yaml` | `source.ref` | `sources/<id>.yaml` |
| `questions/<id>.yaml` | `subject.profile`, `subjects[].profile` | `selectors/<id>.yaml` |
| `questions/<id>.yaml` | `answers[].concept` | the concept that answer defines, within this question |
| `questions/<id>.yaml` | `disclosure.allow[]` | an `answers[].concept` of the same question |
| `questions/<id>.yaml` | `answers[].schema` | a file under `schemas/` |
| `questions/<id>.yaml` | `derivation` | a file under `derivations/` |
| `questions/<id>.yaml` | `governance.fixtures` | a file under `fixtures/` |
| `sources/<id>.yaml` | `request.selectorInputs[].alternatives[].profile` | `selectors/<id>.yaml` |
| `sources/<id>.yaml` | `request.adapterParametersSchema`, `responseSchema`, `factSchema` | a file under `schemas/` |
| `access/policies/<id>.yaml` | `id` | the policy itself, which has to be the file stem |
| `access/policies/<id>.yaml` | `questions[]` | `questions/<id>.yaml` |

A concept belongs to the question that answers it, because two questions may answer the same
concept. One question's `disclosure.allow` never reaches another question's answer.

`source.operation`, `source.facts[].path`, `subject.selector`, and `source.collectionBounds` are not
indexed. They resolve against the project's OpenAPI description rather than against another
authoring document.

Beyond those edges, the server deserializes each question with the same reader the compiler uses and
runs `registry-evidence-authoring`'s own validation, placing each finding at the field it names. A
question the reader cannot parse at all is reported once, carrying the reader's message.

## Diagnostics

Every diagnostic this server publishes has severity `Error`. The channel carries what the compiler
refuses and nothing else, so an author who fixes everything the editor underlines has a project that
builds, and an author who ignores an underline is ignoring a build failure rather than an opinion.

Evidence diagnostics carry a code naming the rule, such as `evidence/unknown-source`,
`evidence/question-file-name`, `evidence/question-shape`, and the authoring library's own finding
codes under the same prefix. A client that disagrees with one rule can filter that rule rather than
the whole server.

## Discovery

Roots come from the workspace folders the client sends at `initialize`. Nothing is scanned below a
folder. A root deeper in the tree is found when a document inside it opens, by walking up from that
document to the nearest directory that declares a root, and every root discovered that way has to
lie inside one of the declared folders. A session that declares no folders has nothing to contain a
root to and accepts whatever the upward walk reaches; a session whose declared folders do not
resolve on this filesystem accepts nothing.

Only regular files in the documented project layouts are indexed. Symbolic links, files outside the
project root, unrelated YAML files, and documents past the per-role byte ceiling are ignored. This
keeps editor analysis inside the same bounded authoring surface as `registryctl` and
`evidencectl`.

## Parsing

Parsing is tolerant. A document with a syntax error still contributes every symbol and reference the
parser recovered, and reports exactly one syntax diagnostic at the point the parse broke, so an
in-progress edit in one file never blinds the rest of the project.

## Run

```console
cargo run -p registry-language-server
```

The same server is available from a release installation as:

```console
registryctl tooling language-server
```

The server communicates over standard input and output and expects the opened workspace (or a
nested directory) to be inside a Registry Stack or Evidence authoring project.
