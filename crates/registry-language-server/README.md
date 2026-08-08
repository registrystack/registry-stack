# Registry Stack language server

`registry-language-server` adds Registry Stack project semantics to YAML editors through the
Language Server Protocol. It provides go to definition, find references, workspace symbols, document
symbols, completion and hover on the names one document writes and another spells back, and errors
for missing, duplicate, or ambiguous references. It deliberately leaves syntax, schemas, mapping-key
completion, and formatting to the editor's YAML language server: the authoring form's JSON Schemas
already complete the keys through the project-local `yaml.schemas` mapping `evidencectl` writes, and
a second list of the same keys would be a second list to disagree with the first.

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

`source.operation`, `source.facts[].path`, `subject.selector`, and `source.collectionBounds` resolve
against the project's OpenAPI description rather than against another authoring document.

## Completion and hover

Both answer from the index the navigation above answers from, so there is no second model of which
field takes which kind. Completion on a value offers every name that reference could have held: the
kind is the reference's own, and a scoped name such as `disclosure.allow[]` offers only the names of
its own scope. A candidate replaces the whole value already written. `source.facts[].path` is the
one field whose candidates are not names another document declares: those are the selectable leaves
of the operation's `200 application/json` response, taken from the set the compiler selects against,
and they are offered whether or not the path written there resolves yet.

An author who invokes completion by hand gets the same list as one who typed a trigger character.
The context is read from the document rather than from the request, because whether a client sends a
trigger at all inside a YAML value depends on client settings this server has no say in.

Hover on a reference names what it resolves to and the project-relative file it is defined in; hover
on a declaration names the declaration. A reference that resolves to nothing describes nothing: the
diagnostic that owns the mistake is already speaking for that field.

A value slot that holds nothing yet holds no scalar for the index to find a reference in, so a list
requested at a bare `key: ` is empty. The server marks every list incomplete, so the client asks
again on the next keystroke and the list appears as soon as one character is there to place it on.

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
project root, unrelated YAML files, and documents past the per-role byte ceiling are ignored, and
those ceilings are the authoring form's own rather than the editor's, so a document `evidencectl`
refuses for its size is one the editor refuses for the same size. How many documents a directory
contributes is bounded only where the authoring form bounds it: an Evidence root stops at the 128
documents the form allows in `questions/` and in `access/policies/`, while `sources/` and
`selectors/`, the other two directories it reads documents from, are read whole at up to 1 MiB a
document, and a Relay root bounds no directory at all and holds every document to 1 MiB. One root
therefore holds roughly the bytes of the directories it reads, and a session holds that for up to 32
roots, so a project with a very large `selectors/` directory can exhaust the server's memory as its
root is indexed. That is the price of the rule behind it: a ceiling only the editor applies would
draw an unresolved reference over a project that builds. Open files are not part of the growth. Each
document is read and closed as the scan reaches it, so a session keeps the same handful of
descriptors open whatever the size of the project.

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
