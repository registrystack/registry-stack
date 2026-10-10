# Registry Stack language server

`registry-language-server` adds Registry Stack project semantics to YAML and JSON editors through the
Language Server Protocol. It provides go to definition, find references, workspace symbols, document
symbols, completion and hover on the names one document writes and another spells back, and errors
for missing, duplicate, or ambiguous references. It deliberately leaves syntax, schemas, mapping-key
completion, and formatting to the editor's existing language servers. The
[shared editor setup](../../editors/README.md#configure-a-project) configures
version-matched schemas wherever the product publishes them.

## Document families

The server reads product authoring surfaces and keeps their indexes apart. Each root belongs to exactly
one family, and a diagnostic names the family that produced it in its `source` field, so a workspace
holding several products can be read without guessing which tool is talking.

| Family | A directory is a root when it holds | Diagnostic source |
|---|---|---|
| Evidence | `evidence-project.yaml`, or both `source.openapi.yaml` and a `questions/` directory | `evidence` |
| BReg | `registry.yaml`: `BRegProject` or BReg `apiVersion` | `breg` |
| Casework | `casework.yaml`: `CaseworkProject` or Casework `apiVersion` | `casework` |
| Scheduling | `scheduling.yaml`: `SchedulingProject` or Scheduling `apiVersion` | `scheduling` |
| Messaging | `messaging.yaml`: `MessagingProject` or Messaging `apiVersion` | `messaging` |
| Discovery | `origins.yaml`: `DiscoveryOrigins` or Discovery origins `apiVersion` | `discovery` |
| Manifest | `metadata.yaml` with `schema_version: registry-manifest/v1`, or an explicit project marker | `manifest` |
| Render | `manifest.yaml`: `RenderBundle` or Render `apiVersion` | `render` |
| Evidence OID4VCI | an explicit project marker | `evidence-oid4vci` |

Evidence accepts the second marker because an authoring project has always carried one OpenAPI
description and a directory of questions. A project written before the marker file existed is still
an authoring project, and requiring a migration before an editor would open it would be a demand
made of authors for the editor's convenience.

A symbolic link declares nothing at either name. A link is how a directory borrows a shape it does
not have, and a borrowed shape must not anchor a root the loader will then read files from.

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

### Current product authoring

The additional products use explicit contract-derived declarations and references over the same
syntax index. They add no dependencies on product runtimes. All support definitions, references,
symbols, completion, and hover for their modeled local authoring edges.

| Product | Indexed relationships |
|---|---|
| BReg | Authored modules, entities and extensions, fields including implicit `id`, selectors, constraints, read paths, entity and project access profiles, action inputs/effects, vocabularies, Manifest projection names, and governed script/WASM/SQL files. Module assets resolve relative to the module. |
| Casework | Queues, access profiles, review kinds/stages/outcomes/producers, clocks/calendars, source bindings and imported request fields, task templates, runtime source names, and development directory clients. |
| Scheduling | Services/offerings/openings/holiday sets, local location/pool/window records, exception reopening targets scoped to location, and fixture offering names. |
| Messaging | Providers, sender profiles, template identities and version-specific metadata files, access profiles, runtime providers, locale and part names and their Jinja body files, provider scripts, and fixed template schema/sample file symbols. |
| Discovery | Origin, mapping, requirement, and evidence-type-list declarations. External evidence type identifiers are not treated as local references. |
| Manifest | Catalog, dataset, service, distribution, codelist, entity and field names; dataset/service/distribution relationships, entity-scoped identifiers, requirements and evidence lists, and Registry Evidence evaluation profiles. |
| Render | Document identifiers, governed entry/schema files, and locale label files. |
| Evidence OID4VCI | Native configuration section symbols. `tokenClient.privateKeyRef` is a secret reference, not a file path, so it offers no navigation; key contents are never read or indexed. |

For arbitrary Manifest and OID4VCI configuration filenames, create
`.registry-stack-editor/project.json` containing `{"product":"manifest","document":"config/metadata.yaml"}`
or the product `evidence-oid4vci`. The document must be an existing regular `.yaml` or `.yml` file
inside the project, using a relative path without traversal or symbolic links. The shared
`python3 editors/configure.py` command writes this marker and configures both editors.

Name scopes follow the owning document contract. An entity field does not complete fields from a
different entity, and Manifest fields also retain their dataset scope. References to separately
deployed records or remote identifiers do not produce invented missing-local-name errors. Product
validation remains the owning CLI's responsibility; these new indexes report syntax and modeled
local reference errors, rather than claiming full compiler validation. Rhai, Jinja, Typst, SQL, and
private-key contents remain with their native tooling.

For ordinary asset paths, completion can repair a missing filename using contained sibling files
with the same extension. It checks at most 1,024 directory entries and reads no candidate contents.
Private-key references do not enumerate neighboring keys. BReg modules are indexed from the authored
module directory, including modules awaiting a lock entry; `bregctl check` owns lock validation.

## Diagnostics

Most diagnostics this server publishes have severity `Error`. A warning the shared configuration reader raises on an accepted document is published with severity `Warning`. Evidence semantic diagnostics carry what its authoring reader or compiler refuses.
Evidence source and selector documents (`sources/<id>.yaml`, `selectors/<id>.yaml`) get navigation but no editor diagnostics; `evidencectl check` is what checks them.
The additional products diagnose their explicitly modeled local authoring relationships. The separately named indexing-ceiling diagnostics explain when the editor cannot
safely build an index and do not claim that the compiler applies the same operational budget.

Evidence diagnostics carry a code naming the rule. A marker, question, or access policy the shared
configuration reader refuses carries the reader's own code and sentence, such as
`config.unknown-key` or `yaml.unexpected-end`, at the line and column `evidencectl check` reports.
The authoring library's findings carry codes under `evidence.<area>.`, such as
`evidence.question.answer-concept-identifier`, and the editor's cross-document rules carry codes such
as `evidence.project.unknown-source` and `evidence.question.file-name`. A client that disagrees with
one rule can filter that rule rather than the whole server.

## Discovery

Roots come from the workspace folders the client sends at `initialize`. Nothing is scanned below a
folder. A root deeper in the tree is found when a document inside it opens, by walking up from that
document to the nearest directory that declares a root, and every root discovered that way has to
lie inside one of the declared folders. A session that declares no folders has nothing to contain a
root to and accepts whatever the upward walk reaches; a session whose declared folders do not
resolve on this filesystem accepts nothing.

Only regular files admitted by a family's authoring layout or declared file references are indexed.
Symbolic links, files outside the project root, and unrelated documents are excluded. Evidence
retains its authoring form's per-role byte ceilings and 128-document limits for `questions/` and
`access/policies/`. The additional products use a 1 MiB editor ceiling per indexed
document. Every root also applies an editor-only aggregate budget of 1,024 indexed documents or 16
MiB across the YAML and JSON documents it parses. A project past either aggregate limit gets one
project-ceiling diagnostic and no partial index, so the editor does not invent unresolved-reference
errors for documents it deliberately left out. Evidence names that rule
`evidence.project.ceiling`. Reduce the
project and save or close a document to retry the complete index. Each document is read and closed
as the scan reaches it, so a session keeps the same handful of descriptors open whatever the size
of the project.

## Parsing

Parsing is tolerant. A document with a syntax error still contributes every symbol and reference the
parser recovered, and reports exactly one syntax diagnostic at the point the parse broke, so an
in-progress edit in one file never blinds the rest of the project. When the shared configuration
reader has already reported that document's syntax, the editor reports the reader's sentence in place
of its own, so the editor and `evidencectl check` name the same break.

## Run

```console
cargo run --locked -p registry-language-server
```

The same server is also hosted by these adopter CLIs from the same source version:

```console
evidencectl tooling language-server
```

The server communicates over standard input and output and expects the opened workspace (or a
nested directory) to be inside a Registry Stack or Evidence authoring project.
