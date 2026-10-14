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
| Evidence | `evidence.yaml` | `evidence` |
| BReg | `registry.yaml`: `BRegProject` or BReg `apiVersion` | `breg` |
| Casework | `casework.yaml`: `CaseworkProject` or Casework `apiVersion` | `casework` |
| Scheduling | `scheduling.yaml`: `SchedulingProject` or Scheduling `apiVersion` | `scheduling` |
| Messaging | `messaging.yaml`: `MessagingProject` or Messaging `apiVersion` | `messaging` |
| Discovery | `origins.yaml`: `DiscoveryOrigins` or Discovery origins `apiVersion` | `discovery` |
| Manifest | `metadata.yaml` with `schema_version: registry-manifest/v1`, or an explicit project marker | `manifest` |
| Render | `manifest.yaml`: `RenderBundle` or Render `apiVersion` | `render` |
| Evidence OID4VCI | an explicit project marker | `evidence-oid4vci` |

### Evidence

`evidence.yaml` uses the normalized `EvidenceProject` v1alpha1 model. The server reads the same
project and governed target-authority documents as `evidencectl check`, including unsaved buffers,
and maps shared diagnostic codes, messages, and field positions into UTF-16 editor ranges.
Former question envelopes and inline operation sources are rejected.

| Written in | Field | Resolves to |
|---|---|---|
| `assertionDefinitions` | acquisition `source`, `search`, and `fetch` | named `sources` |
| definitions and sources | selector profile references | `selectorProfiles` |
| definitions | `derive.function` | an `assertion-derive/v1` named Function |
| sources | `prepare.function`, `extract.function` | a Function with the matching interface |
| named Functions | `source` | the contained Rhai function asset |
| definition outputs | `schema` | the contained schema asset |
| definitions | `fixtures` | the contained fixture asset |
| target authority grants | `definition`, subject `selectorProfile` | project definitions and selector profiles |
| derivation function release entries | `output` | the calling definition's declared outputs |
| generated TypeScript and Python project types | definition and output names | the same normalized declarations |

Navigation, references, completion and hover use these indexed names. Function completion offers
only the matching interface. Output names are scoped to the calling assertion definition; private
facts never become output candidates. Generated files are recognized by the shared generator's
header and per-definition markers, at any contained `.ts` or `.py` path.

File completion enumerates bounded contained siblings with the same extension. No function or
generated code is executed. Missing assets are reported at their path references. Function
signature diagnostics use the shared pure authoring check.

A value slot that holds no scalar has no semantic completion yet. Hover on a reference names its
resolved declaration and project-relative file. Symbolic links, multiply linked files, paths outside
the project, `secrets/`, and dot-prefixed tooling state are excluded.

### Current product authoring

The additional products use explicit contract-derived declarations and references over the same
syntax index. They add no dependencies on product runtimes. All support definitions, references,
symbols, completion, and hover for their modeled local authoring edges.

| Product | Indexed relationships |
|---|---|
| BReg | Authored modules, record types and extensions, value types, fields including implicit `id`, selectors, constraints, read paths, record and project access profiles, Action inputs/plans/commit guards, Proposal permissions/attachments/review context, review authorities, datasets, vocabularies, and governed function/hook/SQL files. Module assets resolve relative to the module. |
| Casework | Queues, access profiles, teams, review policies with policy-scoped stages, outcomes and inline routing fields, trusted producers, read-only context providers and runtime deployment bindings, clocks, calendars and holiday sets, task templates, current fixtures, schema files, and development directory clients. Source namespaces remain opaque external names. |
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
Other products diagnose their explicitly modeled local authoring relationships. Indexing-ceiling
diagnostics explain the editor's operational budgets and do not claim compiler validation.
Shared Evidence parser diagnostics keep their own codes, such as `config.unknown-key` and
`evidence.project.function-interface`. Missing asset diagnostics use `evidence.project.missing-*`.

## Discovery

Roots come from the workspace folders the client sends at `initialize`. Nothing is scanned below a
folder. A root deeper in the tree is found when a document inside it opens, by walking up from that
document to the nearest directory that declares a root, and every root discovered that way has to
lie inside one of the declared folders. A session that declares no folders has nothing to contain a
root to and accepts whatever the upward walk reaches; a session whose declared folders do not
resolve on this filesystem accepts nothing.

Only regular files admitted by a family's authoring layout or declared file references are indexed.
Symbolic links, files outside the project root, and unrelated documents are excluded. Evidence
uses bounded per-document and aggregate indexing budgets. The additional products use a 1 MiB editor ceiling per indexed
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
