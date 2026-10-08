# Registry Stack configuration conventions

These rules apply to every configuration format Registry Stack defines: the
files adopters author, the runtime files operators deploy, and the files our
tools generate for a person or another tool to read. A person who has learned
one product's files should be able to predict how every other product's files
look, how they are read, and how a mistake is reported.

The rules are normative. **MUST** rules are enforced by the gate the
[Enforcement summary](#enforcement-summary) gives them. A mechanical gate fails
CI when a change breaks its rule; where the gate is review, the reviewer cites
the rule ID. **SHOULD** rules are reviewed by people; a deviation needs a
reason in the pull request. A rule whose reason is not evident states it, so
a reviewer can tell a real exception from a habit.

Product guides decide what a format means. These conventions decide how it is
written and read. When a product guide and this page disagree on spelling,
parsing, or diagnostics, this page wins; fix the guide.

## Scope

In scope:

- **Authored files** describe what a registry, service, or package is:
  `registry.yaml`, `module.yaml`, `casework.yaml`, `scheduling.yaml`,
  `messaging.yaml`, Render bundles, Discovery origins and mappings, Evidence
  bundles and authoring files, fixtures, journeys, and the files beside them.
  They are reviewed in version control, are deterministic, and never hold an
  environment value or a secret. A value that differs per environment (an
  issuer, an endpoint) is named in the authored file by a local identifier and
  bound in an operator file.
- **Operator files** describe where and how a deployment runs: every
  `runtime.yaml`, development client files, and operator request files.
- **Generated files** are of two kinds. A **read-back format** is one a
  Registry Stack tool reads again (module locks, package manifests, receipts,
  checkpoints, development state); it follows every rule except CFG-SCHEMA-2
  and CFG-SCHEMA-6, which cover the files people edit. An **output format**
  is written for people or for tools we do not own and is never read back
  (explain output, `--format json` reports); it is registered with
  `reader: none`, follows CFG-ENV, CFG-NAME, CFG-ID, CFG-QTY, and CFG-EMPTY,
  and is exempt from CFG-YAML-1, CFG-CHECK-1, CFG-SCHEMA-2, and CFG-SCHEMA-6.
  A **build artifact** is a read-back format that its own product's build
  writes and reads again and that no one edits (the compiled package model in
  BReg's `package.json`). It is registered with `audience: generated` and
  `buildArtifact: true`; the registry entry is held to the code like any
  other, and no rule of this convention applies to the format.
- Authored and operator **JSON** documents (scenarios, migration descriptors,
  backup bindings) follow every rule that is not YAML-specific, including the
  envelope. A JSON document that is a request or response body of a product
  API (`examples/inputs/*.json`, operator request files) is a payload: the API
  contract governs it, not these conventions. Authored JSON is parsed strictly
  (CFG-YAML-2) and never required to be canonical bytes; a tool that digests it
  canonicalizes it first.

Out of scope, recorded as exception classes in
[Exceptions](#exceptions):

- formats another project owns (OpenAPI, JSON Schema, LinkML, ThunderID
  resources, `SHA256SUMS`, GitHub workflows, release tooling);
- exchange data models whose member names a published specification fixes
  (Registry Manifest metadata documents) and record data (JSONL imports);
- HTTP problem codes, which belong to each product's API contract.

Also out of scope:

- repository tooling metadata read only by repository scripts
  (`config-formats.yaml`, the exceptions register, release manifests), which
  those scripts' tests govern.

## Concepts

| Term | Meaning |
|---|---|
| Format | One document shape with one `apiVersion` and `kind`, owned by one product. |
| Envelope | The `apiVersion` and `kind` pair every document carries. |
| Local identifier | A name an author chooses in our files for something our files define (an entity, a profile, a template, a destination). |
| External identifier | A name defined elsewhere that our files quote (an OIDC client id, a claim name, a scope, a URN). |
| Reference | A member whose value names an item defined elsewhere in the same file or another file. |
| Sentinel | A reserved string written in place of a list or value to state an open choice explicitly, such as `unrestricted`. |
| Diagnostic | One reported problem: severity, code, location, message, and the fix. |
| Stability | `promised`: covered by API stability; `experimental`: shipped, may change in a minor release with a `BREAKING:` note; `unpromised`: no promise (fixtures, journeys, development clients, ctl data files, authoring files). |
| Format registry | `products/platform/config-formats.yaml`, the machine-readable list of every format, its schema, its reader, and its check command. |
| Exceptions register | `products/platform/config-conventions-exceptions.yaml`, every recorded deviation with its class and resolution. |

## 1. Files and envelopes

**CFG-ENV-1 (MUST). Every document carries `apiVersion` and `kind`.** Both
are plain strings at the top level, in any position, and the reader checks
them before it decodes any other member. Neither may come from `${...}`
substitution. A document missing either is refused at its root node, with
the empty path (`config.missing-envelope`); a document of another format, or
at a version the reader does not read, is refused with a message that names
the expected `apiVersion` and `kind`. When both are wrong, only `kind` is
reported (`config.wrong-kind`).
*Why:* a reader can refuse the wrong file with a precise message ("this is a
`CaseworkFixture`, `casework check` reads a `CaseworkProject`"), editors can
pick a schema, and a format can be versioned on its own.
*Enforced by:* the shared reader's envelope check; the format registry lint
(each schema file describes one `apiVersion` and declares both members as
`const`; a format read at several versions has one schema per version,
CFG-SCHEMA-3).

**CFG-ENV-2 (MUST). `apiVersion` is
`id.registrystack.org/formats/<product>/<format>/<version>`.** `<product>` is
the product token (CFG-ENV-3). `kind` matches
`^(BReg|Casework|Scheduling|Messaging|Discovery|Render|Evidence|Manifest|Platform)([A-Z][a-z0-9]+)+$`,
with acronyms written as words (`Mcp`, `Oid4vci`). `<format>` derives from
`kind`: remove the product prefix; remove a trailing `Config`; split the rest
before each uppercase letter; lowercase each word and join with `-`. The
result is non-empty and unique within the product. `<version>` matches
`^v[1-9][0-9]*((alpha|beta)[1-9][0-9]*)?$`.

| `kind` | `apiVersion` (before its version) |
|---|---|
| `CaseworkProject` | `id.registrystack.org/formats/casework/project/` |
| `BRegProject` | `id.registrystack.org/formats/breg/project/` |
| `BRegRuntimeConfig` | `id.registrystack.org/formats/breg/runtime/` |
| `BRegDataImportCheckpoint` | `id.registrystack.org/formats/breg/data-import-checkpoint/` |
| `CaseworkFixture` | `id.registrystack.org/formats/casework/fixture/` |

The `apiVersion` is a name, not a URL: readers compare it literally and never
fetch it. The identifier catalog may document it at the same path under
`https://`.
*Why:* `id.registrystack.org` is the one namespace for every identifier the
stack mints, and its catalog already promises that an identifier is never
reused for another meaning and stays documented after it is retired, which is
what a format version needs. The product and format segments are the ones the
schema `$id` uses (CFG-SCHEMA-3), so one derivation names both.

**CFG-ENV-3 (MUST). `kind` is PascalCase, starts with the owning product's
prefix, and is unique across the stack.**

| Prefix | Product token |
|---|---|
| `BReg` | `breg` |
| `Casework` | `casework` |
| `Scheduling` | `scheduling` |
| `Messaging` | `messaging` |
| `Discovery` | `discovery` |
| `Render` | `render` |
| `Evidence` | `evidence` |
| `Manifest` | `manifest` |
| `Platform` | `platform` |

Supporting services take their parent product's prefix and add their own name
to the format (`BRegMcpRuntimeConfig` is `breg/mcp-runtime`,
`EvidenceOid4vciRuntimeConfig` is `evidence/oid4vci-runtime`).
*Why:* a kind names the file without its path; `Fixture` alone would be
ambiguous in a repository that holds three products.
*Enforced by:* the format registry lint (pattern and uniqueness).

**CFG-ENV-4 (MUST). One document per file, one format per document.** A
leading `---` and a final `...` are accepted. A second YAML document (`---`
after content) is refused. A file that is empty or holds only comments is
refused as `config.missing-envelope`, naming the expected members.
*Enforced by:* the shared reader (`yaml.multiple-documents`).

**CFG-ENV-5 (SHOULD). Tools write `.yaml` files named after the format**
(`registry.yaml`, `runtime.yaml`, `module.yaml`), and write `apiVersion` and
`kind` as the first two keys. Readers accept whatever path they are given; the
envelope, not the extension, identifies the format.

**CFG-ENV-6 (MUST). A product's top-level authored file, the one its project
check starts from (CFG-CHECK-2), is `<Prefix>Project`,** format `project`
(`BRegProject`, `CaseworkProject`, `SchedulingProject`, `MessagingProject`).
It names the project in a top-level `project` block holding the shared
`ProjectIdentity` members, `id` (a local identifier) and `version` (text); the
block may add project-wide members of the product's own. A product whose
top-level authored file is a bundle of files rather than a project (Render,
Evidence) names it `<Prefix>Bundle`, format `bundle`.
*Why:* a person who has written one product's project file knows how the next
one opens, and "package" stays the name of the built artifact.
*Enforced by:* the format registry lint (a `project` format's kind ends in
`Project`, and its `project` block carries the `ProjectIdentity` members).

## 2. The YAML subset

Registry Stack reads YAML 1.2 with one parser, the shared reader in
`registry-platform-yaml`, and accepts a strict subset. Every refusal below
reports the file, line, and column.

**CFG-YAML-1 (MUST). One reader.** Every format in the registry is read
through `registry-platform-yaml` (runtime files through
`RuntimeConfigLoader`, which builds on it). No crate deserializes YAML with
`serde_norway` or any other YAML crate directly; serialization (writing YAML)
is unaffected. JSON documents are read by the same reader, as YAML 1.2 flow
content, so their refusals carry the same codes. The language server may parse
incomplete buffers with its own parser for editor features, but reports
diagnostics from the shared reader.
*Why:* the audit that produced these rules found five parse pipelines whose
behavior depended on the target type: duplicate keys refused in one product
and silently last-wins in another, `id: null` read as the text `"null"`, line
numbers in some errors and none in others.
*Enforced by:* `disallowed-methods` in every `clippy.toml` in the repository
(each repeats the list, since clippy does not merge them), with the proof
script; the conformance corpus.

**CFG-YAML-2 (MUST). Duplicate keys are refused in every mapping,** naming
both lines (`yaml.duplicate-key`).
*Why:* last-wins lets a reviewer approve the first value while the second one
runs.

**CFG-YAML-3 (MUST). Anchors, aliases, and merge keys are refused**
(`yaml.anchor`, `yaml.alias`, `yaml.merge-key`). Merge keys are named as such,
not reported as an unknown `<<` member. The fix says to write the value in full
where it is used. A lone `*` is an alias, not a wildcard; the `yaml.alias`
message says so and the fix says to quote it. A top-level key starting `x-` is
refused as an unknown key with "extension fields are not supported; use a
comment".
*Why:* every value in a reviewed file should be readable where it is used, a
file's meaning should not depend on an expansion the reviewer did not see,
and alias expansion is unbounded work. Repetition belongs in the format (a
named profile, a module), not in YAML syntax.

**CFG-YAML-4 (MUST). Explicit tags are refused** (`!!str`, `!custom`;
`yaml.tag`). Quote a value to make it text.

**CFG-YAML-5 (MUST). Mapping keys are strings.** A plain key that would
resolve to a number, boolean, or null (`1:`, `true:`, `~:`) is refused
(`yaml.non-string-key`); quote it.

**CFG-YAML-6 (MUST). Input is bounded.** A document larger than 1 MiB is
refused before parsing (`yaml.too-large`), naming the bound, and a document
of exactly 1 MiB is accepted; the bound is the same for every format, YAML or
JSON; a product may lower it for a format, never raise it, and declares the
lower bound in the format's registry entry. A document
nested deeper than 128 levels of mappings and lists is refused
(`yaml.too-deep`), naming the bound. Input is UTF-8; a leading byte-order mark
is accepted and ignored; LF and CRLF line endings are both accepted.
*Why:* hand-written configuration never approaches the bound, and one bound
for every format is one fact to remember.

**CFG-YAML-7 (MUST). Comments are allowed everywhere and never carry
meaning.**

**CFG-YAML-8 (MUST). Syntax refusals use a closed list of `yaml.` codes,**
each with line, column, and a fix:

| Code | Refused | Fix |
|---|---|---|
| `yaml.tab-indentation` | a tab character in indentation | Indent with spaces. |
| `yaml.unclosed-quote` | a quoted value with no closing quote | Close the quote. |
| `yaml.invalid-escape` | an escape YAML does not define in a double-quoted value (`"C:\Users"`) | Use single quotes, or double the backslash. |
| `yaml.text-after-quote` | text after the closing quote of a quoted value (`'it's'`, `"x" y`) | Put the whole value inside the quotes. |
| `yaml.colon-in-plain-value` | `: ` inside an unquoted value (`because: Overdue: move it`) | Quote the value. |
| `yaml.unexpected-end` | input that ends inside a list or mapping | Complete or remove the unfinished item. |
| `yaml.syntax` | any other syntax error | Check the indentation and punctuation at this position. |

The other `yaml.` codes are the refusals of CFG-ENV-4, CFG-YAML-2 to 6, and
CFG-VAL-1: `yaml.multiple-documents`, `yaml.duplicate-key`, `yaml.anchor`,
`yaml.alias`, `yaml.merge-key`, `yaml.tag`, `yaml.non-string-key`,
`yaml.too-large`, `yaml.too-deep`, `yaml.ambiguous-number`, and
`yaml.control-character`. A `yaml.` code is added to this rule in the same
change that first reports it.
*Why:* the mistakes of a first hour are syntax mistakes, and a parser's own
text names them in terms an operator cannot act on.

## 3. Scalars and types

**CFG-VAL-1 (MUST). Plain scalars resolve by one table,** the YAML 1.2 core
schema narrowed to forms that read unambiguously:

| Plain scalar | Resolves to |
|---|---|
| `null`, `Null`, `NULL`, `~`, or nothing | null |
| `true`, `True`, `TRUE`, `false`, `False`, `FALSE` | boolean |
| `[-+]?(0\|[1-9][0-9]*)` (`0`, `7`, `-12`, `+5`; `-0` and `+0` read as `0`) | integer |
| `[-+]?(0\|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?` with a fraction, an exponent, or both (`1.5`, `-0.25`, `1e3`, `2.5E-3`) | number |
| a YAML 1.2 core int or float the rows above do not accept: a leading zero (`0123`, `01.5`), a bare point (`.5`, `5.`), a base prefix with or without sign in any case (`0x1F`, `0o17`, `0b101`), every sign and case of `.inf` and `.nan` | refused in every position (`yaml.ambiguous-number`): write a decimal number, or quote it as text |
| anything else, including `yes`, `no`, `on`, `off`, `1_000`, `1:30`, `09:00` | string |

An integer position accepts only an integer; a number (`1e3`, `5.0`) is
refused with `config.expected-integer`, never converted. A number position
accepts both. A value outside the member's bounds, or a number no binary64
value can hold, is refused with `config.out-of-range`, naming the bounds.

Quoted and block scalars (`'...'`, `"..."`, `|`, `>`) are always strings.
A string holds no control character (C0, DEL, or C1, NEL included) other
than tab, line feed, and carriage return, whether written raw or as an escape
(`"\0"`, `"\a"`, `"\x01"`, `"\x7f"`, `"\N"`); such a value is refused with
`yaml.control-character`.

**CFG-VAL-2 (MUST). A member typed as text accepts only a string.** A plain
scalar that resolves to null, a boolean, or a number in a text position is
refused with "quote the value to make it text" (`config.expected-string`).
`id: true`, `version: 1.0`, and `code: 123` are mistakes, not the strings
`"true"`, `"1.0"`, and `"123"`. `code: 0123` is refused in every position
(CFG-VAL-1).
*Why:* silent coercion turned `route: null` into the route `"null"`, and the
same file meant different things to different products.

**CFG-VAL-3 (MUST). Numbers and booleans are never written as strings.** A
quoted `"8080"` in an integer position is refused; there is no string-to-number
coercion.

**CFG-VAL-4 (MUST). Exact decimals are strings.** A value whose exactness
matters (a decimal bound, a money amount, a coordinate edge) is a quoted
string matching `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`. Its schema says so in
`description` and `pattern`.
*Why:* a YAML number is a binary float; `0.1` is not exactly one tenth.

**CFG-VAL-5 (MUST). Times and dates use one form each.** A timestamp is an
RFC 3339 string with an offset (`2026-10-08T09:00:00Z`); a date is
`YYYY-MM-DD`; a time of day is 24-hour `HH:MM`; a time zone is an IANA name
(`Africa/Dakar`).

**CFG-VAL-6 (MUST). Digests are `sha256:` followed by 64 lowercase hex
digits,** in a member named `digest` or ending in `Digest`.

**CFG-VAL-7 (MUST). URLs are absolute.** Whether a position accepts `http`
is the owning product's decision, stated in the schema's `description`, and
the schema and the reader apply the same rule through one shared URL type.
A member holding a URL is named `url`, `uri`, or `issuer`, or ends in `Url`,
`Origin`, or `Issuer`. An identifier that is URI-shaped (an Evidence URN, a
`conceptUri`) is not a URL and keeps its own type.

**CFG-VAL-8 (MUST). Relative paths resolve against the directory of the file
that contains them,** and use `/`. In an authored file a path is normalized
lexically; one that leaves the project directory is refused, and so is one
whose target, after following links, lies outside it.
*Why:* a file's meaning must not depend on the directory a command was run
from.
*Enforced by:* product CLI tests; the conformance corpus, in authored formats
(the file at the registry's `relativePath` role moved outside the project and
reached through `../` segments, then through a link left in its place).

**CFG-VAL-9 (MUST). A value whose type another declaration states is checked
against that declaration.** A predicate operand compared with a declared
field, or a fixture value checked against a display schema, is checked by the
format's check command; a mismatch is an error naming the declared type, never
a runtime non-match.
*Why:* an operand of the wrong type never matches, and the item silently takes
the default path.
*Enforced by:* product CLI tests (for a partial-unique predicate,
`crates/registry-breg/tests/compiler_contract.rs`,
`partial_unique_rejects_invalid_literals_and_json_predicate_fields`); the
conformance corpus (text planted at the registry's `operand` role).

**CFG-VAL-10 (SHOULD). Each path member's schema states whether it accepts a
relative path.** Operator files accept relative paths unless the product gives
its reason in that description.

## 4. Names

**CFG-NAME-1 (MUST). Keys are camelCase ASCII**
(`^[a-z][a-z0-9]*([A-Z][a-z0-9]+)*$`). Acronyms are words: `jwksUri`,
`oidcIssuer`, `tlsTermination`, never `JWKSURI` or `jwksURI`. A mapping whose
keys are local identifiers (an id-keyed map) follows CFG-ID-1 instead. A
mapping whose keys are external identifiers follows CFG-ID-2; its schema
declares `propertyNames`, and the lint skips it.
*Enforced by:* the schema convention lint.

**CFG-NAME-2 (MUST). Every value a machine matches and Registry Stack names
is lowercase kebab-case** (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`): enum values,
sentinels, each segment of an `apiVersion` path, and each segment of a
diagnostic code. A value that names a member of a Registry Stack document or
wire contract is spelled as the member is (`anchor: stageEnteredAt`), and its
schema marks the enum with `x-registry-member-names: true`. A value
the product's API also returns has one spelling in both: renaming a
configuration value renames the API value and regenerates the OpenAPI document
in the same change. A value that names a command is written as the command
is typed (`source add`).
Protocol constants are written exactly as their specification writes them
(`ES256`, `EdDSA`, `at+jwt`, `private_key_jwt`, `GET`, `application/json`,
`fr-SN`); each is recorded in the exceptions register under
`protocol-constant`.
*Why:* the audit found snake, kebab, camel, and single-word values mixed
inside single enums; kebab is the majority across products and the form our
identifiers and codes already use.
*Enforced by:* the schema convention lint (every `enum` and `const` string).

**CFG-NAME-3 (MUST). Bounds are spelled `maximum<Thing>` and
`minimum<Thing>`,** never `max`, `min`, or `<thing>Limit`
(`maximumRequestBytes`, `minimumReplicas`). This includes keys of our own
grammars that borrow another specification's keyword (`minLength` is
`minimumLength`).
*Enforced by:* the schema convention lint (keys starting `max`/`min` followed
by an uppercase letter, and keys ending `Limit`).

**CFG-NAME-4 (MUST). A quantity's unit is the last word of its key** and is
spelled out: `Milliseconds`, `Seconds`, `Minutes`, `Hours`, `Days`,
`WorkingDays`, `Bytes`, `Degrees`. A count has no unit word. A unit not listed
here is added to the list in the same change that first uses it. See CFG-QTY.

**CFG-NAME-5 (MUST). A concept shared by several products has one name.**

| Concept | Key | Refused spellings (lint) |
|---|---|---|
| Time allowed to handle one inbound request | `requestTimeoutMilliseconds` under `listener` | `requestTimeoutSeconds` |
| Time allowed for one outbound call or delivery attempt | `attemptTimeoutMilliseconds` | `timeoutMilliseconds`, `attemptTimeoutSeconds`, `requestTimeoutMilliseconds` outside `listener` |
| Delay before a retry | `retryDelaySeconds` | `retrySeconds` |
| Most attempts for one call or delivery | `maximumAttempts` | `maxAttempts` |
| Time allowed to drain on shutdown | `shutdownGraceMilliseconds` | `shutdownTimeoutSeconds` |
| Longest accepted token lifetime | `maximumTokenLifetimeSeconds` | `maxTokenLifetimeSeconds` |
| How long records of a kind are kept | `retentionDays`, or `<thing>RetentionDays` where one block keeps several kinds | `retainDays`, `retention.<thing>Days` |
| Cache entry lifetime | `cacheTtlSeconds` | |
| Largest accepted body or file | `maximum<Thing>Bytes` | `max<Thing>Bytes`, `maxSize` |

Adding a shared concept adds a row here in the same change.
*Enforced by:* the schema convention lint (one unit per key stem across all
schemas; no key in the refused column).

**CFG-NAME-6 (SHOULD). Booleans are named so `true` turns the behavior on**
(`enabled`), never `disableX` or `noX`.

**CFG-NAME-7 (MUST). A setting that weakens a safe default takes a named
value that states what the operator accepts,** not a boolean:
`tlsTermination: operator-controlled-upstream`, not `insecure: true`.
*Why:* the value reads as an acknowledgement in review and greps as one.

**CFG-NAME-8 (SHOULD). A member holding a relative path ends in `File`,
`Directory`, or `Path`** (`descriptionFile`, not `description`).
*Why:* a path under a prose name gets written as prose.

## 5. Identifiers and references

**CFG-ID-1 (MUST). Local identifiers match `^[a-z][a-z0-9_-]{0,63}$`** in
every product and every position. A product may refuse identifiers that
collide after it derives a name from them (`date-of-birth` and
`date_of_birth` both becoming one column), and says so in the diagnostic.
*Why:* the audit found nine identifier grammars, so the same id was valid in
one file and refused in the next.
*Enforced by:* the shared `LocalId` type in `registry-platform-yaml` (schema
name `LocalId`); the convention lint checks definition sites: every member
named `id` references `$defs/LocalId`, and every id-keyed mapping declares
`propertyNames` referencing `$defs/LocalId` or `$defs/ExternalId`, or carries
the foreign marker (CFG-EMBED-2). A reference position is held by CFG-ID-4:
the check command resolves it to a definition, so a reference cannot use a
grammar its target lacks.

**CFG-ID-2 (MUST). External identifiers are not reshaped.** A client id, a
claim name, a scope, or a URN is accepted as its issuer writes it: a
non-empty string with a stated maximum length, compared exactly.

**CFG-ID-3 (MUST). A reference is the target's identifier as a plain
string,** under a key named for the target's kind (`entity: person`,
`template: welcome`). A reference to an item inside another item is a mapping
of plain identifiers (`{entity: person, field: birth-date}`). References are
never dotted strings, never API names, and never paths into another file's
structure.
*Why:* one reference shape is one thing to learn, and a checker can resolve
every reference the same way.

**CFG-ID-4 (MUST). Every reference is resolved by the format's check
command,** including references to other files of the same product. A
dangling reference is an error at check time, not at activation.
*Enforced by:* product CLI tests; the conformance corpus (an identifier
nothing defines, written at the registry's `reference` role).

**CFG-ID-5 (MUST). Named items are a list of mappings, each with an `id`
member, when their order carries meaning, and an id-keyed mapping when it
does not.** Either way identifiers are unique and a duplicate is refused.
*Enforced by:* product CLI tests; the conformance corpus (the first item of
the list at the registry's `idList` role copied after its last item, refused
with `config.duplicate-id` at the copy's `id`).

**CFG-ID-6 (MUST). A list that is a set refuses duplicates**
(`config.duplicate-item`) instead of collapsing them, and its schema declares
`uniqueItems: true`. Reader types use the shared `UniqueList<T>` from
`registry-platform-yaml`; serde's derived `BTreeSet`, `HashSet`, and
`IndexSet` keep one copy silently and are not reader types. The same family
provides the id-unique list that CFG-ID-5 requires.
*Enforced by:* the source lint (no set type in the reader-type closure); the
convention lint (a list of values or identifiers declares `uniqueItems`); the
conformance corpus (the first item of the set at the registry's `set` role
copied after its last item, refused with `config.duplicate-item`).

**CFG-ID-7 (MUST). A union names its variant in one of two shapes.**
Internally tagged: a `type` member, whose values follow CFG-NAME-2, beside the
variant's members. Externally tagged: a mapping with exactly one key, the
variant's name (a key, so camelCase), whose value holds the variant
(`after: {workingDays: 5}`). Every variant, including one with no members,
refuses unknown keys, and a refusal of the variant names the accepted
variants. Untagged unions follow CFG-SCHEMA-8. The shared command report
envelope (`ok: true` with `result`, `ok: false` with `error`) is tagged by
`ok` and needs no `type` member.

**CFG-ID-8 (SHOULD). A check warns when two identifiers in one namespace
differ only by `-` versus `_`.**
*Why:* both are valid and distinct, and a reader takes them for one.

## 6. Quantities

**CFG-QTY-1 (MUST). A duration is an integer with its unit in the key**
(`attemptTimeoutMilliseconds: 5000`, `retentionDays: 30`). ISO 8601 duration
strings and unit-suffixed strings (`PT5S`, `5s`) are not used.
*Why:* integers can be range-checked by a schema, read without a parser,
diffed exactly, and they are already the form of almost every duration in the
stack.

**CFG-QTY-2 (MUST). One stem, one unit.** A key stem (`requestTimeout`) uses
the same unit in every format. Choose the coarsest unit that expresses every
legitimate value as an integer. Legitimate values are those an operator would
deliberately configure, not every value a previous grammar accepted; the
migration note names the values no longer writable.

**CFG-QTY-3 (MUST). Sizes are integer bytes** (`maximumRequestBytes:
1048576`).

**CFG-QTY-4 (MUST). Every integer member has a stated minimum and maximum**
in its schema, and the reader enforces the same bounds through the shared
bounded integer types in `registry-platform-yaml` (`BoundedU32<MIN, MAX>`,
`BoundedU64<MIN, MAX>`). They emit both bounds into the schema and refuse a
value outside them with `config.out-of-range`, naming the bounds. An implicit
`minimum: 0` for an unsigned type does not state a bound.
*Enforced by:* the convention lint (every `integer` property declares
`minimum` and `maximum`); the conformance corpus boundary sweep (each integer
in each format's example whose registered schema states both bounds, set one
past its maximum and then one below its minimum; a format with no registered
schema is not swept).

## 7. Empty, null, and omitted values

**CFG-EMPTY-1 (MUST). `null` is never a value.** `null`, `~`, or an empty
value after a key is refused in every member with "give a value, or remove the
key if the member is optional" (`config.null-value`). Absence has one spelling:
omit the key. An optional block whose presence turns a feature on is written
`{}` when it has no members; `null` or `true` in its place is refused, naming
`{}`. A format that compares record values may accept null as a record value
only through the shared `DataLiteral` type, recorded in the exceptions
register (`stable-move`) until the format states unset values explicitly.
*Why:* the audit found `null` meaning absent, empty, the text `"null"`, and an
error, depending on the member; and an empty value after a key is more often
an unfinished edit or an empty template variable than a choice.

**CFG-EMPTY-2 (MUST). An empty list or mapping is never how a file says "no
restriction".** Where entries grant (an allow-list, bindings), empty means
none, and a granting member that also accepts the sentinel refuses `[]`,
naming it. Where entries restrict (required scopes or purposes, per-issuer
rules, a deny-list), empty is refused: omit the member when nothing is added
and omission is closed (CFG-EMPTY-3), and otherwise write the sentinel
`unrestricted` in place of the list. An enumerable set (Scheduling
`channels`) takes no sentinel: its open choice is every member listed, and
`[]` is refused.

```yaml
requiredScopes: unrestricted      # any authenticated caller of this profile
rowBoundaries: unrestricted       # every row the profile can otherwise reach
allowedClients: [case-portal]     # [] is refused here, naming unrestricted
```

A product that refuses the sentinel for a member says why in the refusal. A
check warns on an allow-list item equal to `*` or `unrestricted`: the sentinel
replaces the list, it is not an item of it.
*Why:* `[]` meaning "everything" in one key and "nothing" in the next is the
access-policy mistake reviewers miss most; a word is visible in review and
greppable in an audit.
*Enforced by:* the schema convention lint (a member that accepts
`unrestricted` declares `minItems: 1` on its list form); review classifies
each member as granting or restricting.

**CFG-EMPTY-3 (MUST). Omitting a security-relevant member fails closed or is
refused.** No default grants access, widens a network boundary, accepts an
unauthenticated caller, or turns off verification. Where a product needs the
open choice, the operator writes it (CFG-NAME-7, CFG-EMPTY-2).
*Enforced by:* review with a security review note (AGENTS.md), against the
security-relevant members the format registry lists per format.

**CFG-EMPTY-4 (MUST). Every default is declared in the schema** (`default`),
is the value the reader uses, and validates against the member's own schema.
An optional member with no default value declares no `default` (never
`default: null`), and its `description` states what omitting it means. A
default computed from other members is described, not declared.
*Enforced by:* the convention lint (no `default: null`; every `default`
validates against its member's schema).

**CFG-EMPTY-5 (SHOULD). The check command can print the effective document**
with every default filled in.

**CFG-EMPTY-6 (MUST). In an expectation format (fixtures, journeys,
simulations), an absent member means not checked.** Asserting that something
is absent has an explicit spelling (`target: none`), never an omitted key.
*Why:* a typed reader reads every omitted expectation as absent, so a fixture
that meant "no target" would silently stop asserting.

## 8. Secrets and environment

**CFG-SEC-1 (MUST). Secrets appear only as references,** in members whose
key ends in `Ref` (one) or `Refs` (a list). A reference is `secret:env/NAME`,
with `NAME` matching `[A-Z][A-Z0-9_]{0,127}`, or `secret:file/name`, with
`name` matching `[a-z][a-z0-9._-]{0,127}`, resolved under
`secretProviders.file.root`. It is parsed by the one shared `SecretReference`
type and typed in every schema through `$defs/SecretReference` (Evidence's
frozen `$defs/secret-ref` carries the same pattern until the stable move). A
reference names where a secret is read, never the secret, so a format may
allow references in an authored file (the Evidence bundle). An inline secret,
a bare path to a key file (development `*File` members, `evidence-oid4vci`
`privateKeyFile`), and a reference in a member not ending in `Ref` or `Refs`
are refused.

**CFG-SEC-2 (MUST). Substitution happens only in operator files,** only
inside string values, never in keys, `apiVersion`, `kind`, a member ending in
`Ref` or `Refs`, or anything under `secretProviders`. The forms are `${NAME}`
(refused when unset or empty), `${NAME:-fallback}`, and `${NAME:?message}`
(refused without repeating the message), with `NAME` matching
`[A-Za-z_][A-Za-z0-9_]*`; there is no escape. A substitution in an integer or
boolean position is refused (CFG-VAL-3): write the value or template the
whole file. An authored file containing a substitution expression is refused
at that value (`config.substitution-not-allowed`), as a structural problem
(CFG-DIAG-5), and the remedy names the operator-file member that binds such a
value or,
where the product has none, says to write the value in the authored file.
Text that is not an expression, such as a lone `${`, is accepted.
*Why:* an authored file must mean the same thing on every machine, and a
digest pins it.

**CFG-SEC-3 (MUST). No message repeats a scalar value read from a file or the
environment.** A diagnostic may name keys and the path to them (including
local identifiers used as keys), the accepted values, bounds, the expected
envelope, and a local identifier from an authored file that passes the
`LocalId` grammar (the queue a dangling reference names). It may name an
environment variable a substitution expression references. It never repeats
any other value as written, a variable's value, a fallback, or a `:?`
message.
*Enforced by:* the shared reader's message construction; the conformance
corpus plants a marker in scalar values that are not local identifiers and
asserts that it never appears in any product's output.

## 9. Embedded content

**CFG-EMBED-1 (MUST). Code lives in its own file,** referenced by a relative
path and pinned by digest where the format pins content: Rhai scripts, SQL,
WASM modules, message templates, and Typst sources. Regular-expression
patterns and JSON Schema fragments may be written inline.

**CFG-EMBED-2 (MUST). An embedded foreign document (a JSON Schema, an
OpenAPI fragment) is read by its own rules, not ours,** and the schema marks
the member with `x-registry-foreign: <specification>` (`json-schema-2020-12`,
`openapi-3.1`), which the convention lint reads to skip its interior. An
extension keyword we add inside a foreign document follows that document's
style (`x-registry-maxBytes` beside `maxItems`) and is listed in the
exceptions register as `external-format`.

## 10. Diagnostics

**CFG-DIAG-1 (MUST). One diagnostic shape.** Every checking command reports
problems as:

```json
{
  "severity": "error",
  "code": "breg.entity.unknown-field-type",
  "artifact": "BRegModule",
  "path": "/entities/0/fields/2/type",
  "message": "the field type is not one of: text, integer, decimal, date, boolean",
  "suggestedAction": "Use one of the listed field types.",
  "source": { "file": "modules/household/module.yaml", "line": 14, "column": 11 }
}
```

`severity` is `error` or `warning`, and nothing else. `artifact` is the
document's `kind`; when `kind` is absent or wrong, `artifact` is the kind the
command expected, or is absent. `path` is an RFC 6901 JSON pointer into the
document as written. `source` is present whenever the diagnostic concerns a
file, with `line` and `column` whenever the reader knows a position, which it
does for every structural and type error (CFG-SCHEMA-8). `source.file` is the
path as the command was given it, or, for a file the command found itself, the
path given for the project joined with the file's path inside it. `line` and
`column` are 1-based; `column` counts Unicode scalar values, a leading
byte-order mark is not counted, and a tab counts as one. A key problem
(unknown, duplicate, removed) points at the key; a value problem at the
value's first character; a missing member at the key of the mapping that
lacks it. A problem that involves another location lists it in `related`,
each entry with `file`, `line`, `column`, `path`, and `message`. The type
lives in `registry-platform-yaml` and the ctl report envelope (`ok`,
`command`, `status`, ..., `diagnostics`) carries it unchanged.

**CFG-DIAG-2 (MUST). Human output puts the position first:**

```text
error[breg.entity.unknown-field-type] modules/household/module.yaml:14:11 /entities/0/fields/2/type
  the field type is not one of: text, integer, decimal, date, boolean
  next: Use one of the listed field types.
```

Each `related` entry follows the `next:` line as a `note:` line with its own
position, path, and message. The output ends with one summary line counting
errors, warnings, and the files checked (`2 errors, 1 warning in 3 files`).
A path longer than 120 characters is shown as its first and last 60 joined by
`...`; the JSON `path` is always whole.

**CFG-DIAG-3 (MUST). Codes are dotted, lowercase, each segment kebab-case.**
A product code is `<product>.<area>.<condition>` with the product token
(`breg`, `casework`, `scheduling`, `messaging`, `discovery`, `render`,
`evidence`, `manifest`, `platform`); a shared reader code is
`<namespace>.<condition>`, with `yaml` for syntax and `config` for envelope,
key, and type problems. A code is never reused for a different condition.

**CFG-DIAG-4 (MUST). Exit codes:** 0 when no error was reported (warnings
allowed), 1 when the input was refused, 2 for a usage error, 3 when something
the command depends on was unavailable. Every checking command takes
`--deny-warnings`, which makes a reported warning exit 1.

**CFG-DIAG-5 (MUST). A check reports every problem it can find in one run.**
Structural problems are those the reader finds before decoding: every `yaml.`
code and the envelope check. All are reported together, and a document with
one is not decoded. A problem that stops the parser ends the pass, so nothing
after it is found: `yaml.too-large` and `yaml.not-utf8` are reported alone,
before parsing; a syntax error, `yaml.too-deep`, and `yaml.multiple-documents`
follow the problems found before them. While decoding, the reader records every unknown and
removed key and continues; decoding stops at its first other error in a
document. Semantic checks run only on documents decoded without error and
report all their findings. The reader reports at most 100 diagnostics for one
file, the first by position, then one `config.too-many-problems` diagnostic
counting the rest, so a damaged file cannot flood a terminal or a log.

**CFG-DIAG-6 (MUST). Every refusal names its fix** in `suggestedAction`, as a
sentence an operator can act on without reading the source. The shared reader
words the common type errors this way, taking `<unit>` from the key
(CFG-NAME-4, left out for a count) and the bounds from the schema
(CFG-QTY-4):

| Written | `message` | `suggestedAction` |
|---|---|---|
| a quoted number in an integer position (`"400"`) | expected a whole number of `<unit>` from `<minimum>` to `<maximum>`; quoted values are text | Remove the quotes. |
| a number with a unit (`5s`, `48h`) | expected a whole number of `<unit>` from `<minimum>` to `<maximum>` | Write the number of `<unit>` as digits. |
| `1_000` or `1e6` in an integer position | expected a whole number of `<unit>` from `<minimum>` to `<maximum>` | Write digits only. |
| `yes`, `no`, `on`, or `off` in a boolean position | expected true or false; yes, no, on, and off are text | Write true or false. |
| a substitution in an integer or boolean position | substitution fills text values only | Write the value, or template the whole file. |

## 11. Schemas, editors, and the registry

**CFG-SCHEMA-1 (MUST). Every format is registered** in
`products/platform/config-formats.yaml` with its kind, apiVersion values,
audience, owning product, stability (promised, experimental, unpromised),
schema path and `$id`, reader, check command, minimal valid example, the
member it offers for each typed conformance case (CFG-CHECK-3), and its
security-relevant members (CFG-EMPTY-3). For an output format, the minimal
valid example is a committed output of the command that writes it.

**CFG-SCHEMA-2 (MUST). Every authored and operator format ships a JSON
Schema generated from the Rust types** (schemars under a `schema` feature,
written by an `examples/*-schema.rs` generator), committed, and held
byte-identical by a drift check that runs on every pull request that touches
the product. A hand-written normative schema is allowed only where the
contract precedes the code (Evidence's frozen contracts), with a differential
test holding the code to it.

**CFG-SCHEMA-3 (MUST). `$id` is
`https://id.registrystack.org/schemas/<product>/<format>/<format>.<version>.schema.json`,**
with the same `<product>` and `<format>` segments as the format's
`apiVersion` (CFG-ENV-2).

**CFG-SCHEMA-4 (MUST). Schemas are closed.** An object schema that declares
members closes them with `additionalProperties: false` when all its members
are in its own `properties`, or with `unevaluatedProperties: false` when they
are spread across `allOf`, `oneOf`, `anyOf`, or `$ref`. An id-keyed mapping
declares `propertyNames` and `additionalProperties: <item schema>`. A
subschema under `if`, `then`, `else`, `not`, `dependentSchemas`, or an
applicator branch that only constrains members declared elsewhere is exempt.
A node that passes through a payload the format neither describes nor
promises (a value the product writes as its engine holds it) may stay open
when it carries `x-registry-passthrough: <reason>`, a sentence saying why.
The convention lint refuses the annotation with an empty reason, and in a
promised format its product reads, since that reader refuses unknown keys in
the same position; a promised output format may carry it, and the annotated
node's content is outside the format's promise.
The reader refuses unknown keys in the same positions (CFG-SCHEMA-8).

**CFG-SCHEMA-5 (MUST). Shared blocks have one definition.** The platform
defines `ListenerConfig`, `PrivateListenerConfig`, `DatabaseConfig`,
`OidcIssuerConfig`, `OidcClientsConfig`, `JwksSource`, `AuditKeyConfig`,
`SecretProvidersConfig`, `SecretReference`, `IdentityConfig`,
`ProjectIdentity`, `Url`, `LocalId`, `ExternalId`, and `Digest`. A product
embeds a shared definition unchanged under its shared name, or flattens a
shared block from the platform crate, and never declares its own type for a
concept a shared block covers, whatever its shape. Embedded definitions are
compared with the platform schema; flattened blocks are checked at their Rust
type.

**CFG-SCHEMA-6 (MUST). Every authored and operator format is mapped for
editors** by
`editors/configure.py`, per project directory; where file names collide
across products, the modeline (CFG-SCHEMA-7) selects the schema.

**CFG-SCHEMA-7 (MUST). A tool that creates a YAML file writes the
`# yaml-language-server: $schema=<$id>` modeline on its first line.** The
modeline may name the local schema copy the tool wrote instead of the `$id`,
for a network that cannot reach `id.registrystack.org`.
*Enforced by:* the conformance corpus runner's `init` mode, which runs each
product's init command named in the corpus harness and reads the first line
of each format's file it writes.

**CFG-SCHEMA-8 (MUST). Every position keeps its source position.** A reader
type decodes so that every error, including one inside a union variant or a
shared block, carries the path, line, and column of the offending node:

- every struct refuses unknown keys;
- `flatten` only places a platform shared block into a host that refuses
  unknown keys; a map, an enum, or an `Option` is never flattened;
- a tagged union, internal or external (CFG-ID-7), is decoded by the shared
  reader's union helper (or as one flat struct of position-carrying members
  validated per variant), never by serde's derived `tag`; every variant of an
  internally tagged union is a struct variant, including an empty one
  (`Variant {}`);
- an untagged union is allowed only when its variants differ by node kind
  (scalar, list, mapping), never between two mappings told apart by which
  members are present;
- a nested deserializer's message is never passed through as text.

*Why:* serde's derived unions and flatten buffer the subtree without
positions, so the same mistake would be reported at different positions, or
with no accepted keys, by different products.
*Enforced by:* the conformance corpus unknown-key sweep (a key planted in
every mapping of every registered format's example, including each union
variant and shared block, asserting `config.unknown-key`, path, line, and
column); a source lint over the reader-type closure of every registered
format for `serde(flatten`, `serde(untagged`, `serde(tag`, and unit variants
in tagged enums, ratcheted by the exceptions register.

**CFG-SCHEMA-9 (SHOULD). Editors get the same rules without a source
checkout.** The editor mapping is installable from the released tools
(`init` writes it, or `<product>ctl editor setup`), and a rule the schema
cannot express (an `http` issuer allowed only on development loopback, a
cross-file reference) is stated in the member's `description`.

## 12. Checking commands

**CFG-CHECK-1 (MUST). Every read format has an offline check command** that
reads it through the shared reader, applies every rule the runtime would
apply that needs no network or database, and reports CFG-DIAG diagnostics. A
runtime file is checkable before deployment, against the project directory it
binds, with no built package, database, or network. A check of an operator
file reads no secret material: it checks every substitution expression and
secret reference by syntax and position, and skips value checks that need
substituted text unless asked to substitute from the current environment
(`--environment`). It may report that a referenced secret file is missing or
too widely readable, without reading it.

**CFG-CHECK-2 (MUST). A product's project check reads every file of the
project it owns,** including fixtures, journeys, development clients, and
cross-file references (CFG-ID-4). A directory scan reads every `.yaml` and
`.yml` file, identifies each by its envelope, refuses one whose kind does not
belong there, and never skips a YAML file silently.

**CFG-CHECK-3 (MUST). The conformance corpus proves the products agree.**
`products/platform/conformance/yaml/` holds one negative case per reader rule.
Its runner inserts each case into every registered read format's minimal
valid example (registered with the format) at the position the case names:
the top level for reader rules, and for type rules the member of that type
the registry names for each format. It then runs that format's check command
and asserts the same code, the same path relative to the insertion point, and
the same line and column offset from every product.

**CFG-CHECK-4 (SHOULD). A tool that rewrites an authored file preserves
comments, key order, and formatting outside the node it edits,** or refuses
and prints the manual edit.

## 13. Change and versioning

**CFG-CHANGE-1 (MUST). One spelling per version.** A version of a format
accepts exactly one spelling of each key and value. There are no aliases.

**CFG-CHANGE-2 (MUST). A removed or renamed key, and a retired `apiVersion`,
is refused with its replacement named** (`config.removed-key`: "`maxBytes` was renamed to
`maximumBytes`"; `config.retired-api-version`, naming the current
`apiVersion`), registered in the format's removed-key table. The refusal is
the migration guide; it stays until the format's next stable version.

**CFG-CHANGE-3 (MUST). Before 1.0, an alpha format may change in place.**
Each breaking change ships in one change with: a `BREAKING:` entry and exact
migration steps in the product CHANGELOG and the stack release note; updated
examples, `init` templates, tutorials, and fixtures; regenerated schemas; and
the documented steps applied in the release upgrade rehearsal.

**CFG-CHANGE-4 (MUST). After a format is stable, it changes only under
[API stability](../../docs/site/src/content/docs/reference/api-stability.mdx):**
the replacement is a new `apiVersion` read alongside the old one, and the
check command reports the deprecated version as a warning.

**CFG-CHANGE-5 (MUST). New formats and new keys comply from their first
commit.** The exceptions register only shrinks, except for protocol
constants, external formats, and exchange models.

## Exceptions

A deviation from a MUST rule is allowed only when it is recorded in
`products/platform/config-conventions-exceptions.yaml` with its rule, format,
location, class, reason, and resolution. The convention lint fails on an
unrecorded deviation and on a recorded one that no longer deviates.

| Class | Meaning | Resolution |
|---|---|---|
| `protocol-constant` | A value another specification defines, written as it defines it. | Permanent. |
| `external-format` | A file whose grammar another project owns. | Permanent; listed so the scope is explicit. |
| `exchange-model` | A published data model whose member names its specification fixes. | Permanent for that specification version. |
| `stable-move` | A respelling of something a correct file in a promised format already writes (header, key, enum value, identifier grammar, unit, discriminator), applied in the release that moves promised formats to stable. | That release. |
| `decision` | A deviation waiting on a named, dated decision. | The decision; the entry names it. |
| `pending` | A deviation in work the configuration conventions program has not reached yet; the entry's `wp` names the work package that removes it. | That work package. `--strict` refuses every `pending` entry; the program is done when `--strict` passes. |

A whole format whose grammar another project owns, or that a published
exchange model fixes, carries `exceptionClass` in `config-formats.yaml`
instead of one entry per finding.

## Enforcement summary

Each MUST rule appears once; SHOULD rules are in the last row.

| Rules | Gate |
|---|---|
| CFG-ENV-1, 4; CFG-YAML-2 to 8; CFG-VAL-1 to 3; CFG-EMPTY-1; CFG-SEC-2, 3; CFG-DIAG-1, 2, 5; CFG-CHANGE-2 | reader unit tests named with the rule ID; the conformance corpus; for CFG-ENV-1 also the convention lint (`const` envelope) |
| CFG-YAML-1 | `disallowed-methods` in every `clippy.toml` in the repository, with the proof script; the conformance corpus; the convention lint's source scan (a reader that bypasses `registry-platform-yaml`) |
| CFG-ENV-2, 3, 6; CFG-NAME-1 to 5; CFG-ID-1, 6, 7; CFG-QTY-1 to 4; CFG-VAL-6, 7; CFG-EMPTY-2, 4; CFG-SEC-1; CFG-EMBED-2; CFG-SCHEMA-1, 3 to 6 | `check-config-conventions.py` over the registry and every schema, with the exceptions register as ratchet; for CFG-EMPTY-2 the lint checks the sentinel shape and review classifies each member as granting or restricting; for CFG-SEC-1 also the `SecretReference` parser tests; for CFG-ID-6 also the source lint (set types) and the corpus's duplicated set item; for CFG-QTY-4 also the corpus boundary sweep over the bounds each format's registered schema states |
| CFG-SCHEMA-8; CFG-CHANGE-1 | source lint over the reader-type closure (`flatten`, `untagged`, `tag`, `alias`, set types); the corpus unknown-key sweep |
| CFG-SCHEMA-2 | each product's schema drift check, in a job that runs on every pull request touching the product; the convention lint (a format with no generated schema) |
| CFG-CHECK-1 to 3; CFG-DIAG-3, 4, 6; CFG-ID-4, 5; CFG-VAL-8, 9; CFG-SCHEMA-7 | product CLI tests and the corpus runner; for CFG-ID-4, CFG-ID-5, CFG-VAL-8 and CFG-VAL-9 the cases at the registry's `conformance` roles (dangling reference, duplicate id, escaping path, mistyped operand); for CFG-SCHEMA-7 the runner's `init` mode (the modeline each product's init command writes); for CFG-CHECK-1 also the convention lint (the registry's `check` field) |
| CFG-CHANGE-5 | the convention lint compares the exceptions register with the base entry by entry (rule, format, location): an added entry outside the growth classes fails, and so does a class change, so deletion is the only other change and a moved entry counts as added; an explicit `--base` without the register fails |
| CFG-ID-2, 3; CFG-VAL-4, 5; CFG-NAME-7; CFG-EMPTY-3, 6; CFG-EMBED-1; CFG-CHANGE-3, 4 | review citing the rule; CFG-EMPTY-3 also needs a security review note (AGENTS.md) |
| CFG-ENV-5; CFG-VAL-10; CFG-NAME-6, 8; CFG-ID-8; CFG-EMPTY-5; CFG-SCHEMA-9; CFG-CHECK-4 (SHOULD) | review |

## Example

An excerpt of a compliant operator file (other required members omitted):

```yaml
# yaml-language-server: $schema=https://id.registrystack.org/schemas/messaging/runtime/runtime.v1alpha1.schema.json
apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
listener:
  bind: 127.0.0.1:8443
database:
  runtimeUrlRef: secret:env/MESSAGING_DATABASE_URL
audit:
  retentionDays: 90
```

The same excerpt with two mistakes:

```yaml
apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
listener:
  bind: 127.0.0.1:8443
audit:
  retentionDays: "90"
listener:
  bind: 0.0.0.0:8443
```

Every product's check reports the structural problem first, because the
reader will not guess which `listener` was meant:

```text
error[yaml.duplicate-key] runtime.yaml:7:1 /listener
  the key is already defined in this mapping
  next: Keep one definition of the key.
  note: runtime.yaml:3:1 /listener the first definition
1 error, 0 warnings in 1 file
```

With the second `listener` removed, the next run reports the type problem:

```text
error[config.expected-integer] runtime.yaml:6:18 /audit/retentionDays
  expected a whole number of days from 1 to 36500; quoted values are text
  next: Remove the quotes.
1 error, 0 warnings in 1 file
```
