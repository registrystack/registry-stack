# Registry Stack configuration conventions

These rules apply to every configuration format Registry Stack defines: the
files adopters author, the runtime files operators deploy, and the files our
tools generate for a person or another tool to read. A person who has learned
one product's files should be able to predict how every other product's files
look, how they are read, and how a mistake is reported.

The rules are normative. **MUST** rules are enforced by a gate named in the
rule; a change that breaks one fails CI. **SHOULD** rules are reviewed by
people; a deviation needs a reason in the pull request. Every rule names why it
exists, so a reviewer can tell a real exception from a habit.

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
  environment value or a secret.
- **Operator files** describe where and how a deployment runs: every
  `runtime.yaml`, development client files, and operator request files.
- **Generated files** a tool writes for a person or another tool to read back:
  module locks, package manifests, receipts, explain output.
- Authored and operator **JSON** files (scenarios, request inputs, migration
  descriptors, backup bindings) follow every rule that is not YAML-specific.

Out of scope, recorded as exception classes in
[Exceptions](#exceptions):

- formats another project owns (OpenAPI, JSON Schema, LinkML, ThunderID
  resources, `SHA256SUMS`, GitHub workflows, release tooling);
- exchange data models whose member names a published specification fixes
  (Registry Manifest metadata documents) and record data (JSONL imports);
- HTTP problem codes, which belong to each product's API contract.

## Concepts

| Term | Meaning |
|---|---|
| Format | One document shape with one `apiVersion` and `kind`, owned by one product. |
| Envelope | The `apiVersion` and `kind` pair that opens every document. |
| Local identifier | A name an author chooses in our files for something our files define (an entity, a profile, a template, a destination). |
| External identifier | A name defined elsewhere that our files quote (an OIDC client id, a claim name, a scope, a URN). |
| Reference | A member whose value names an item defined elsewhere in the same file or another file. |
| Sentinel | A reserved string written in place of a list or value to state an open choice explicitly, such as `unrestricted`. |
| Diagnostic | One reported problem: severity, code, location, message, and the fix. |
| Format registry | `products/platform/config-formats.yaml`, the machine-readable list of every format, its schema, its reader, and its check command. |
| Exceptions register | `products/platform/config-conventions-exceptions.yaml`, every recorded deviation with its class and resolution. |

## 1. Files and envelopes

**CFG-ENV-1 (MUST). Every document opens with `apiVersion` and `kind`.**
Both are plain strings, the first two keys of the top-level mapping, and are
compared literally before any other member is read. Neither may come from
`${...}` substitution.
*Why:* a reader can refuse the wrong file with a precise message ("this is a
`CaseworkFixture`, `casework check` reads a `CaseworkProject`"), editors can
pick a schema, and a format can be versioned on its own.
*Enforced by:* the shared reader's envelope check; the format registry lint
(every registered format declares both as `const` in its schema).

**CFG-ENV-2 (MUST). `apiVersion` is
`id.registrystack.org/formats/<product>/<format>/<version>`.** `kind` is the
product prefix followed by the format name. `<product>` is the product token
(CFG-ENV-3); `<format>` is the kebab-case format name without a trailing
`Config`, and a product's project file (`kind` ending in `Project`) is
`project`.

| `kind` | `apiVersion` (before its version) |
|---|---|
| `CaseworkProject` | `id.registrystack.org/formats/casework/project/` |
| `BRegRuntimeConfig` | `id.registrystack.org/formats/breg/runtime/` |
| `SchedulingPolicyPackage` | `id.registrystack.org/formats/scheduling/policy-package/` |
| `CaseworkFixture` | `id.registrystack.org/formats/casework/fixture/` |
| `RenderBundle` | `id.registrystack.org/formats/render/bundle/` |

`<version>` is `v<N>`, `v<N>alpha<M>`, or `v<N>beta<M>`. The `apiVersion` is a
name, not a URL: readers compare it literally and never fetch it. The
identifier catalog may document it at the same path under `https://`.
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
second YAML document (`---` after content) is refused.
*Enforced by:* the shared reader (`yaml.multiple-documents`).

**CFG-ENV-5 (SHOULD). Tools write `.yaml` files named after the format**
(`registry.yaml`, `runtime.yaml`, `module.yaml`). Readers accept whatever
path they are given; the envelope, not the extension, identifies the format.

## 2. The YAML subset

Registry Stack reads YAML 1.2 with one parser, the shared reader in
`registry-platform-yaml`, and accepts a strict subset. Every refusal below
reports the file, line, and column.

**CFG-YAML-1 (MUST). One reader.** Every format in the registry is read
through `registry-platform-yaml` (runtime files through
`RuntimeConfigLoader`, which builds on it). No crate deserializes YAML with
`serde_norway` or any other YAML crate directly; serialization (writing YAML)
is unaffected.
*Why:* the audit that produced these rules found five parse pipelines whose
behavior depended on the target type: duplicate keys refused in one product
and silently last-wins in another, `id: null` read as the text `"null"`, line
numbers in some errors and none in others.
*Enforced by:* `clippy.toml` `disallowed-methods` (root and every crate-level
`clippy.toml`); the cross-product conformance corpus (CFG-CHECK-3).

**CFG-YAML-2 (MUST). Duplicate keys are refused in every mapping,** naming
both lines (`yaml.duplicate-key`).
*Why:* last-wins lets a reviewer approve the first value while the second one
runs.

**CFG-YAML-3 (MUST). Anchors, aliases, and merge keys are refused**
(`yaml.anchor`, `yaml.alias`, `yaml.merge-key`). Merge keys are named as such,
not reported as an unknown `<<` member.
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
refused before parsing (`yaml.too-large`), naming the bound. Input is UTF-8; a
leading byte-order mark is accepted and ignored; LF and CRLF line endings are
both accepted.
*Why:* hand-written configuration never approaches the bound, and one bound
for every format is one fact to remember.

**CFG-YAML-7 (MUST). Comments are allowed everywhere and never carry
meaning.**

## 3. Scalars and types

**CFG-VAL-1 (MUST). Plain scalars resolve by one table,** the YAML 1.2 core
schema narrowed to forms that read unambiguously:

| Plain scalar | Resolves to |
|---|---|
| `null`, `Null`, `NULL`, `~`, or nothing | null |
| `true`, `True`, `TRUE`, `false`, `False`, `FALSE` | boolean |
| `0`, or an optional sign followed by a digit 1 to 9 and more digits | integer |
| decimal with a fraction or exponent (`1.5`, `-0.25`, `1e3`) | number |
| a leading-zero integer (`0123`), `0x`, `0o`, `.inf`, `.nan` | refused (`yaml.ambiguous-number`): write a decimal number, or quote it as text |
| anything else, including `yes`, `no`, `on`, `off`, `1_000`, `1:30` | string |

Quoted and block scalars (`'...'`, `"..."`, `|`, `>`) are always strings.

**CFG-VAL-2 (MUST). A member typed as text accepts only a string.** A plain
scalar that resolves to null, a boolean, or a number in a text position is
refused with "quote the value to make it text" (`config.expected-string`).
`id: true`, `version: 1.0`, and `code: 0123` are mistakes, not the strings
`"true"`, `"1.0"`, and `"0123"`.
*Why:* silent coercion turned `route: null` into the route `"null"`, and the
same file meant different things to different products.

**CFG-VAL-3 (MUST). Numbers and booleans are never written as strings.** A
quoted `"8080"` in an integer position is refused; there is no string-to-number
coercion.

**CFG-VAL-4 (MUST). Exact decimals are strings.** A value whose exactness
matters (a decimal bound, a money amount, a coordinate edge) is a quoted
string matching `^-?[0-9]+(\.[0-9]+)?$`. Its schema says so in `description`
and `pattern`.
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

**CFG-VAL-8 (MUST). Relative paths resolve against the directory of the file
that contains them,** use `/`, and in an authored file may not leave the
project directory.
*Why:* a file's meaning must not depend on the directory a command was run
from.

## 4. Names

**CFG-NAME-1 (MUST). Keys are camelCase ASCII** (`^[a-z][a-zA-Z0-9]*$`).
Acronyms are words: `jwksUri`, `oidcIssuer`, `tlsTermination`, never `JWKSURI`.
A mapping whose keys are local identifiers (an id-keyed map) follows
CFG-ID-1 instead.
*Enforced by:* the schema convention lint.

**CFG-NAME-2 (MUST). Every value a machine matches and Registry Stack names
is lowercase kebab-case** (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`): enum values,
sentinels, each segment of an `apiVersion` path, and each segment of a
diagnostic code.
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
(`maximumRequestBytes`, `minimumReplicas`).
*Enforced by:* the schema convention lint (keys starting `max`/`min` followed
by an uppercase letter, and keys ending `Limit`).

**CFG-NAME-4 (MUST). A quantity's unit is the last word of its key** and is
spelled out: `Milliseconds`, `Seconds`, `Minutes`, `Hours`, `Days`,
`WorkingDays`, `Bytes`. A count has no unit word. See CFG-QTY.

**CFG-NAME-5 (MUST). A concept shared by several products has one name.**

| Concept | Key |
|---|---|
| Time allowed for one outbound request | `requestTimeoutMilliseconds` |
| Time allowed to drain on shutdown | `shutdownGraceMilliseconds` |
| Longest accepted token lifetime | `maximumTokenLifetimeSeconds` |
| How long records of a kind are kept | `retentionDays` on the item, or `<thing>Days` inside a `retention` block |
| Cache entry lifetime | `cacheTtlSeconds` |
| Largest accepted body or file | `maximum<Thing>Bytes` |

Adding a shared concept adds a row here in the same change.
*Enforced by:* the schema convention lint (one unit per key stem across all
schemas; a listed concept spelled another way fails).

**CFG-NAME-6 (SHOULD). Booleans are named so `true` turns the behavior on**
(`enabled`, `trustProxyIdentityHeaders`), never `disableX` or `noX`.

**CFG-NAME-7 (MUST). A setting that weakens a safe default takes a named
value that states what the operator accepts,** not a boolean:
`tlsTermination: operator-controlled-upstream`, not `insecure: true`.
*Why:* the value reads as an acknowledgement in review and greps as one.

## 5. Identifiers and references

**CFG-ID-1 (MUST). Local identifiers match `^[a-z][a-z0-9_-]{0,63}$`** in
every product and every position. A product may refuse identifiers that
collide after it derives a name from them (`date-of-birth` and
`date_of_birth` both becoming one column), and says so in the diagnostic.
*Why:* the audit found nine identifier grammars, so the same id was valid in
one file and refused in the next.
*Enforced by:* one shared `LocalId` type in `registry-platform-yaml`, and the
schema convention lint (every identifier position references the shared
`$defs/localId`).

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

**CFG-ID-5 (MUST). Named items are a list of mappings with `id` first when
their order carries meaning, and an id-keyed mapping when it does not.**
Either way identifiers are unique and a duplicate is refused.

**CFG-ID-6 (MUST). A list that is a set refuses duplicates** instead of
collapsing them, and its schema declares `uniqueItems: true`.

**CFG-ID-7 (MUST). A tagged union names its variant with `type`,** whose
values follow CFG-NAME-2, and every variant, including one with no members,
refuses unknown keys.

## 6. Quantities

**CFG-QTY-1 (MUST). A duration is an integer with its unit in the key**
(`requestTimeoutMilliseconds: 5000`, `retentionDays: 30`). ISO 8601 duration
strings and unit-suffixed strings (`PT5S`, `5s`) are not used.
*Why:* integers can be range-checked by a schema, read without a parser,
diffed exactly, and they are already the form of almost every duration in the
stack.

**CFG-QTY-2 (MUST). One stem, one unit.** A key stem (`requestTimeout`) uses
the same unit in every format. Choose the coarsest unit that expresses every
legitimate value as an integer.

**CFG-QTY-3 (MUST). Sizes are integer bytes** (`maximumRequestBytes:
1048576`).

**CFG-QTY-4 (MUST). Every quantity has a stated minimum and maximum** in its
schema, and the reader enforces the same bounds.

## 7. Empty, null, and omitted values

**CFG-EMPTY-1 (MUST). `null` is never a value.** In an optional member it
reads exactly as if the key were absent. In any other member it is refused
with "remove the key, or give a value" (`config.null-value`).
*Why:* the audit found `null` meaning absent, empty, the text `"null"`, and an
error, depending on the member.

**CFG-EMPTY-2 (MUST). An empty list or mapping means the empty set, and never
widens access or scope.** An empty allow-list allows nothing. Where an empty
list would mean "no restriction", the member is refused when empty and the
open choice is written as the sentinel `unrestricted` in place of the list:

```yaml
requiredScopes: unrestricted      # any authenticated caller of this profile
rowBoundaries: unrestricted       # every row the profile can otherwise reach
allowedClients: [case-portal]     # an allow-list: [] would allow no client
```

*Why:* `[]` meaning "everything" in one key and "nothing" in the next is the
access-policy mistake reviewers miss most; a word is visible in review and
greppable in an audit.
*Enforced by:* the schema convention lint (a member that accepts
`unrestricted` declares `minItems: 1` on its list form).

**CFG-EMPTY-3 (MUST). Omitting a security-relevant member fails closed or is
refused.** No default grants access, widens a network boundary, accepts an
unauthenticated caller, or turns off verification. Where a product needs the
open choice, the operator writes it (CFG-NAME-7, CFG-EMPTY-2).

**CFG-EMPTY-4 (MUST). Every default is declared in the schema** (`default`)
and is the value the reader uses. A schema generated from the reader's types
carries it by construction; a hand-written schema's differential test checks
it.

**CFG-EMPTY-5 (SHOULD). The check command can print the effective document**
with every default filled in.

## 8. Secrets and environment

**CFG-SEC-1 (MUST). Secrets appear only as references, in operator files,
in members whose key ends in `Ref`.** A reference is `secret:env/NAME` or
`secret:file/name`, parsed by the one shared `SecretRef` type and typed in
every schema through the shared `$defs/secretRef`. An inline secret, a bare
path to a key file, or a secret in an authored file is refused.

**CFG-SEC-2 (MUST). `${NAME}` substitution happens only in operator files,**
only inside string values, never in keys, never in `apiVersion` or `kind`,
and never in a `*Ref` member. An authored file that contains `${` in a value
is refused with the remedy (move the value to `runtime.yaml`).
*Why:* an authored file must mean the same thing on every machine, and a
digest pins it.

**CFG-SEC-3 (MUST). No message repeats a value read from a file or the
environment.** A diagnostic names the key, its position, the accepted values
or bounds, and the fix; it never quotes what was written. Expected envelope
values may be named.
*Enforced by:* the shared reader's message construction; the conformance
corpus asserts that a planted marker value never appears in any product's
output.

## 9. Embedded content

**CFG-EMBED-1 (MUST). Code lives in its own file,** referenced by a relative
path and pinned by digest where the format pins content: Rhai scripts, SQL,
WASM modules, message templates, and Typst sources. Regular-expression
patterns and JSON Schema fragments may be written inline.

**CFG-EMBED-2 (MUST). An embedded foreign document (a JSON Schema, an
OpenAPI fragment) is read by its own rules, not ours,** and the schema marks
the member as foreign so the convention lint skips its interior.

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

`severity` is `error` or `warning`. `artifact` is the document's `kind`.
`path` is an RFC 6901 JSON pointer into the document as written. `source` is
present whenever the reader knows a position, which it does for every
structural and type error. The type lives in `registry-platform-yaml` and the
ctl report envelope (`ok`, `command`, `status`, ..., `diagnostics`) carries it
unchanged.

**CFG-DIAG-2 (MUST). Human output puts the position first:**

```text
error[breg.entity.unknown-field-type] modules/household/module.yaml:14:11 /entities/0/fields/2/type
  the field type is not one of: text, integer, decimal, date, boolean
  next: Use one of the listed field types.
```

**CFG-DIAG-3 (MUST). Codes are `<namespace>.<area>.<condition>`,** lowercase,
each segment kebab-case. Product codes start with the product token (`breg`,
`casework`, `scheduling`, `messaging`, `discovery`, `render`, `evidence`,
`manifest`); the shared reader uses `yaml.` for syntax and `config.` for
envelope, key, and type problems. A code is never reused for a different
condition.

**CFG-DIAG-4 (MUST). Exit codes:** 0 when no error was reported (warnings
allowed), 1 when the input was refused, 2 for a usage error, 3 when something
the command depends on was unavailable.

**CFG-DIAG-5 (MUST). A check reports every problem it can find in one run.**
All structural problems of a document are reported together; type decoding
stops at its first error in a document; semantic checks report all their
findings.

**CFG-DIAG-6 (MUST). Every refusal names its fix** in `suggestedAction`, as a
sentence an operator can act on without reading the source.

## 11. Schemas, editors, and the registry

**CFG-SCHEMA-1 (MUST). Every format is registered** in
`products/platform/config-formats.yaml` with its kind, apiVersion values,
audience, owning product, stability (promised, experimental, internal),
schema path and `$id`, reader, and check command.

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

**CFG-SCHEMA-4 (MUST). Schemas are closed:** every object declares
`additionalProperties: false`, and the reader refuses unknown keys in the
same positions, including inside union variants and flattened blocks.

**CFG-SCHEMA-5 (MUST). Shared blocks have one definition.** Listener,
database, OIDC issuer and clients, audit, identity, secret providers, URL,
`secretRef`, `localId`, and `digest` come from the platform's shared `$defs`;
a product does not redeclare a shared block with the same shape.

**CFG-SCHEMA-6 (MUST). Every registered format is mapped for editors** by
`editors/configure.py`.

**CFG-SCHEMA-7 (SHOULD). A tool that creates a file writes the
`# yaml-language-server: $schema=<$id>` modeline on its first line.**

## 12. Checking commands

**CFG-CHECK-1 (MUST). Every format has an offline check command** that reads
it through the shared reader, applies every rule the runtime would apply that
needs no network or database, and reports CFG-DIAG diagnostics. A runtime
file is checkable before deployment.

**CFG-CHECK-2 (MUST). A product's project check reads every file of the
project it owns,** including fixtures, journeys, development clients, and
cross-file references (CFG-ID-4).

**CFG-CHECK-3 (MUST). The conformance corpus proves the products agree.**
`products/platform/conformance/yaml/` holds one negative case per reader rule.
Its runner wraps each case in every registered format's envelope, runs that
format's check command, and asserts the same code, path, line, and column from
every product.

**CFG-CHECK-4 (SHOULD). A tool that rewrites an authored file preserves
comments, key order, and formatting outside the node it edits,** or refuses
and prints the manual edit.

## 13. Change and versioning

**CFG-CHANGE-1 (MUST). One spelling per version.** A version of a format
accepts exactly one spelling of each key and value. There are no aliases.

**CFG-CHANGE-2 (MUST). A removed or renamed key, and a retired `apiVersion`,
is refused with its replacement named** (`config.removed-key`: "`maxBytes` was renamed to
`maximumBytes`"), registered in the format's removed-key table. The refusal is
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
commit.** The exceptions register only shrinks, except for protocol constants
and external formats.

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
| `stable-move` | A header or name change to a promised format, applied in the release that moves promised formats from `v1alpha1` to stable. | That release. |
| `decision` | A deviation waiting on a named, dated decision. | The decision; the entry names it. |

## Enforcement summary

| Rules | Gate |
|---|---|
| CFG-ENV-1, 4; CFG-YAML-1 to 7; CFG-VAL-1 to 3; CFG-EMPTY-1; CFG-SEC-2, 3; CFG-DIAG-1, 2, 5; CFG-CHANGE-2 | `registry-platform-yaml` and `RuntimeConfigLoader` unit tests; the conformance corpus |
| CFG-YAML-1 | `clippy.toml` `disallowed-methods` in every clippy configuration |
| CFG-ENV-2, 3; CFG-NAME-1 to 5; CFG-ID-1, 6, 7; CFG-QTY-2, 4; CFG-EMPTY-2; CFG-SEC-1 (schema typing); CFG-SCHEMA-1, 3 to 6 | `products/platform/scripts/check-config-conventions.py` over the format registry and every generated schema, with the exceptions register as its ratchet |
| CFG-SCHEMA-2 | each product's schema drift check, run on pull requests |
| CFG-CHECK-1 to 3; CFG-DIAG-3, 4, 6 | each product's CLI tests and the conformance corpus runner |
| CFG-ID-3, 4, 5; CFG-VAL-4 to 8; CFG-QTY-1, 3; CFG-NAME-6, 7; CFG-EMPTY-3 to 5; CFG-SEC-1; CFG-EMBED-1, 2; CFG-SCHEMA-7; CFG-CHECK-4; CFG-CHANGE-1, 3 to 5 | review, with this page cited; the shared types (`LocalId`, `SecretRef`, URL, digest) where a type can hold the rule |

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
retention:
  recordDays: 400
```

The same excerpt with two mistakes:

```yaml
apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
listener:
  bind: 127.0.0.1:8443
retention:
  recordDays: "400"
listener:
  bind: 0.0.0.0:8443
```

Every product's check reports the structural problem first, because the
reader will not guess which `listener` was meant:

```text
error[yaml.duplicate-key] runtime.yaml:7:1 /listener
  the key is already defined on line 3
  next: Keep one definition of the key.
```

With the second `listener` removed, the next run reports the type problem:

```text
error[config.expected-integer] runtime.yaml:6:15 /retention/recordDays
  expected an integer; quoted values are text
  next: Remove the quotes.
```
