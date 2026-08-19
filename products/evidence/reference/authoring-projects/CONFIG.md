# Evidence authoring form reference

Status: Adopter tooling, outside the frozen Version 1 contract set

The authoring form is what an adopter writes before a deployment project
exists: one marker document that names the project root, and one YAML document
per question. `evidencectl` compiles those documents into the
`bundle/evidence.yaml` grammar that
[the deployment configuration reference](../request-adapter/deployment-projects/CONFIG.md)
describes. A local compile synthesizes a loopback `runtime.yaml` beside that
bundle so the project can be run on the author's machine, while a production
build writes the bundle alone and copies the `runtime.yaml` of the deployment
target it is given, so nothing on this page reaches a deployed process's
runtime. This page documents the input, not the output.

The two are not the same promise. The deployment grammar is the frozen Version
1 configuration contract. The authoring form is adopter tooling:
`crates/registry-evidence-authoring/src/model.rs` holds its model,
`crates/registry-evidence-authoring/src/validate.rs` holds its checks, and
`crates/registry-evidencectl/schemas/authoring/` holds the JSON Schemas
generated from that model for an adopter's editor. All three may change with
the tooling that generates them. A document this page accepts must still
compile, and compiling is where the frozen contract applies.

Every authored document is closed. Each type in `model.rs` and `marker.rs`
carries `#[serde(deny_unknown_fields)]`, so a key the form does not know is a
rejection rather than something carried along. All names in this reference are
exact and case-sensitive.

## What an authoring project holds

`crates/registry-evidence-authoring/src/layout.rs` names the parts of a project
and the ceiling each is read under.

| Path | Holds | Ceiling |
|---|---|---|
| `evidence-project.yaml` | The project marker | 4 KiB |
| `source.openapi.yaml` | The single OpenAPI description operations are drawn from | 16 MiB |
| `questions/` | Authored questions, one YAML document each | 64 KiB per document, 1 to 128 per project |
| `sources/` | Source definitions a question may name instead of an inline operation | 1 MiB |
| `selectors/` | Selector definitions | 1 MiB |
| `derivations/` | Authored derivation programs, one Rhai file each | 64 KiB |
| `schemas/` | Schemas a structured answer may name | 1 MiB |
| `fixtures/` | Recorded request and response pairs a project is replayed against | 1 MiB |
| `secrets/` | Key material a project needs to run locally | n/a |
| `access/policies/` | Access policy documents | 64 KiB |

Every project retains `source.openapi.yaml`, and it is read before any question
is, so a project whose questions all name a `source.ref` and no operation still
carries one. It declares `openapi: 3.0.x` or `3.1.x`; any other version is
rejected.

As soon as one question names an `operation`, that description is read under a
closed profile. Its top-level keys are `openapi`, `info`, `servers`, `paths`,
and `components`, so anything else, `tags` and a top-level `security`
included, is refused as an unsupported key. `servers` holds exactly one entry,
whose object carries the single field `url`, spelled as a canonical loopback
HTTP origin with an explicit non-zero port: `http://127.0.0.1:8080` or
`http://[::1]:8080`. HTTPS, a hostname such as `localhost`, a trailing slash, a
`description` beside the `url`, and a second server are each refused. A project
whose questions all name a `source.ref` is held to the version alone.

Only the marker and a question have a Rust type behind them, so only those two
carry a generated schema. `crates/registry-evidence-authoring/src/schema.rs`
states the reason: a schema written by hand for one of the other parts would be
the drift the generated pair exists to prevent. The key-path inventory at the
end of this page is therefore the marker and the question, and nothing else.

### Parsing, form validation, and compilation

The generated schemas describe the JSON-compatible shape that can be parsed
into the marker and question models. They do not describe every condition for
an accepted authoring project. After parsing, the shared authoring library
checks field bounds and relationships within one question. `evidencectl` then
checks filenames, referenced files, cross-question relationships, local
artifacts, and the compiled deployment grammar. The real `evidence` binary
performs the final bundle check before a local generation or production
candidate is published.

For example, the question schema describes `subjects` as an array but does not
state its item-count bound. A document with nine structurally valid subjects
can pass JSON Schema validation, then the shared form validator rejects it
because one question accepts only 1 through 8 subjects. Treat schema success as
editor and parse-shape feedback, not as a successful compile.

### Local secrets and signing identity

`evidencectl new` creates `secrets/`, adds it to `.gitignore`, and generates
disposable local key material. A local compile requires that directory to be a
plain, non-symlink directory owned by the current user with exact mode `0700`.
The generated signing private JWK and the two independent HMAC masters remain
inside that directory. They are not bundle artifacts.

The compiler reads `secrets/signing-p256-public.jwk.json` as a bounded regular
file. The shared JWK parser limits the JSON document to 64 KiB, rejects private
members, and requires an `ES256` key with `kty: EC` and `crv: P-256`. Its `kid`
must equal the 43-character RFC 7638 thumbprint of that exact public key. The
compiler copies only this public half to
`bundle/public-keys/<kid>.jwk.json` and uses that path as
`signing.activePublicJwkFile`.

The generated local `runtime.yaml` records the canonical secret-directory path
and synthesizes `signer.privateKeyRef` as
`secret:file/signing-p256-private-jwk`. The generated runtime contains the
reference, not the private JWK, HMAC masters, or another secret value. The
runtime validates the referenced owner-only files before serving.

## The project marker

`evidence-project.yaml` confirms that a directory holding authoring parts is
the project a caller thinks it read. A directory without one is not an error.

| Key | Required | Meaning |
|---|---|---|
| `version` | yes | Marker format version. `1` is the only value this crate parses. |
| `project` | yes | The kind of project the marker names. `evidence-authoring` is the only kind today. |

`evidencectl new` writes exactly two lines, held to that text by
`crates/registry-evidence-authoring/src/marker.rs`:

```yaml
version: 1
project: evidence-authoring
```

## An authored question

One document under `questions/` states what is asked, of which subjects, from
which source, and which governed concepts the answer carries. This is a
complete question, from the fixtures in `crates/registry-evidencectl/src/authoring.rs`:

```yaml
id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
```

### Identity and text

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | The question's local name, which must equal the stem of the document's own filename, so `id: adult-status` is read from `questions/adult-status.yaml`. Lowercase local identifier. |
| `purpose` | yes | The purpose a caller must state to receive this answer. Lowercase local identifier. |
| `question` | yes | The question in words, for a human reviewing the project. Non-empty, at most 512 bytes, no control characters. |

A lowercase local identifier starts with `a` through `z`, is at most 64 bytes,
and continues with lowercase letters, digits, `.`, `_`, or `-`. That spelling
is the one the form accepts wherever an author names something: question `id`
and `purpose`, subject `role`, `selector`, and `profile`, fact `name`, answer
`concept`, and a `source.ref`.

Two names the form accepts can still compose into one it refuses. A question
with more than one subject compiles a selector profile named
`local-subject-{id}-{role}-v1`, and `validate_named_map` in
`crates/registry-evidence/src/config.rs` holds every named-map key,
`selectorProfiles` included, to a 128-byte local identifier, so a 64-byte `id`
beside a 64-byte `role` produces a 146-byte key the bundle check refuses. The
compile measures nothing it generates, and the refusal says only that a local
identifier is invalid, naming neither the question, nor the role, nor the
length. A single-subject question's profile name reaches 81 bytes and a
generated source name 77, so the multi-subject form is the only one that can
cross the ceiling.

### Subjects

A question is asked about one party or about several. Write `subject` for one,
or `subjects` for a list of 1 to 8. Declaring both, or neither, is rejected.

| Key | Required | Meaning |
|---|---|---|
| `subject` | one of the two | A single party. |
| `subjects` | one of the two | 1 to 8 parties. |
| `subject.role` | yes | What this party is to the question. Unique across the question's subjects. |
| `subject.selector` | yes | The request field carrying this party's identifier. |
| `subject.profile` | no | The selector profile the field belongs to. A question that names an `operation` must omit it, because `evidencectl` derives the profile from the operation. A question that names a `source.ref` may omit it only when exactly one alternative of that source's selector input for this role lists this field; no match and two matches are refused alike, so a field two profiles expose has to name its profile. |
| `subject.source` | no | Inline `operation` only. `true` selects this role to supply a path selector and `false` excludes it. Omit it when the field names one role unambiguously. When several roles use the same path field, exactly one must be `true`. A question that names a `source.ref` must omit it. |
| `subject.derivation` | no | Whether this party's selector value is offered to the derivation program. Defaults to `false`. |

`subjects[]` carries the same five keys as `subject`.

A question that names a `source.ref` has to reach its subjects through that
source: `compile_referenced_subjects` in
`crates/registry-evidencectl/src/authoring.rs` rejects a subject the source
does not use and that is not declared for derivation. Use is narrower than the
match that settles the profile. `source_uses_subject` requires the matched
alternative's `fields` to hold the subject's selector and nothing beside it,
and it runs however the profile was settled, so an alternative listing a second
field is refused and writing `subject.profile` out does not rescue it. A second
pass then requires each source role to be selected by exactly one subject. An
inline `operation` question is held to none of this: its subjects are compared
with the operation's own path parameters instead, as the Source section
describes.

A two-party question declares both roles and lets the source consume both
selectors:

```yaml
subjects:
  - role: child
    selector: child_id
  - role: candidate-parent
    selector: candidate_id
```

### Source

A question reads either from a source the project already defines, or from one
operation of the project's own OpenAPI description together with the facts it
projects out of the response.

| Key | Required | Meaning |
|---|---|---|
| `source.ref` | one of the two | The name of a definition under `sources/`. A question using `ref` declares no `facts` and no `collectionBounds`. |
| `source.operation` | one of the two | One `operationId` from `source.openapi.yaml`. Non-empty, at most 256 bytes, no control characters. Compiles for a local run only. |
| `source.facts` | with `operation` | 1 to 16 values projected out of the response. |
| `source.collectionBounds` | with a collection | Up to 16 pointers, each bounding one array the facts walk into. |

Declaring both forms, or neither, is rejected. The two do not reach the same
destination. A question a deployment build can compile names a `source.ref`; an
inline `operation` serves a local run and stops there. `compile_plan` in
`crates/registry-evidencectl/src/authoring.rs` takes the inline branch as soon
as one question omits `source.ref`, and that branch compiles each inline
question's source against the loopback HTTP origin `exact_loopback_server`
reads out of the description, with an authentication kind of `none` written
beside it. `render_production_bundle` then replaces the bundle's whole
`sources` object with what those plans produced, so the governance a deployment
build is given cannot substitute an authenticated source, and
`validate_production_sources` refuses a production source that is not
authenticated HTTPS. A `source.openapi.yaml` that declares the HTTPS server
such a source would need never reaches that check: `exact_loopback_server`
refuses it while the plan is still being compiled.

An `operationId` must resolve to exactly one operation, and that operation must
be a GET; a match on any other method is refused with the same finality as a
match on none. What it resolves to is read under the same closed profile the
document is: the selected path item carries only `get` and `parameters`, and
the operation itself only `operationId`, `parameters`, and `responses`, so an
ordinary `summary` or `description` beside them is refused, and so are an
operation-level `security`, a request body, and `servers` on either the path
item or the operation.

The selector fields named by that operation's path and the operation's
parameters are then required to be the same set. A field used by one subject
selects that role by default. When several roles use the same path field,
exactly one must declare `source: true`; the others are derivation-only. A
subject not selected for the path is accepted only when it declares
`derivation: true`; that subject remains available to the reviewed derivation
but is omitted from the source selector inputs and path bindings.
`exact_path_selectors` in `crates/registry-evidencectl/src/authoring.rs` reads
the path item's `parameters` and the operation's own as one list and compares
its length to the number of distinct path selector fields before it reads any of them, so
an extra parameter of any kind, a query filter beside the selector included,
is refused for the count alone. Each parameter is closed to `name`, `in`,
`required`, and `schema`, so an ordinary `description` beside them, and a
`$ref` to a shared parameter component, are unsupported keys; its `schema` is
closed to `type`, so a `format`, a `pattern`, or a `minLength` is refused the
same way. What is left must read `in: path`, `required: true`, and
`schema.type: string`, and the parameter names must equal the path-bound
subject selector names exactly, each named once. A path-bound subject may also
declare `derivation: true`; it then participates in both the fixed source read
and the derivation.

The path that operation is written under is held to the same shape. It starts
with `/` and not `//`, holds no `?`, `#`, or `\`, and no segment of it is
empty, `.`, or `..`. Each selector appears as `{selector}` occupying one
complete segment exactly once, and the path's own count of `{` and of `}` each
equal the number of selectors, so `/people/{person_id}` is accepted and
`/people/id-{person_id}` is not. A question that names a `source.ref` is held
to none of this: its selectors are read against that source's declared selector
inputs instead.

### Facts

One fact names a value and the place it is read from.

| Key | Required | Meaning |
|---|---|---|
| `facts[].name` | yes | The name the derivation reads the value under. Lowercase local identifier, unique within the question. |
| `facts[].path` | yes | An extended JSON Pointer into the response. Unique within the question, starts with `/`, at most 256 bytes, no control characters, and naming a scalar leaf the response schema offers. |
| `facts[].combine` | yes | `exactly-one` or `collect`. |

A path walks into an array by writing `*` for the element, so
`/events/*/status` reads the `status` of every element of `/events`. A path
that visits a collection must say `combine: collect`; a path that visits none
must say `combine: exactly-one`. Either mismatch is rejected by name, so a
finding says which fact disagrees with its own path.

A well-formed path still has to land on a value the response offers. The leaves
are read from the selected operation's exact `200` `application/json` response
schema, with no `default` or wildcard response standing in for it, and a
container is never one of them.
`crates/registry-evidence-authoring/src/openapi/flatten.rs` produces no leaf
under a `oneOf` or `anyOf`, an `allOf` merging more than one schema, an untyped
or genuinely multi-type node (only `[T, "null"]` is admitted), the unnamed
members of `additionalProperties` or `patternProperties`, an object with no
`properties`, an array with no `items`, a repeated `$ref` in a cycle, or past
16 pointer segments.

A selected scalar also carries its own closed bounds, and the compile stops
where it does not: an integer needs both `minimum` and `maximum`, or an `enum`
or a `const`; a string needs `minLength` and `maxLength`, or a `format`, an
`enum`, or a `const`. The finding names the pointer and asks for those bounds
in the retained OpenAPI document, because that is the one place a fact's shape
is stated.

### Bounding collections

`source.collectionBounds` maps a pointer to the largest number of elements the
project will read from the array at that pointer. Each `*` in a fact path
contributes the pointer that stands before it, so `/events/*/status` needs a
bound at `/events`. A pointer is bounded the same way a fact path is, and its
value is an integer in 1 to 256.

One fact is bounded by the product of every bound its own path walks through,
and that product may not exceed 256 either. Two nested bounds of 17 are each
inside the range and together are not, so a path that visits more than one
collection has to be read as a multiplication.

```yaml
source:
  operation: listRecordEvents
  facts:
    - name: event_statuses
      path: /events/*/status
      combine: collect
    - name: event_times
      path: /events/*/occurredAt
      combine: collect
  collectionBounds:
    /events: 4
```

The declared pointers and the collections the facts reach are compared as sets,
so a bound that is missing and a bound nothing reaches are both rejected, and
both are named. A question whose facts visit no collection therefore writes
`collectionBounds: {}` or leaves the key out.

### Answers

`answers` lists 1 to 16 governed concepts, each with a unique `concept` name.

| Key | Required | Meaning |
|---|---|---|
| `answers[].concept` | yes | The concept's local name. Lowercase local identifier, unique within the question. |
| `answers[].id` | for production | The stable URI a relying party matches on. A local compile invents one; a production compile requires it and refuses a disposable `urn:registrystack:evidence:local:` value. Bounded as a URI by the bundle check, not by the form. |
| `answers[].type` | yes | `boolean`, `controlled-category`, `bounded-integer`, or `reviewed-structured-value`. |
| `answers[].values` | for `controlled-category` | 2 to 32 unique values, each non-empty, at most 64 bytes, no control characters, and each spelled as a codelist code. |
| `answers[].minimum`, `answers[].maximum` | for `bounded-integer` | Both required together, both within plus or minus 9007199254740991, and `minimum` no greater than `maximum`. |
| `answers[].schema` | for `reviewed-structured-value` | Exactly one `schemas/<name>.yaml` file: two path components, the first `schemas`, the extension `yaml`. The file must exist, and its own top-level `$id` must be an absolute URI, which becomes the concept's `schema` constraint under the same deferred bound. |
| `answers[].maximumSerializedBytes` | for `reviewed-structured-value` | The serialized ceiling for the value, in 1 to 65536. |
| `answers[].sdJwtVc` | optional with `reviewed-structured-value` | How this answer appears in the SD-JWT VC serialization. No other answer type accepts it. |

Each type accepts only the keys its own row lists. A `boolean` answer declares
no `values`, no bounds, no `schema`, no `maximumSerializedBytes`, and no
`sdJwtVc`. A `controlled-category` answer declares no numeric bounds and no
`sdJwtVc`. A `bounded-integer` answer declares no `values` and no `sdJwtVc`. A
`reviewed-structured-value` answer declares no scalar constraints.

A `controlled-category` answer's `values` are held to a second grammar the form
does not state. `compile_concept` writes them into a generated codelist as its
codes, and `validate_code` in `crates/registry-evidence/src/bundle.rs` requires
each code to begin with an ASCII alphanumeric and to continue with ASCII
alphanumerics, `.`, `_`, `:`, or `-`. A value such as `New York` satisfies
every rule in the Answers table and is then refused as an invalid codelist code.
The other three types carry no second grammar: a `boolean` compiles to an empty
constraint object, a `bounded-integer` states the same bound in both layers,
and a `reviewed-structured-value`'s named schema is the only authority on its
value's shape.

Four URIs an authoring project writes are bounded only after the form has
accepted them. `validate_uri` in `crates/registry-evidence/src/config.rs` holds
a URI to 1 through 512 bytes and then requires it to parse, and it is what
reads an answer `id`, the `$id` of the file `answers[].schema` names,
`governance.requirement`, and `governance.evidenceType`. The form reads none of
the four: `validate_answer` never looks at `answer.id`, and `validate_question`
never opens `governance` at all. A `controlled-category` answer's `id` is
measured twice over, because the compile derives that concept's category scheme
as `{id}:categories` and holds the derived URI to the same 512 bytes.

### Disclosure

| Key | Required | Meaning |
|---|---|---|
| `disclosure.allow` | yes | Exactly the concepts the question declares, each once. |

The list is checked against the declared concepts as a set and by length, so a
missing concept, an unknown one, and a repeated one are all rejected. Writing
it out is the point: a concept reaches a response because an author named it
here, never because it appeared under `answers`.

### Response formats and the SD-JWT VC projection

| Key | Required | Meaning |
|---|---|---|
| `responseFormats` | no | Defaults to `[signed-jws]`. Must contain `signed-jws` exactly once, and may add `sd-jwt-vc` once. |
| `answers[].sdJwtVc.claim` | with `sdJwtVc` | The claim name the answer is projected under. At most 64 bytes, starts with an ASCII letter, continues with ASCII letters, digits, or `_`, unique within the question, and not one of the 24 names the response format has already given a meaning. |
| `answers[].sdJwtVc.disclosure` | with `sdJwtVc` | `top-level` is the only value. |

An `sdJwtVc` projection without `sd-jwt-vc` in `responseFormats` is rejected.
The reserved claim names are listed in `validate.rs`: the registered JWT and
SD-JWT VC claims, and the Evidence payload's own names.

```yaml
answers:
  - concept: birth_certificate
    type: reviewed-structured-value
    schema: schemas/birth-certificate.yaml
    maximumSerializedBytes: 2048
    sdJwtVc:
      claim: birthCertificate
      disclosure: top-level
responseFormats: [signed-jws, sd-jwt-vc]
```

### The derivation program

| Key | Required | Meaning |
|---|---|---|
| `derivation` | yes | The Rhai program that turns facts into concepts, under `derivations/`. Each question names its own file; two questions pointing at one program is rejected. |

`crates/registry-evidence-authoring/src/derivation.rs` compiles the program
without running it and holds it to three rules: function names are unique, the
name `derive` is reserved for the generated concept binding, and the program
declares exactly one `answer(facts, selectors, context)` with those three
parameters. Function discovery reads the parsed syntax tree, so a name inside
a string or a comment is not an entry point.

```text
fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    let adult_on = add_calendar_years(born, 18);
    #{is_adult: compare_dates(context.legal_local_date, adult_on) >= 0}
}
```

### Governance

`governance` is optional for a local compile and required for a production one.
Omitting it lets `evidencectl` invent disposable
`urn:registrystack:evidence:local:` identifiers, a UTC observation timezone,
and a 300 second validity, which are usable for a fixture run and refused for a
deployment. Six of these keys become the `requirements[]` key of the same name
in `bundle/evidence.yaml`. The other two are renamed: `governance.requirement`
becomes `requirements[].id`, and `governance.disclosureFamilies` becomes
`requirements[].disclosureGuard.families`.

| Key | Required | Meaning |
|---|---|---|
| `governance.requirement` | with `governance` | The requirement URI this question answers. Under the deferred URI bound the Answers section states. |
| `governance.kind` | with `governance` | `criterion`, `information-requirement`, or `constraint`. Without `governance`, a question with one boolean concept compiles as `criterion` and anything else as `information-requirement`. |
| `governance.referenceFrameworks` | with `governance` | The governed legal or procedural framework URIs. The form itself accepts any list, an empty one included; `RequirementConfig::validate` in `crates/registry-evidence/src/config.rs` requires 1 to 16 unique entries, each an absolute URI of at most 512 bytes, so an empty list, a repeated framework, and a seventeenth entry are refused by the bundle check instead. |
| `governance.evidenceType` | with `governance` | The exact Evidence Type URI. Under the same deferred URI bound. |
| `governance.validitySeconds` | with `governance` | The assertion lifetime, in seconds. The form itself accepts any whole number; the bundle grammar bounds it to 1 through 31536000, and a deployment caps it again at its own `signing.maximumAssertionValiditySeconds`. |
| `governance.observationTimezone` | with `governance` | The IANA timezone the derivation's legal local date and time are computed in. |
| `governance.fixtures` | with `governance` | Exactly one project-relative `fixtures/<name>.yaml` file, which must exist. Its content is a contract the compile never reads. |
| `governance.disclosureFamilies` | with `governance` | The disclosure family URIs this question's concepts belong to. `DisclosureGuard::validate` bounds this list exactly as `RequirementConfig::validate` bounds `referenceFrameworks`. |

A production compile also requires a stable `id` on every answer, and refuses a
disposable local identifier anywhere in `requirement`, `referenceFrameworks`,
`evidenceType`, `disclosureFamilies`, or an answer `id`.

`governance.fixtures` is the widest deferral on this table.
`validate_production_inputs` confirms the two path components, the `yaml`
extension, and that the file is there, and never opens it.
`validate_fixture_coverage` in `crates/registry-evidence/src/bundle.rs`, which
`Bundle::load` reaches for every requirement naming a fixture, is what states
the contract: the file declares `synthetic_only: true` and a `cases` sequence
of 1 to 256 entries, each carrying a unique string `id` of 1 to 128 bytes, and
those ids have to cover all eight categories. Four are exact ids, `positive`,
`no-match`, `source-failure`, and `anti-reconstruction`, and four are prefixes,
`negative`, `boundary`, `missing`, and `ambiguous`. A fixture missing one of
them compiles and is refused by the bundle check.
[The fixture reference](../request-adapter/deployment-projects/FIXTURES.md)
describes what a case holds.

Authored `governance` is also where two questions can collide, and the compile
is not what catches it. It reads one question at a time; `BundleConfig::validate`
in `crates/registry-evidence/src/config.rs` then requires that requirement
identifiers, Evidence Type identifiers, and answer concept identifiers each be
unique across the whole bundle, and that no two requirements share a disclosure
family. Two questions that each satisfy every rule on this page therefore
compile, and the `evidence` binary's bundle check refuses what they produced.
That check is reached either way, and this is where the bundle grammar's bounds
on an authored list are applied as well: a local compile asks the `evidence`
binary to check the staged generation, and a deployment build asks it to check
the staged bundle, each before anything is published, so neither path publishes
what the grammar refuses. Without `governance` there is nothing to collide:
`evidencectl` derives `requirement:{id}`, `evidence-type:{id}`,
`disclosure-family:{id}`, and
`concept:{question_id}:{concept}` from the question's own id.

### Local access policies

An optional document under `access/policies/<id>.yaml` groups authored
questions for one local requester policy. Access policy documents affect the
local development authority profiles that `evidencectl` compiles. They are not
part of the production authoring form or copied into a production target.

The document is closed and has exactly these keys:

```yaml
version: 1
id: age-checks
questions: [adult-status, age-bracket]
```

`version` must be `1`. `id` follows the lowercase local-identifier grammar and
must equal the filename stem. `questions` contains 1 through 128 existing
question ids in strictly increasing lexical order, which also makes the list
unique. The project may contain 1 through 128 policy files, and every entry in
`access/policies/` must be an `<id>.yaml` regular file no larger than 64 KiB.

Use the command when adding a policy so it validates question ids and writes
the sorted closed document without replacing an existing file:

```sh
evidencectl access policy add age-checks \
  --question adult-status \
  --question age-bracket
```

When at least one explicit policy exists, local compilation replaces the
single implicit all-question caller profile with one authority profile per
policy. A project that has `access/clients/` but no access policy is rejected.

## Bounds at a glance

Every ceiling the authoring form applies, with the file that states it.

| Limit | Value | Stated in |
|---|---|---|
| Questions per project | 128 | `layout.rs` |
| Question document size | 64 KiB | `layout.rs` |
| Project marker size | 4 KiB | `layout.rs` |
| OpenAPI description size | 16 MiB | `layout.rs` |
| Derivation program size | 64 KiB | `layout.rs` |
| Subjects per question | 1 to 8 | `validate.rs` |
| Question text | 512 bytes | `validate.rs` |
| Concepts per question | 1 to 16 | `validate.rs` |
| Facts per question | 1 to 16 | `validate.rs` |
| Fact path and collection pointer | 256 bytes | `validate.rs` |
| Selectable leaf depth | 16 pointer segments | `openapi/flatten.rs` |
| Collection bounds per question | 16 | `validate.rs` |
| Collection bound value | 1 to 256 | `validate.rs` |
| Controlled-category values | 2 to 32, each 64 bytes | `validate.rs` |
| Bounded-integer bounds | plus or minus 9007199254740991 | `validate.rs` |
| Structured answer serialized size | 1 to 65536 bytes | `validate.rs` |
| Local identifier | 64 bytes | `validate.rs` |
| SD-JWT VC claim name | 64 bytes | `validate.rs` |
| Operation identifier | 256 bytes | `validate.rs` |
| Local public signing JWK | 64 KiB | `registry-platform-crypto` |
| Access policies per project | 1 to 128 | `authoring.rs` |
| Questions per access policy | 1 to 128 | `authoring.rs` |
| Access policy document size | 64 KiB | `layout.rs` |

## Complete key-path inventory

Every key path the generated authoring schemas define, in one machine-checked
list. A property is written `name`, an array item `name[]`, and a map value
`name.*`.

`products/evidence/scripts/check-config-key-paths.sh` fails when either block
and its schema disagree in either direction, so a key added to the authoring
model cannot ship without a line here, and a line here cannot outlive its key.
The blocks are generated. After regenerating the schemas with
`products/evidence/scripts/check-authoring-schema.sh`, run
`products/evidence/scripts/check-config-key-paths.sh --write`, review the diff,
and document the new keys in this page's prose.

Parity is the same rule the frozen contracts are held to, and it is not the
same promise. These schemas are adopter tooling. A key path leaving this
inventory is a tooling change, not a break in the Version 1 configuration
contract.

### `questions/<name>.yaml`

<!-- evidence-authoring-question-key-paths:start -->
```text
answers
answers[]
answers[].concept
answers[].id
answers[].maximum
answers[].maximumSerializedBytes
answers[].minimum
answers[].schema
answers[].sdJwtVc
answers[].sdJwtVc.claim
answers[].sdJwtVc.disclosure
answers[].type
answers[].values
answers[].values[]
derivation
disclosure
disclosure.allow
disclosure.allow[]
governance
governance.disclosureFamilies
governance.disclosureFamilies[]
governance.evidenceType
governance.fixtures
governance.kind
governance.observationTimezone
governance.referenceFrameworks
governance.referenceFrameworks[]
governance.requirement
governance.validitySeconds
id
purpose
question
responseFormats
responseFormats[]
source
source.collectionBounds
source.collectionBounds.*
source.facts
source.facts[]
source.facts[].combine
source.facts[].name
source.facts[].path
source.operation
source.ref
subject
subject.derivation
subject.profile
subject.role
subject.selector
subject.source
subjects
subjects[]
subjects[].derivation
subjects[].profile
subjects[].role
subjects[].selector
subjects[].source
```
<!-- evidence-authoring-question-key-paths:end -->

### `evidence-project.yaml`

<!-- evidence-authoring-project-marker-key-paths:start -->
```text
project
version
```
<!-- evidence-authoring-project-marker-key-paths:end -->
