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
rejection rather than something carried along. All names below are exact and
case-sensitive.

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

Only the marker and a question have a Rust type behind them, so only those two
carry a generated schema. `crates/registry-evidence-authoring/src/schema.rs`
states the reason: a schema written by hand for one of the other parts would be
the drift the generated pair exists to prevent. The key-path inventory at the
end of this page is therefore the marker and the question, and nothing else.

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

### Subjects

A question is asked about one party or about several. Write `subject` for one,
or `subjects` for a list of 1 to 8. Declaring both, or neither, is rejected.

| Key | Required | Meaning |
|---|---|---|
| `subject` | one of the two | A single party. |
| `subjects` | one of the two | 1 to 8 parties. |
| `subject.role` | yes | What this party is to the question. Unique across the question's subjects. |
| `subject.selector` | yes | The request field carrying this party's identifier. |
| `subject.profile` | no | The selector profile the field belongs to. A question that names an `operation` must omit it, because `evidencectl` derives the profile from the operation. |
| `subject.derivation` | no | Whether this party's selector value is offered to the derivation program. Defaults to `false`. |

`subjects[]` carries the same four keys as `subject`.

Every subject has to be reachable: `evidencectl` rejects a subject that the
source does not use and that is not declared for derivation. A two-party
question declares both roles and lets the source consume both selectors:

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
| `source.operation` | one of the two | One `operationId` from `source.openapi.yaml`. Non-empty, at most 256 bytes, no control characters. |
| `source.facts` | with `operation` | 1 to 16 values projected out of the response. |
| `source.collectionBounds` | with a collection | Up to 16 pointers, each bounding one array the facts walk into. |

Declaring both forms, or neither, is rejected. An `operationId` must resolve to
exactly one operation, and that operation must be a GET; a match on any other
method is refused with the same finality as a match on none.

### Facts

One fact names a value and the place it is read from.

| Key | Required | Meaning |
|---|---|---|
| `facts[].name` | yes | The name the derivation reads the value under. Lowercase local identifier, unique within the question. |
| `facts[].path` | yes | An extended JSON Pointer into the response. Unique within the question, starts with `/`, at most 256 bytes, no control characters. |
| `facts[].combine` | yes | `exactly-one` or `collect`. |

A path walks into an array by writing `*` for the element, so
`/events/*/status` reads the `status` of every element of `/events`. A path
that visits a collection must say `combine: collect`; a path that visits none
must say `combine: exactly-one`. Either mismatch is rejected by name, so a
finding says which fact disagrees with its own path.

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
| `answers[].id` | for production | The stable URI a relying party matches on. A local compile invents one; a production compile requires it and refuses a disposable `urn:registrystack:evidence:local:` value. |
| `answers[].type` | yes | `boolean`, `controlled-category`, `bounded-integer`, or `reviewed-structured-value`. |
| `answers[].values` | for `controlled-category` | 2 to 32 unique values, each non-empty, at most 64 bytes, no control characters. |
| `answers[].minimum`, `answers[].maximum` | for `bounded-integer` | Both required together, both within plus or minus 9007199254740991, and `minimum` no greater than `maximum`. |
| `answers[].schema` | for `reviewed-structured-value` | Exactly one `schemas/<name>.yaml` file: two path components, the first `schemas`, the extension `yaml`. The file must exist, and its own top-level `$id` must be an absolute URI. |
| `answers[].maximumSerializedBytes` | for `reviewed-structured-value` | The serialized ceiling for the value, in 1 to 65536. |
| `answers[].sdJwtVc` | no | How this answer appears in the SD-JWT VC serialization. |

Each type accepts only the keys its own row lists. A `boolean` answer declares
no `values`, no bounds, no `schema`, no `maximumSerializedBytes`, and no
`sdJwtVc`. A `controlled-category` answer declares no numeric bounds. A
`bounded-integer` answer declares no `values`. A `reviewed-structured-value`
answer declares no scalar constraints.

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
| `governance.requirement` | with `governance` | The requirement URI this question answers. |
| `governance.kind` | with `governance` | `criterion`, `information-requirement`, or `constraint`. Without `governance`, a question with one boolean concept compiles as `criterion` and anything else as `information-requirement`. |
| `governance.referenceFrameworks` | with `governance` | The governed legal or procedural framework URIs. |
| `governance.evidenceType` | with `governance` | The exact Evidence Type URI. |
| `governance.validitySeconds` | with `governance` | The assertion lifetime, in seconds. The form itself accepts any whole number; the bundle grammar bounds it to 1 through 31536000, and a deployment caps it again at its own `signing.maximumAssertionValiditySeconds`. |
| `governance.observationTimezone` | with `governance` | The IANA timezone the derivation's legal local date and time are computed in. |
| `governance.fixtures` | with `governance` | Exactly one project-relative `fixtures/<name>.yaml` file, which must exist. |
| `governance.disclosureFamilies` | with `governance` | The disclosure family URIs this question's concepts belong to. |

A production compile also requires a stable `id` on every answer, and refuses a
disposable local identifier anywhere in `requirement`, `referenceFrameworks`,
`evidenceType`, `disclosureFamilies`, or an answer `id`.

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
| Collection bounds per question | 16 | `validate.rs` |
| Collection bound value | 1 to 256 | `validate.rs` |
| Controlled-category values | 2 to 32, each 64 bytes | `validate.rs` |
| Bounded-integer bounds | plus or minus 9007199254740991 | `validate.rs` |
| Structured answer serialized size | 1 to 65536 bytes | `validate.rs` |
| Local identifier | 64 bytes | `validate.rs` |
| SD-JWT VC claim name | 64 bytes | `validate.rs` |
| Operation identifier | 256 bytes | `validate.rs` |

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
and document the new keys in the prose above.

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
subjects
subjects[]
subjects[].derivation
subjects[].profile
subjects[].role
subjects[].selector
```
<!-- evidence-authoring-question-key-paths:end -->

### `evidence-project.yaml`

<!-- evidence-authoring-project-marker-key-paths:start -->
```text
project
version
```
<!-- evidence-authoring-project-marker-key-paths:end -->
