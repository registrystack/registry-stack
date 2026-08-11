# Evidence request-adapter API

Status: Implemented Version 1 trusted request-adapter ABI

This document defines the Version 1 API visible to reviewed source-adapter
scripts. It is intentionally smaller than Rhai's standard library. The host is
Rust. Adapter scripts cannot perform I/O or choose transport authority.

This contract is the `registry.evidence.request-adapter/v1` ABI and is bound to
the Evidence bundle contract Version 1. A
source does not carry a redundant `adapterAbiVersion` field unless the product
later demonstrates a need to run multiple adapter ABIs under one bundle
version.

`evidencectl build` is an authoring-to-bundle compiler, not another adapter
runtime. It carries reviewed scripts and their referenced schemas into one
closed candidate, then asks the real `evidence` binary to compile and evaluate
them. Production build metadata cannot add an ABI entry point, helper,
transport capability, source call, or script-selected behavior.

## Complete Version 1 surface

This inventory is the complete adopter-facing Version 1 script surface. It
defines all five entry points, every host-provided helper, the pinned Rhai
syntax, result types, resource bounds, and forbidden constructs. Adopters do
not need to inspect the Rust implementation to determine whether a script is
supported.

```text
prepare(selectors: map, context: {parameters: map, prior_facts: map}) -> RequestParts
extract(response: JSON, context: {parameters: map, prior_facts: map}) -> LookupResult
derive(facts: map, selectors: map, evaluation_context: map)
    -> array<DerivedConceptValue>
prepare_batch(items: array<{slot: int, selectors: map}>, context: {parameters: map})
    -> RequestParts
extract_batch(response: JSON, context: {parameters: map, slots: array<int>})
    -> array<{slot: int, result: LookupResult}>
```

Version 1 uses one shared deterministic helper catalogue for `prepare`,
`extract`, `prepare_batch`, `extract_batch`, and `derive`. The helpers are pure and provide no external
authority. Capability separation instead comes from the values Rust supplies
and the closed result validator for each entry point. For example, preparation
receives no evaluation context or codelist handles, and `RequestParts` rejects
typed derivation values.

The compiler accepts exactly one function with the required entry-point name
and arity. It rejects top-level executable statements, an absent or overloaded
entry point, function pointers, data-derived dispatch, anonymous functions,
and closures. Statically named, bounded same-file helper functions are allowed;
Rust invokes only the declared entry point.

## Entry points

An ordinary source has two separately compiled adapter scripts, and each
requirement has one separately compiled derivation script. An optional HTTP
batch block names two additional separately compiled scripts:

```text
prepare(selectors: map, context: {parameters: map, prior_facts: map}) -> RequestParts
extract(response: JSON, context: {parameters: map, prior_facts: map}) -> LookupResult
derive(facts: map, selectors: map, evaluation_context: map)
    -> array<DerivedConceptValue>
prepare_batch(items: array<{slot: int, selectors: map}>, context: {parameters: map})
    -> RequestParts
extract_batch(response: JSON, context: {parameters: map, slots: array<int>})
    -> array<{slot: int, result: LookupResult}>
```

- All five entry points run with fresh state on every invocation.
- Inputs are isolated per-invocation copies constructed by Rust. A script may
  mutate a local nested map, array, or string, but that mutation cannot affect
  the bundle, a later invocation, or the other adapter stage.
- Scripts compile at startup. Top-level executable statements are forbidden.
- Named same-file helper functions are allowed, but Rust invokes only the
  declared entry point. Calls remain statically named in reviewed source.
- Preparation runs after successful authorization and durable access-attempt
  audit, but before credential resolution or source access.
- `context.parameters` is the source's closed startup-validated configuration.
  `context.prior_facts` is empty for single and search stages and is exactly the
  schema-validated search FactSet for the fixed fetch stage.
- Extraction receives neither selectors nor prepared request parts.
- Batch preparation receives one to sixteen ordered exact maps with `slot` and
  `selectors`, plus context with exactly `parameters`. Each opaque non-negative
  integer slot is Rust-issued and carries correlation only. Each selectors map
  is the ordinary minimized source input for that logical item.
- Batch extraction receives the projected and schema-validated response plus
  context with exactly `parameters` and `slots`. It receives neither selectors
  nor prepared request parts and returns one exact `{slot, result}` map for
  every supplied slot. Result order may differ. Rust restores request order and
  rejects a missing, duplicate, extra, negative, non-integer, or out-of-range
  slot as a source-protocol failure.
- Derivation runs only for `match`, receives only the authorized roles and
  fields declared by the requirement's closed `derivation.selectorInputs`, and
  receives neither the source response nor prepared request parts. A
  derivation that declares no selector inputs receives an empty map.

## Bundle configuration shape

The Version 1 bundle schema adds these exact script-owned fields while keeping
transport authority in the existing source request object:

```yaml
sources:
  source-a:
    transport: http-json
    baseUrl: https://source.example
    posture: record-transformed
    authentication: {kind: static-authorization, tokenRef: secret:file/source-token}
    request:
      method: POST
      path: /v1/search
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs:
        - role: child
          alternatives:
            - {profile: record-reference-v1, fields: [record_reference]}
      prepareScript: adapters/source-a-prepare.rhai
      adapterParameters: {resultLimit: 2}
      adapterParametersSchema: schemas/source-a-parameters.schema.yaml
      preparationLimits:
        query: forbidden
        jsonBody: required
        maximumJsonDepth: 12
        maximumCollectionItems: 32
        maximumStringBytes: 512
        maximumNormalizedBytes: 8192
      projection: [/total, /results]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/source-a-response.schema.yaml
    extractScript: adapters/source-a-extract.rhai
    factSchema: schemas/source-a-facts.schema.yaml
    batch:
      maximumItems: 16
      prepareScript: adapters/source-a-batch-prepare.rhai
      extractScript: adapters/source-a-batch-extract.rhai
      responseSchema: schemas/source-a-batch-response.schema.yaml
      projection: [/results/*/slot, /results/*/outcome, /results/*/facts]
requirements:
  - id: urn:example:requirement:relationship:v1
    derivation:
      script: derivations/relationship.rhai
      selectorInputs:
        - role: candidate
          alternatives:
            - {profile: person-reference-v1, fields: [person_reference]}
      parameters: {matching_policy: exact-reference-v1}
```

`request.selectorInputs` controls preparation exposure.
`derivation.selectorInputs` independently controls derivation exposure. Every
alternative must exactly match one declared requirement role, profile, and
field set. Rust rejects a missing, surplus, unauthorized, or incompatible
binding at startup. `prepareScript` and `extractScript` are symmetric,
separately compiled entry points; neither is a transport plugin.

The optional `batch` block is eligible only on a fixed-path `http-json` source
under both bundle and runtime `source-batch` capability. Its scripts cannot
change the ordinary source's method, origin, path, authentication, headers,
TLS, redirect policy, timeout, response limit, concurrency semaphore, or
preparation limits. Its response uses the batch projection and schema, but
every match still validates against the ordinary `factSchema`. SQLite, path
templates, multi-stage acquisitions, and batches above `maximumItems` use the
ordinary entry points sequentially in request order.

The ceiling of at most two minimally projected results, which lets one bounded
request separate a unique match from ambiguity, is governed adapter policy. Its
value is declared by the reviewed source configuration, here
`adapterParameters: {resultLimit: 2}`, and rendered into the request by that
source's `prepareScript`. Rust enforces only the generic one-request-per-stage,
projection, and response bounds around it. The adapter's result limit is not a
Rust domain rule, built-in operation, or property of any source product.

## Inputs

For `prepare`, `selectors` contains only roles, profiles, and fields declared
by the source's closed `selectorInputs` contract. Rust has already validated
and authorized them. Surplus request fields are not passed to preparation.
Scripts may rely on this exact shape and should not repeat role, profile,
field, type, or bound validation. Host-shape violations are Rust contract
failures and belong in host negative tests. A script still validates
requirement-specific semantic relationships that Rust cannot infer, such as a
provider status or a governed namespace agreement.

For `derive`, `selectors` contains only the roles, profiles, and fields declared
by that requirement's closed derivation selector-input contract. Rust resolves
those values from the already authorized requirement subjects. A relationship
requirement can therefore retrieve a record using only a child selector and
compare an extracted parent fact with only the separately authorized
candidate-parent reference. Derivation cannot inspect the child selector when
it did not declare it, the complete HTTP request, bearer token, grant, or
caller-supplied surplus data.

```json
{
  "subject": {
    "profile": "person-demographics-v1",
    "values": {
      "given_name": "Synthetic",
      "family_name": "Subject",
      "birth_date": "2000-02-29"
    }
  }
}
```

Source-adapter `parameters` is non-secret bundle data validated at startup
against a closed JSON Schema. It may contain provider field identifiers and
fixed request constants. It must not contain credentials, tokens, requester
identity, authorization objects, audit handles, or runtime state. The same
parameters are supplied independently to `prepare` and `extract`; neither
invocation can mutate the other's copy.

Derivation parameters remain in `evaluation_context.parameters`, alongside
Rust-owned observation time and codelist handles. They are independent of the
source-adapter parameters unless the reviewed bundle deliberately repeats a
non-secret constant in both closed configurations.

The adapter-parameter conversion is closed:

| JSON form | Rhai form |
|---|---|
| boolean | `bool` |
| integer in the signed 64-bit range | `i64` |
| bounded UTF-8 string | `string` |
| bounded array of permitted forms | `array` |
| bounded object of permitted forms | `map` |

Null, fractional numbers, integers outside the signed 64-bit range, and typed
derivation envelopes such as `{type: "decimal", value: "..."}` are not adapter
parameters. They fail startup validation. No implicit numeric conversion is
performed.

`response` is one bounded JSON response from the fixed source request. Rust
rejects an invalid media type, oversized body, malformed JSON, redirect, or
transport failure before extraction. JSON integers outside the signed 64-bit
range are rejected before Rhai so they cannot silently become imprecise binary
floating-point values. Ordinary fractional JSON numbers remain `f64`; an
adapter must reject one wherever the provider contract requires an integer.

### Response projection

`request.projection` is a Rust-enforced, client-side allowlist applied after
the bounded JSON response is parsed and before it is converted to Rhai. It is
not documentation and does not request provider-side field selection. A source
should also use a provider field-selection feature when one exists, but its
acquisition posture describes what crosses the wire before this local pruning.

Each projection entry is an extended JSON Pointer. Ordinary segments follow
RFC 6901 escaping: `~0` means `~` and `~1` means `/`. The reserved segment `*`
visits every current array element. Numeric array indexes, recursive descent,
filters, predicates, unions, and script-computed projection paths are not
supported. Examples:

```text
/total
/results/*/status
/results/*/declaration/mother.personReference
```

Projection constructs a new JSON tree containing only present selected leaves
and the objects or arrays needed to reach them. Object keys not selected are
dropped. Array order and length are preserved; each selected array element is
projected independently. A missing selected leaf is omitted rather than
invented or treated as `null`, so extraction can distinguish missing data from
an explicit JSON null and fail according to the provider contract. A missing
or mistyped intermediate container is a source-protocol failure before Rhai.
An empty projection, duplicate path, invalid escape, overlapping ancestor and
descendant paths, or path that cannot be reconciled with another selected path
fails bundle validation.

### Declared response shape

Every source declares a required `responseSchema`: a bundle-relative closed
JSON Schema, in the same subset as `adapterParametersSchema` and `factSchema`,
describing the projected tree. Rust validates the projected response against it
after projection and before conversion to Rhai, so a response outside the shape
the adapter was reviewed against never reaches a script; that is a
source-protocol failure like any other.

Two rules differ from the fact and adapter-parameter roles, because the
projected tree is not the wire response:

- It may require fewer members than it declares properties. Projection drops a
  selected leaf the record did not carry, and a page decided ambiguous is never
  read record by record, so a record on that page need not be complete.
- A node may write its type as the pair `[T, "null"]`. A source that reports an
  explicit null where it holds no value has that null carried through
  projection verbatim, and it reaches the script as the same unit marker
  `is_missing` already reads. This is the only union the subset admits, and
  only in this role: a fact and an adapter parameter are never null.

State in the schema what a shape can state: member presence where it is
guaranteed, member types, array bounds and uniqueness, string bounds and
formats, and enumerated or constant values. What remains for the script is what
a shape cannot state, such as how a reported total agrees with the records
returned, page-count arithmetic, and which values must agree with the closed
adapter parameters.

Response byte limits and JSON parsing bounds apply before projection, so the
configured `maximumResponseBytes` describes the wire body Evidence is willing
to read. The projected tree is bounded separately: it must serialize to at most
65,536 bytes, and Rhai input bounds apply to it again. Exact root-envelope
checks in an extraction script may therefore rely on unselected root keys having
been removed. The fixture harness supplies raw provider JSON and runs this same
projection before extraction.

## Output from `prepare`

`RequestParts` has exactly two members:

```text
RequestParts {
  query: array<{name: string, value: string}>,
  body: JSON | null
}
```

- Query pairs remain ordered and may repeat a name.
- Query names and values are lexical strings even when the provider interprets
  them as numbers or booleans. Constants destined for the query string must be
  authored as strings such as `"2"` and `"true"`; JSON body values retain
  their JSON types. Rust performs no implicit query conversion.
- Query names and values are logical raw strings. Names must be non-empty.
  Rust rejects CR or LF in either component and percent-encodes each component
  exactly once as UTF-8. ASCII letters, digits, `-`, `.`, `_`, and `~` remain
  unescaped; every other byte uses uppercase `%HH`, including space as `%20`.
- Rust validates the complete result before acquiring credentials.
- The source definition decides whether query and body output are permitted.
- Unknown members or non-JSON values fail closed.

The following are never script-controlled:

```text
source, origin, URL, path, method, headers, authentication, credentials,
content type, timeout, redirect policy, retry policy, pagination, proxy use,
response limit, concurrency, or number of requests
```

Rust executes only the requirement's closed acquisition: one request for
`single`, or one fixed search followed by one fixed fetch after a unique
validated match. A response cannot supply a source, URL, next page, retry, or
third request.

A bundle may define a Rust-owned `pathTemplate` with tagged complete-segment
`pathBindings`. `from: selector` binds an already validated and authorized
selector field. `from: prior-fact` is valid only on a fetch source and binds a
scalar property required by the preceding search fact schema. Bindings are not
`RequestParts` and are never selected by a script. Values reject `/`, `\`, `%`,
controls, `.` and `..`, then Rust percent-encodes them exactly once. Expansion
cannot change the configured origin, endpoint family, method, credentials, or
request count. A source declares exactly one of fixed `path` or `pathTemplate`.

Bundle-fixed `fixedHeaders` are ordered, non-secret constants. Names are unique
after ASCII case folding and cannot set authentication, host/routing, cookies,
body framing, content length/type, connection, forwarding, proxy, or tracing
headers. Rust adds `Content-Type: application/json` for a JSON body and owns all
authentication and framing headers. Header names and values are bounded and
reject controls, CR, and LF. Scripts cannot observe or modify headers.

The governed bundle and operator runtime split, the Basic, static-Authorization,
static-API-key, and OAuth profiles, the local-only credential-free loopback
boundary, and logical private-CA bindings are defined in
[`deployment-projects/CONFIG.md`](deployment-projects/CONFIG.md). They are
transport contracts, not script capabilities.

### Normalization and exact fixtures

Rust converts the Rhai result into a JSON tree before applying result limits.
For byte limits and deterministic transport, normalized JSON is compact UTF-8
with no insignificant whitespace, object keys in lexical byte order, array
order preserved, canonical JSON integer spelling, and finite floating-point
values rendered in the shortest round-trippable form. Unsupported and
non-finite values fail closed.

Expected `RequestParts` may be an external JSON file in a focused adapter
fixture or the inline `common.expectedRequestParts` object in a complete
project fixture. Both are parsed and compared structurally after normalization.
Source-file whitespace and object-member order are not significant. The order
of the query-pair array is significant. A separate transport assertion compares
the exact encoded query string and exact normalized JSON request-body bytes
sent to the mock. The closed project fixture vocabulary is defined in
[`deployment-projects/FIXTURES.md`](deployment-projects/FIXTURES.md).

## Output from `extract`

`LookupResult` is one member of this closed union:

```text
#{outcome: "no_match"}
#{outcome: "ambiguous"}
#{outcome: "match", facts: <JSON object>}
```

- `no_match` and `ambiguous` contain no `facts` member.
- `match` requires exactly one provider match and facts that satisfy the
  source's closed fact schema.
- Provider protocol inconsistencies must fail. They must not become
  `no_match`, `ambiguous`, or default facts.
- An absent result never represents an authoritative negative assertion.

## Output from `derive`

`derive/3` returns an array of `DerivedConceptValue` maps:

```text
DerivedConceptValue {
  concept_id: string,
  value: supported value
}
```

Each map has exactly `concept_id` and `value`. The array contains at most 16
items. Concept identifiers must equal the selected requirement's declared
output set exactly. Duplicates, missing required concepts, undeclared concepts,
and extra map members fail before evidence construction.

Ordinary JSON-compatible values remain subject to the concept's declared form,
codelist, cardinality, size, range, and precision constraints. Three protected
result forms require host constructors:

- `Decimal` is created only by `decimal(canonical_text)` or
  `parse_decimal(canonical_text)`. It has at most 28 significant digits and 9
  fractional digits and is serialized by Rust as its exact canonical JSON
  string. Rhai floats cannot satisfy a bounded-decimal concept.
- `EntityReferenceSeed` is created only by
  `entity_reference_seed(protected_string)`, whose input is 1 through 512 UTF-8
  bytes. The seed cannot be serialized, logged, compared, or used directly as
  a public identifier. Rust projects it to an audience-scoped reference after
  validation.
- `EntityReferenceSeedList` is an array containing only
  `EntityReferenceSeed` values, with at most 64 items. Rust projects each seed
  independently after the complete output gate passes.

## Selector-aware derivation and relationship decisions

Selector-aware derivation exists for relational assertions whose truth is
defined by both an authoritative source record and an independently authorized
subject role. It does not turn Evidence into a general identity resolver.

Permitted reviewed rules include:

- exact membership of an authoritative opaque identifier in a complete source
  relationship set;
- exact comparison of a closed tuple of authoritative attributes after a
  deterministic, jurisdiction-governed canonicalization implemented in the
  derivation script; and
- direct mapping of an explicit source-owned relationship decision.

The default reference rule is exact opaque-identifier membership. A bundle
using names, dates, transliteration, or another attribute rule must version and
review that rule explicitly and name the resulting concept no more strongly
than the source and governance justify. Probabilistic matching, fuzzy scoring,
candidate ranking, deduplication, and best-match selection remain outside this
ABI.

A derivation may return `false` only after extraction established one uniquely
resolved authoritative record and emitted a schema-required returned-record
identifier, relationship-set contract identifier, reference namespace, and
`relationship_set_complete: true` fact. When the provider returns the lookup
identifier, the derivation declares that authorized lookup selector and
requires exact equality before using the record. The derivation must require
and validate those facts before comparing the candidate. No match, ambiguity,
returned-record mismatch, partial relationship data, namespace mismatch,
or protocol uncertainty stops before the boolean result and never becomes an
authoritative negative assertion. The bundle review must justify how the configured source
contract distinguishes an absent optional relationship from missing data.

In the portable family example, `reference_namespace` and
`relationship_set_contract` are copied from closed adapter parameters and then
compared with closed requirement parameters. That is startup constant
agreement between reviewed bundle sections, not proof that the provider
returned a namespace or contract identifier. If either value can vary by
record, extraction must derive and validate it from projected provider data,
the fact schema must require it, and fixtures must cover mismatch. Governance
must always establish that returned references belong to the declared
namespace and that the relationship set has the claimed meaning and
completeness.

`legal-parent-relationship` is valid only where deployment governance states
that the configured source fields and matching rule establish legal
parentage. The portable OpenCRVS reference therefore uses
`registered-parent-relationship` until that stronger jurisdiction-specific
meaning is documented.

## Version 1 combined language surface

With the Version 1 additions, adapter scripts may construct `bool`, signed
64-bit integer, finite floating-point number, character, string, array, map,
and unit/null values. Adapter outputs must be JSON-compatible; non-finite
numbers and unsupported host-object values are rejected.

The Version 1 ABI pins Rhai 1.25.1 core syntax plus the host registrations in
this document. Rhai syntax does not grant host authority, but its observable
behavior is still part of the reviewed-script contract. The supported surface
includes:

| Surface | Available behavior |
|---|---|
| Bindings | `let`, `const`, reassignment, and local function parameters |
| Control | `if`/`else`, `return`, `throw`, and bounded `for` over arrays |
| Construction | array, map, string, integer, boolean, and unit literals |
| Access | fixed or computed map indexing and bounded non-negative array indexing |
| Boolean | `!`, `&&`, `||`, equality and inequality |
| Integer | arithmetic, bitwise operations, shifts, equality, and ordering |
| Floating point | arithmetic, equality, and ordering, including mixed integer/float operands |
| String | concatenation, substring removal, equality, and ordering |
| Functions | statically named same-file functions within the global call-depth limit |

Only arrays are registered as iterable by the host. Ranges, string slicing,
`switch`, `try`/`catch`, unbounded loop forms, optional chaining, and null
coalescing are rejected by the hardened compiler. A missing map key produces
unit. Map membership uses the registered `map.contains` helper. Equality between
different types returns false and inequality returns true; same-type array or
map comparison is not registered and fails.

Rhai counts a negative array index from the end of the array. The startup source
review therefore routes every index operand through a host-owned index guard,
and a negative index fails the invocation however it was computed rather than
silently addressing another element.

The following are deliberately forbidden:

- `Fn(...)`, function pointers, `.call`, `.curry`, and data-derived dispatch;
- anonymous functions and closures;
- interpolated backtick strings and their implicit value-to-string
  conversion;
- raw string literals such as `#"..."#`, so the source review and the Rhai
  tokenizer can never disagree about where a string ends. `#{` remains the map
  literal;
- a block or an `if` chain used in operand position, because the source review
  could not then classify a following `[` and the index guard would be lost.
  Assign the intermediate result to a mutable local and use that local;
- top-level executable statements;
- `try`/`catch`, so a script cannot suppress the host-private unavailable
  termination raised by `required`; and
- `switch`, `while`, `until`, `loop`, `do`, range construction, string slicing,
  optional chaining, and null coalescing because Version 1 adapters do not
  require them.

Negative tests pin each forbidden construct and the index guard. The operation,
call-depth, expression-depth, string, array, and map ceilings apply to every
otherwise permitted construct.

### Language essentials

| Function or operator | Signature and meaning |
|---|---|
| Integer equality | `i64 == i64`, `i64 != i64` |
| Integer ordering | `<`, `<=`, `>`, `>=` over signed 64-bit integers |
| Integer arithmetic | Binary `+`, `-`, `*`, `/`, `%`, `**`; unary `+` and `-` |
| Integer bitwise | `&`, `|`, `^`, `<<`, `>>` |
| Floating arithmetic | `+`, `-`, `*`, `/`, `%`, `**`, unary `+/-`, equality, and ordering over `f64` |
| Mixed numeric operations | Arithmetic, equality, and ordering between `i64` and `f64` in either operand order |
| Boolean logic | `!bool`, boolean equality and inequality; `&&` and `||` are language control operators |
| String operations | `string + string`, `string + char`, `char + string`, `string - string`, `+=`, equality, and lexical ordering |
| `array.len` | Number of array items as an integer |
| `len(map)` | Number of map entries as an integer |
| `map.contains(name)` | Whether an exact string key exists |
| Array iteration | `for value in array`, bounded by the operation and array limits |
| `type_of(value)` | Pinned Rhai type name, including registered opaque type names |

### Evidence primitives

The opaque types cannot be serialized into
`RequestParts` or extraction facts. Some helpers require handles that only
Rust can supply through derivation context.

| Function | Signature and behavior |
|---|---|
| `parse_date` | `string -> Date`; strict canonical proleptic-Gregorian `YYYY-MM-DD` |
| `parse_instant` | `string -> Instant`; uppercase `T` and `Z`, explicit offset, no leap second, optional 1 to 9 fractional digits, normalized to UTC |
| `parse_integer` | `string -> i64`; optional ASCII `-` and one or more ASCII digits; leading zeroes allowed; rejects `+`, whitespace, non-ASCII digits, fractions, exponents, empty input, and overflow |
| `decimal` | `string -> Decimal`; alias of `parse_decimal` |
| `parse_decimal` | `string -> Decimal`; canonical exact decimal with no `+`, exponent, leading zero, trailing fractional zero, empty fraction, negative zero, NaN, or infinity; zero is exactly `0` |
| `integer_to_decimal` | `i64 -> Decimal` |
| `add_calendar_years` | `(Date, i64) -> Date`; clamps the day at month end, from -1000 through 1000 years inclusive |
| `add_calendar_months` | `(Date, i64) -> Date`; clamps the day at month end, from -12000 through 12000 months inclusive |
| `compare_dates` | `(Date, Date) -> i64`; returns `-1`, `0`, or `1` |
| `compare_instants` | `(Instant, Instant) -> i64`; returns `-1`, `0`, or `1` |
| `days_between` | `(Date, Date) -> i64`; second minus first, from -365000 through 365000 days inclusive |
| `compare_decimals` | `(Decimal, Decimal) -> i64`; returns `-1`, `0`, or `1` |
| `bucket_number` | `(Decimal, array<NumericBucket>) -> string`; requires 1 to 64 contiguous, ordered half-open buckets with unique codes; a value outside every bucket fails the invocation |
| `entity_reference_seed` | `string -> EntityReferenceSeed`; opaque value permitted only through the derived-value gate |
| `codelist_lookup` | `(CodelistHandle, string) -> string or unit`; handle is supplied only by Rust |
| `list_contains` | `(array<scalar>, scalar) -> bool`; supports boolean, integer, string, Date, Instant, and Decimal while keeping types distinct; validates every element before answering |
| `set_contains` | `(array<scalar>, scalar) -> bool`; same scalar types and the same complete validation, and rejects duplicate set entries |
| `array.push(value)` | Appends one value to the invocation-local array within the 256-item bound and returns unit |
| `string.replace(from, to)` | Replaces every exact non-overlapping literal occurrence in the invocation-local string within the 16,384-byte bound and returns unit; no regex or normalization |
| `required` | `(value, safe_error_code) -> value`; unit becomes the closed unavailable outcome; the code must match `[a-z][a-z0-9_]*` and be at most 64 ASCII bytes |
| `required` code handling | The bundle-owned code is validated for shape and then discarded. It documents the reviewed script; it never reaches the public problem, audit, logs, or the raised signal, which is a host-private, unforgeable, uncatchable value |
| `is_missing` | `value -> bool`; true only for unit |
| `get_path` | `(value, json_pointer) -> value`; resolves one RFC 6901 pointer and returns unit when any segment resolves to nothing. Only `~0` and `~1` escapes; an array segment is a non-negative decimal integer with no leading zero. A pointer that is not resolvable syntax, exceeds 256 bytes, or exceeds 16 segments is a script fault and fails the invocation rather than answering missing |

`NumericBucket` has exactly `minimumInclusive: Decimal`,
`maximumExclusive: Decimal`, and `code: string`. `LegalLocalTime` is another
opaque registered type. It is supplied only as
`evaluation_context.legal_local_time`; there is no script constructor.

For context, Rust supplies derivation with exactly `observed_at: Instant`,
`legal_local_date: Date`, `legal_local_time: LegalLocalTime`, validated
`parameters: map`, and `codelists: map<CodelistHandle>`. The authorized
selectors are a distinct explicit derivation argument, not ambient context.
None of those values is supplied to request preparation or extraction except
for preparation's separately minimized selector argument.

`observed_at` is always a runtime-supplied instant normalized to UTC.
`legal_local_date` and `legal_local_time` use the requirement's validated IANA
`observationTimezone`; when that optional field is omitted, they use UTC. A
time-dependent definition should declare its legal timezone explicitly and
pin boundary fixtures rather than rely on the fallback.

For JSON-originating values, `type_of` tags include `"i64"`, `"f64"`,
`"bool"`, `"string"`, `"array"`, `"map"`, and `"()"`. A script-created
character has tag `"char"`. Ranges and `Fn` values and their construction
paths are forbidden. The function can also return the registered names
`"Date"`, `"Instant"`, `"LegalLocalTime"`, `"Decimal"`,
`"EntityReferenceSeed"`, and `"CodelistHandle"`. This limited type-name
inspection is intentionally part of the reviewed surface.

No implicit conversion to string, JSON parsing, JSON serialization, regular
expression, sorting, object merge, string splitting or joining, Unicode
normalization, case folding, URL encoding, Base64, hashing, or cryptographic
helper is available. Rhai does perform its existing mixed integer/float numeric
operations. Exact legal or financial arithmetic must use the `Decimal`
helpers. Rust performs serialization, URL encoding, authentication, signing,
and hashing outside the script.

Ordinary Rhai floats are carried only on the adapter surfaces that see
provider-shaped JSON: request preparation and source extraction, and only when
finite and inside the signed 64-bit magnitude. A public derived value is never
an ordinary float. Declare an integer concept or an exact `Decimal` instead;
a float reaching the derived-value gate fails the invocation.

`parse_integer` permits leading zeroes because provider text may use them; the
result has ordinary integer semantics. Extraction must still enforce
provider-specific bounds such as a non-negative count. Invalid input terminates
the invocation under the closed error class for that adapter stage.

No other Rhai standard package is loaded. In particular, scripts have no:

```text
network, HTTP client, filesystem, environment, process execution, logging,
printing, diagnostics, clock, timezone database, randomness, UUID generation,
shared mutable state, imports, modules, eval, plugins, dynamic function
dispatch, object reflection beyond type_of, or secrets
```

## Hard limits

These engine ceilings apply independently of script logic:

| Resource | Hard ceiling |
|---|---:|
| Script source | 65,536 bytes |
| Operations per invocation | 100,000 |
| Call depth | 32 |
| Expression depth | 64 |
| Modules | 0 |
| String value | 16,384 bytes |
| Array | 256 items |
| Map | 256 entries |
| Source-response body before projection | 1,048,576 wire JSON bytes |
| Projected source response | 65,536 serialized JSON bytes |
| Source-response input | 1,048,576 normalized JSON bytes |
| Facts, parameters, or result | 65,536 normalized bytes |
| Extracted fact entries | 64 |
| Derived concept values | 16 |
| Configured codelists | 256 |
| Entries per codelist | 4,096 |
| Numeric buckets | 64 |
| Entity-reference seeds in one derived value | 64 |
| `get_path` pointer | 256 bytes |
| `get_path` pointer segments | 16 |
| Entity-reference seed input | 512 bytes |
| `required` error code | 64 ASCII bytes |
| Exact decimal precision | 28 significant digits |
| Exact decimal scale | 9 fractional digits |
| Instant/local-time fractional precision | 9 digits |

The Version 1 preparation profile adds these hard ceilings. A source may
configure stricter `RequestParts` limits:

| Resource | Hard ceiling |
|---|---:|
| Combined normalized preparation input | 1,048,576 bytes |
| Request-batch items or extraction slots | 16 |
| Normalized `RequestParts` output | 65,536 bytes |
| Query pairs | 64 |
| Query name | 64 bytes |
| Query value | 4,096 bytes |
| JSON body depth | 32 |

Operation exhaustion, bound violations, invalid indexing, integer errors, and
explicit `throw` terminate the invocation. They never produce partial request
parts or partial facts.

## Errors and observability

Adapter scripts use only stable, value-free signals:

```text
adapter_input_error
source_protocol_error
derivation_input_error
```

`source_protocol_error` is the extraction signal.
`adapter_input_error` is the request-preparation signal.
`derivation_input_error` rejects an
inconsistent selector/fact/policy contract without including any input value.
Its public collapse is deliberate: a uniquely found record whose derivation
inputs are inconsistent returns the same `evidence.unavailable` problem as
`no_match` and `ambiguous`, so a caller cannot learn from the response that a
record exists. The internal category stays a value-free operator diagnostic in
audit. The `required` primitive uses another,
host-private unavailable termination. It is an opaque Rust-owned value that
script source cannot construct, reproduce with `throw`, or catch. The compiler
rejects `try`/`catch`.

Rust maps compilation, entry-point, input-bound, invocation, request-result,
source-protocol, and extraction-result failures to closed internal classes.
Selector values, source facts, response bodies, parameters, credentials,
tokens, and raw Rhai errors must not enter HTTP problems, audit data, logs,
metrics, traces, snapshots, panic output, or test-failure artifacts.

An adapter failure after the access-attempt audit prevents credential use,
source access, evidence construction, response protection, and disclosure as
applicable to its pipeline position. There is no fallback request or fallback
adapter.

Once an optimized batch invocation begins, a preparation, source, projection,
schema, extraction, slot, fact, or later failure aborts the outer request. It
never falls back to ordinary per-item calls and never releases completed item
results.

Tests prove that a script cannot forge the host-private
unavailable marker, use `Fn` or an anonymous function, interpolate an opaque
host value, or place a selector in an error, log, audit detail, metric, trace,
snapshot, or failed-test diagnostic.

## Review examples

- [DHIS2 preparation](dhis2-tracker/prepare.rhai) produces ordered repeated
  `filter` query pairs while Rust keeps the endpoint and credentials fixed.
- [OpenCRVS preparation](opencrvs-event-search/prepare.rhai) produces one
  bounded Event Search body.
- [OpenCRVS extraction](opencrvs-event-search/extract.rhai) emits only a narrow
  provider-search fact. It does not decide legal parenthood.
- [Deployment-shaped examples](deployment-projects/README.md) show complete
  DHIS2 adult-status and OpenCRVS adult-status, registered-parent confirmation,
  and registered-parent identification projects using this ABI.

The accepted Evidence contracts and runtime implement this API together with
startup, negative, resource-bound, redaction, exact-request, and one-request
transport tests.
