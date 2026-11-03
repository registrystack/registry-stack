# Evidence derivation script API

Status: current Version 1 assertion derivation ABI, maintained reference.

Use `derive/3` to turn a completed, schema-validated Source lookup into the
selected requirement's concept values. Registry Evidence supplies the private
facts, separately minimized authorized selectors, and deterministic evaluation
context. Rust validates the result before subject binding, signing and release.

Source acquisition and extraction use reviewed [Adapter packs](../../../adapter/CONCEPT.md).
Pack scripts use the Adapter exchange ABI and compile separately from Evidence
assertion derivations. Evidence Sources bind a pinned pack, route, connection,
selector inputs and fact schema through the
[compiled Source configuration](deployment-projects/CONFIG.md#adapter-pack-source-example).
The retired Evidence `prepare`, `extract`, `prepare_batch` and `extract_batch`
entry points are refused; they are not alternate forms of `derive`.

This reference describes the compiled `registry.evidence.request-adapter/v1`
assertion ABI under Evidence bundle Version 1. For normalized EvidenceProject
Functions, use the [authoring reference](../authoring-projects/CONFIG.md).
An authored `assertion-derive/v1` Function returns local `{output, value}`
entries; the authoring compiler translates them into compiled
`{concept_id, value}` entries. The host helpers and resource limits apply to
both authored and compiled assertion derivations.

The implementation source is `registry-evidence`'s `rhai_runtime` module,
including `compile_derivation`, `derive` and the closed result decoder.
`evidencectl package` compiles authoring inputs and delegates execution to the
real `evidence` binary; it supplies no additional script runtime or authority.

## Entry point

```text
derive(facts: map, selectors: map, evaluation_context: map)
    -> array<DerivedConceptValue>
```

Each derivation artifact declares one public `derive` function with exactly
three arguments. Statically named same-file helpers are permitted; overloaded
entry points, top-level executable statements, anonymous functions, function
pointers and data-derived dispatch are refused.

Scripts compile before readiness. Every invocation receives fresh state and
fresh input copies, so local mutation cannot change the bundle, another
invocation or another definition. Only a completed `match` reaches derivation;
no-match, ambiguous, unresolved and malformed lookup results release no facts
to this ABI.

## Inputs

`facts` is the complete private FactSet from the matched pack route, validated
against the Evidence Source's closed `factSchema`. Internal pack operations
may compose multiple reviewed reads, but derivation receives one completed
FactSet. Integer tokens outside the signed 64-bit range fail before conversion
to Rhai rather than becoming imprecise floats. Provider identifiers outside
that range must be strings.

`selectors` contains only the roles, profiles and fields declared by the
requirement's derivation selector-input contract. Rust resolves them from the
already authorized requirement subjects. Omission yields an empty map. A
relationship derivation can compare a returned parent reference with the
separately authorized candidate-parent selector without receiving the complete
request, credentials, grant or unrelated lookup selectors.

For example, one declared role is represented as:

```json
{
  "subject": {
    "profile": "record-reference-v1",
    "values": {"record_reference": "synthetic-reference"}
  }
}
```

`evaluation_context` contains exactly the runtime observation instant, legal
local date and time, closed requirement parameters and read-only codelist
handles described in [Evidence primitives](#evidence-primitives). The caller
cannot supply a clock. Parameters carry reviewed non-secret requirement data,
not requester identity, authorization objects, credentials or runtime handles.

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

A derivation may return `false` only after the pack lookup established one uniquely
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

A reviewed pack may supply `reference_namespace` and
`relationship_set_contract` as fixed constants checked against closed
requirement parameters. Constant agreement does not prove that the provider
returned a namespace or contract identifier. If either value can vary by
record, the pack must derive and validate it from provider data,
the fact schema must require it, and fixtures must cover mismatch. Governance
must always establish that returned references belong to the declared
namespace and that the relationship set has the claimed meaning and
completeness.

`legal-parent-relationship` is valid only where deployment governance states
that the configured source fields and matching rule establish legal
parentage. The portable OpenCRVS reference therefore uses
`registered-parent-relationship` until that stronger jurisdiction-specific
meaning is documented.

## Version 1 derivation language surface

Derivation scripts may construct `bool`, signed
64-bit integer, finite floating-point number, character, string, array, map,
and unit/null values. Derived values must satisfy the closed result gate; ordinary floats and
unsupported host objects are rejected as public outputs.

The Version 1 ABI pins Rhai 1.27.0 core syntax plus the host registrations in
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
  optional chaining, and null coalescing because the reviewed derivation language excludes them.

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
| `to_string(value)` | Signed 64-bit integer to canonical decimal text, or Boolean to `true`/`false`; only these two typed overloads exist. Registered opaque handles cannot be converted to text. |

### Evidence primitives

Opaque values cross the result gate only through the declared Decimal and
entity-reference forms. Some helpers require handles that only Rust can supply
through derivation context.

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
Acquisition scripts use the separate Adapter exchange contract.

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

Finite ordinary floats inside the signed 64-bit magnitude may occur in
private facts or local computation. A public derived value is never an
ordinary float. Declare an integer concept or an exact `Decimal` instead; a
float reaching the derived-value gate fails the invocation.

`parse_integer` permits leading zeroes because provider text may use them; the
result has ordinary integer semantics. Reviewed pack logic validates
provider-specific bounds such as a non-negative count. Invalid derivation
input terminates the invocation under a closed error class.

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
| Facts, parameters, or result | 65,536 normalized bytes |
| Input fact entries | 64 |
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

Operation exhaustion, bound violations, invalid indexing, integer errors and
explicit `throw` terminate the invocation. A failed derivation releases no
partial concept values.

## Errors and observability

A reviewed derivation can throw `derivation_input_error` to reject an
inconsistent selector, fact or policy contract without including input values.
The public result is `evidence.unavailable`, also used for no-match and
ambiguous lookups, so the failure does not reveal that a record exists.
The internal audit category remains value-free.

The `required` helper terminates a missing-value invocation with a host-private,
unforgeable unavailable marker. Its safe-code argument is validated and then
discarded. Scripts cannot manufacture the marker with `throw` or catch it;
`try` and `catch` are refused.

Rust maps compilation, entry-point, input-bound, invocation and result failures
to closed internal classes. Selector values, source facts, parameters,
credentials, tokens and raw Rhai errors are excluded from HTTP problems, audit
details, logs, metrics, traces and snapshots. Signing and release audit receive
only values that passed the complete output gate.

Request batches execute logical items sequentially under Rust-owned ordering.
An allowed unavailable result belongs to its item; an acquisition, protocol,
signing or audit failure aborts the request without partial release. Provider
scripts do not receive or manufacture request-batch correlation slots.

Tests prove that a script cannot forge the host-private
unavailable marker, use `Fn` or an anonymous function, interpolate an opaque
host value, or place a selector in an error, log, audit detail, metric, trace,
snapshot, or failed-test diagnostic.

## Review examples

- [Professional licence derivation](../../fixtures/acceptance/professional-licence/derivations/professional-licence.rhai)
  uses runtime legal time, exact dates and Decimal buckets.
- [Deployment-shaped examples](deployment-projects/README.md) combine reviewed
  packs with adult-status and registered-parent assertion derivations.
- [Adapter script contract](../../../adapter/CONCEPT.md#8113-script-abi)
  defines the separate exchange input and result seams used inside packs.
