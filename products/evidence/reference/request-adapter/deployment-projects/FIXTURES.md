# Evidence Version 1 project fixture contract

Status: Partially implemented Version 1 executable fixture contract

Project fixtures are sanitized inputs to the production bundle loader, script
runtime, request materializer, source projection, output gate, evidence
construction, signer, verifier, and privacy checks. Evaluation does not start
the HTTP server, authenticate a JWT, write audit, resolve source credentials,
or contact a provider. Those boundaries are covered by package and HTTP-path
tests. Fixtures are not illustrative prose. Unknown keys, unknown mutation
names, and an expectation the harness cannot execute fail fixture evaluation.

Focused adapter directories may keep separate JSON input/output files. Complete
deployment projects use this YAML format so an adopter can review one case
matrix beside the requirement.

A requirement may omit its fixture reference only while its immutable bundle
declares `assuranceProfile: local`. Local serving still uses the ordinary
authenticated, authorized, source-bounded, minimum-disclosure, signed, and
fail-closed audit path. Production and evidence-grade bundles retain this
document's complete fixture-coverage requirement and fail to load when a
reference is absent or its captured suite is incomplete.

For production compilation, each editable question names one regular,
project-relative `fixtures/<name>.yaml` file. The build copies that file into
the candidate bundle and delegates its execution to `evidence evaluate`; it
does not reinterpret fixture semantics or manufacture cases. Missing,
symlinked, outside-project, duplicate, or incomplete fixture references stop
the build before publication. The build's private validation secrets and
runtime are not fixture inputs and never appear in the candidate.

## File shape

```yaml
fixture: registry.evidence.reference.example/v1
synthetic_only: true
common:
  observed_at: "2026-08-02T00:00:00Z"
  selectors: {}
  derivationSelectorInputs: {}
  expectedRequestParts:
    query: []
    body: null
  expectedTransport:
    path: /v1/search
    fixedHeaders:
      - {name: Accept, value: application/json}
cases: []
privacyExpectation:
  evidenceContains: []
  evidenceExcludes: []
  diagnosticsExclude: []
```

| Key | Required | Meaning |
|---|---|---|
| `fixture` | yes | Unique fixture contract identifier ending in `/v1`. |
| `synthetic_only` | yes | Must be literal `true`. Live values are forbidden. |
| `common` | yes | Deterministic inputs inherited by every case. |
| `cases` | yes | Non-empty ordered array with unique case ids. |
| `privacyExpectation` | yes | Tokens/canaries that must be present or absent at public and diagnostic boundaries. |

`observed_at` is required and may be overridden by a case. Rust derives
`legal_local_date` and `legal_local_time` from that instant and the requirement's
configured IANA timezone exactly as it does in production. A fixture cannot
inject those derived values. Boundary cases choose an observation instant that
produces the required local date or time.

`selectors` contains the complete authorized role map for the requirement.
`derivationSelectorInputs`, when present, states the exact minimized role map
the harness expects Rust to supply to `derive/3`. It must equal the bundle's
closed derivation selector-input declaration. Omit it when derivation receives
an empty map.

`extract` is required of a fixture whose source reads a SQLite extract, and
forbidden of one whose source answers over a network. It states the world the
cases run against as the SQL that builds it rather than as a database file, so
it is reviewable in a diff and no table name arrives in this tree inside an
opaque binary. The harness materializes it into a temporary read-only file and
binds that file in place of the operator's path before the project's own
runtime document loads. It carries the reserved `evidence_extract` metadata row
that `CONFIG.md` requires of any extract, because the fixture builds a real one
and startup refuses a file without it.

The seed is trusted executable project input and is not sandboxed as untrusted
code. Run only reviewed project seeds in an isolated local environment. Never
import or evaluate a foreign bundle as a fixture.

```yaml
common:
  observed_at: "2026-08-02T00:00:00Z"
  selectors:
    subject:
      profile: record-reference-v1
      values: {record_reference: REC-0001}
  extract: |
    CREATE TABLE evidence_extract (
      published_at TEXT NOT NULL,
      publisher    TEXT NOT NULL,
      extract_id   TEXT NOT NULL
    );
    INSERT INTO evidence_extract (published_at, publisher, extract_id) VALUES
      ('2026-08-01T00:00:00Z', 'urn:example:publisher', '2026-08-01-snapshot');
    CREATE TABLE records (reference TEXT NOT NULL);
    INSERT INTO records (reference) VALUES ('REC-0001'), ('REC-0002');
  expectedRequestParts:
    parameters: {}
  expectedTransport:
    statement: queries/source-b-lookup.sql
```

Every case of that fixture answers from the one extract and picks its subject
with `selectors`, because that is what a published snapshot is: one file
holding many records, not one file per outcome. The statement runs for real
against it, which is the one asymmetry in the harness. An HTTP call needs a
network, a credential, and a live third party, so it cannot run offline and its
cases carry the response the provider returned. Reading a local SQLite file
needs none of those, so fixtures stay hermetic, deterministic, and offline
while executing the statement for real. A recorded result would leave the
statement itself, which is the part most likely to be wrong, as the one thing
no case covers.

`purpose` names which of the requirement's declared purposes a case exercises,
and may be stated in `common`, in a case, or in both. A requirement declaring
exactly one purpose may omit it. A requirement declaring more than one must
state it, so offline evaluation reaches every authorized purpose and none is
silently skipped. An omitted declaration is a fixture contract failure, not an
authorization denial. A declared purpose the requirement does not list is
denied exactly as the served path denies it.

`common.expectedRequestParts` is compared structurally after ABI
normalization. Query-pair order is significant; JSON object order and source
whitespace are not. The harness then passes those parts and the resolved
authorized selectors through the production request materializer and compares
the path, encoded query, and JSON body. There is no case-level
`expectedRequestParts` override.

`query` and `body` are the channels an HTTP request is prepared into. A
statement request has neither, so its fixture states `parameters` instead: the
map preparation produced, which is `{}` for a source with no preparation
script, and stating the empty map is what proves no script added a parameter of
its own. The two shapes are exclusive rather than optional keys of one shape,
so a fixture cannot state the parts of a transport its source does not have and
an HTTP fixture that omits `query` fails to parse instead of defaulting to
empty.

A `search-then-fetch` fixture also supplies
`common.expectedFetchRequestParts` and `common.expectedFetchTransport`. The
harness validates them only after the search returns a unique schema-valid
FactSet, using that exact FactSet as the fetch adapter context and declared
prior-fact path input.

`common.expectedTransport` contains the exact fixed path or expanded path and
the exact configured non-secret headers. Authentication and Rust-owned framing
headers are checked by dedicated redacted transport assertions, never copied
into fixture YAML. A case-level `expected.expectedTransport` may add an exact
encoded query and normalized body for an encoding-focused case.

A statement source crosses its boundary as a statement and the values bound
into it, so its `expectedTransport` states `statement`, the bundle-relative
artifact the source declares. The statement is named rather than restated: its
text is a reviewed artifact hashed with the rest of the bundle, so a second
copy in the fixture would only be something to drift from. A case-level
`expected.expectedTransport` may add `parameters`, the exact map bound into
that statement, which is where a case pins what a caller-supplied value became.
The reserved `evidence_now` is bound by Rust at execution time and is not part
of that map.

### Request batches and fixture scope

The project fixture remains one logical evidence evaluation per case. Adding an
HTTP source `batch` block does not add request-batch members, opaque slots, or a
second expected response vocabulary to this file. `evidence evaluate` continues
to exercise the ordinary source contract for each case, which proves that the
optimized source has a semantically complete sequential path and that omission
or ineligibility can safely select it before I/O.

The optimized lane is covered by the generic source and runtime contract tests.
Those tests compile the batch scripts, invoke `prepare_batch` with one to
sixteen ordered `{slot, selectors}` items, apply the ordinary preparation
limits, pass a bounded projected response through the batch response schema,
and require `extract_batch` to return an exact slot bijection over ordinary
lookup results. They also prove strategy selection, no late fanout, ordered
response restoration, all-unavailable success, and outer abort on every other
failure.

Production and evidence-grade fixture coverage is therefore unchanged: every
requirement still needs its complete positive, negative, boundary, no-match,
ambiguity, missing-data, and privacy cases on the ordinary path. A batch block
adds no authority, disclosure shape, lookup outcome, or derivation behavior
that could replace those cases. Its referenced scripts and schema must still
exist, compile, and pass the bundle startup contract.

## Case input vocabulary

Every case has a required `id` and exactly one of these eleven tagged forms:

- `response`: raw provider JSON returned by the local mock. Rust applies the
  configured projection before extraction. The fixture never pre-projects or
  synthesizes an envelope.
- `responses`: the exact search-source and fetch-source response map for a
  `search-then-fetch` requirement. An unresolved search stops before fetch;
  the fetch response is evaluated only after a unique search match.
- `selectors`: the authorized role map this case picks out of the fixture's own
  extract, replacing `common.selectors` for the case. The statement runs, so
  the case states which record it is about rather than what the source returned.
- `sourceFailure`: one closed source failure from the table below, naming a way
  the source did not complete.
- `declaredUnresolved: true`: the data-free outcome of the requirement's
  initial HTTP source returning its exact configured `unresolvedProblem`. It
  carries no response body and is refused for an undeclared or statement
  source.
- `bundleMutation`: one named startup mutation below.
- `statementMutation`: one named mutation of a disposable copy of the reviewed
  statement, checked while the source compiles.
- `requestMutation`: one named authorization/request mutation below.
- `derivationMutation`: one named script-output mutation below.
- `derivationParameterMutation`: one closed mutation of a disposable copy of
  the requirement's derivation parameters before startup validation.
- `selectorOverrides`: one closed selector-input replacement that exercises
  preparation rejection or exact transport materialization.

A form belongs to the transport its source has. `response` and `responses`
state what a network returned and are refused for a statement source;
`selectors` and `statementMutation` describe an extract and the statement that
reads it, and are refused for a source that answers over a network. The
`declaredUnresolved` belongs only to an HTTP source that declares the tuple.
The remaining forms describe the bundle or the authorized request and read the
same on either transport.

An HTTP source that declares `unresolvedProblem` uses one
`declaredUnresolved: true` project case for the configured data-free outcome.
That case requires exactly `publicProblem: evidence.unavailable`,
`derivationRuns: false`, `signed: false`, and `sourceRequestCount: 1`, with no
`lookup` expectation. It truthfully covers both mandatory no-match and
ambiguous categories because the provider collapsed those hidden states before
Evidence could observe either one. The source contract suite separately sends
the exact 404 `application/problem+json` six-member tuple through the HTTP
transport and tests undeclared, mismatched, malformed, duplicate, extra,
mistyped, wrong-media, wrong-status, and oversized responses as dependency
failures. No fixture may restate the Problem Details body or pass it to
extraction.

A fixture currently executes a SQLite statement only when that source is the
initial acquisition stage. The evaluator refuses a later SQLite stage and
cannot represent an initial SQLite search together with later recorded HTTP
responses. The serving transport model permits those orders, but the supported
production/evidence-grade build journey cannot prove them. Treat such a project
as local authoring only and do not bypass the fixture gate to present it as
deployable assurance. Version 1 completion requires the harness to execute every
SQLite stage across HTTP to HTTP, HTTP to SQLite, SQLite to HTTP, and SQLite to
SQLite, with a build/serving gate for any order it cannot execute. Replaying a
recorded statement result is not evidence for reviewed SQL.

The optional inputs shared by applicable forms are:

- `observed_at`;
- `purpose`, which selects one of the requirement's declared purposes and
  overrides any `common.purpose`.

The closed mutation names used by these projects are:

| Field and name | Exact harness action |
|---|---|
| `bundleMutation: duplicate-disclosure-family` | Give two enabled requirements the same unsafe disclosure family and require startup rejection. |
| `statementMutation: attach-external-database` | Compile a disposable statement that attaches a second database and require the authorizer to refuse it. |
| `requestMutation: swap-subject-roles` | Exchange the child and candidate-parent role assignments without changing their profiles or origins. |
| `requestMutation: supply-grant-derived-candidate` | Add caller material for a role whose configured origin is the authenticated grant. |
| `derivationMutation: return-raw-reference` | Replace the disposable fixture derivation with one that returns the synthetic raw reference as a public value. |

Mutation cases never alter the reviewed project files on disk.

The closed `sourceFailure` names are per transport, because a failure of one
transport is not a thing that can happen to the other. A refused connection is
not a statement about a local file, and a refused SQL statement is not a
statement about a network. Naming a failure the source cannot have fails the
fixture rather than passing a case that could never occur:

| Name | Transport | The source did not complete because |
|---|---|---|
| `timeout` | both | The source exhausted its declared end-to-end timeout. |
| `oversized` | both | The assembled result exceeded the declared response size. |
| `connection-refused` | `http-json` | The origin could not be reached. |
| `invalid-media-type` | `http-json` | The response carried a media type the source does not accept. |
| `malformed-json` | `http-json` | The response body was not the JSON the source requires. |
| `extract-too-old` | `sqlite-extract` | The extract's published instant is older than the declared bound. |
| `statement-parameter` | `sqlite-extract` | A declared prepared parameter was not supplied at request time. |
| `statement-budget` | `sqlite-extract` | Statement execution exceeded its virtual-machine step budget. |
| `statement-result` | `sqlite-extract` | The result exceeded `maximumRows`, `maximumCellBytes`, or `maximumResponseBytes`, or result typing or execution failed. |

Every one of them collapses into the same `source.unavailable` public
class, which is the point: what a caller learns from a source that did not
answer is that it did not answer.

Extract opening, metadata, statement-authorizer, column-agreement, and static
parameter-agreement failures are startup failures, not request-time
`sourceFailure` cases. They belong in bundle/statement mutation cases and the
source contract suite. SQLite uses one `timeout` deadline across concurrency
admission, blocking-worker queueing, and execution. The separate
`statement-budget` name covers the virtual-machine step ceiling. The harness
must not synthesize a request-time cause the serving lifecycle cannot produce.

A `sourceFailure` case proves only the closed public-problem mapping for an
injected transport failure. It is not evidence that the acquisition path
actually reached that failure. The transport's source contract suite must
trigger each applicable failure at its real enforcement point, and a
complete-project fixture must execute every successful acquisition stage
rather than substituting a `sourceFailure` value for it.

## Expected vocabulary

Each case has a required `expected` object. Unknown keys and keys irrelevant to
the selected tagged form are rejected. Success, unresolved, and failure cases
must state their exact lookup, derivation, signing, and public outcome where
those stages apply. Omission is not treated as a wildcard.

| Key | Value | Assertion |
|---|---|---|
| `lookup` | `match`, `no_match`, or `ambiguous` | Exact closed extraction outcome. |
| `facts` | JSON object | Exact complete fact object after fact-schema validation, never a partial match. |
| `value` | supported scalar | Exact value of the requirement's only concept. Use only for a one-concept requirement. |
| `values` | concept map | Exact complete set of disclosed concepts, keyed by concept id. Use for a requirement disclosing more than one concept. |
| `entityReferenceCount` | integer | Exact number of audience-scoped entity references in the public value. |
| `rawReferencesDisclosed` | boolean | Whether any configured raw reference appears in evidence; these projects require `false`. |
| `signed` | boolean | Whether a flattened JWS success is returned. A valid `false` concept still requires `true`. |
| `publicProblem` | problem code | Exact safe public failure code. |
| `error` | adapter signal | Exact value-free internal fixture signal: `adapter_input_error`, `source_protocol_error`, or `derivation_input_error`. |
| `derivationRuns` | boolean | Whether `derive/3` is invoked. |
| `bundle` | `accepted` or `rejected` | Startup bundle result. |
| `outputGate` | `accepted` or `rejected` | Derived-value gate result. |
| `rejectedBefore` | `credential`, `source`, `derivation`, or `signing` | Latest boundary that must not be crossed. |
| `sourceRequestCount` | integer | Exact number of evidence-data operations the production path would attempt. Version 1 permits `0` through the acquisition's fixed ceiling, at most `5`. For an injected `sourceFailure`, this count is modeled; it does not prove the fixture harness executed the source. |
| `expectedTransport` | object | Exact expanded path, encoded query string, and normalized body bytes for a transport-focused case, or the exact statement artifact and bound parameters where the source reads an extract. |

`expectedTransport` is accepted only for the `selectorOverrides` form.
Successful `response`, `responses`, and `selectors` cases require
`lookup: match`, `derivationRuns: true`, and `signed: true`. The harness
creates a fresh in-memory P-256 key for the evaluation, signs the constructed
Evidence, and verifies the JWS and exact payload policy. The private key is
never read from deployment secrets, written to disk, or included in output.
Unresolved and failing cases require `signed: false` and the exact
`derivationRuns` value.

A `declaredUnresolved` case is intentionally not a `sourceFailure`: it is a
configured source outcome and maps to `evidence.unavailable`, not
`source.unavailable`. Its explain trace records neutral `unresolved`, never
`no-match`, `ambiguous`, or upstream problem members.

Every `facts` expectation is exact. If a test cares about only two of four
facts, it must still list all four. This prevents fixtures from silently
accepting a new or leaked fact.

`value` and `values` are mutually exclusive, and `values` is exact in the same
way: it states every concept the requirement discloses, so a new or leaked
concept cannot pass unnoticed.

## Error classes and public problems

Fixtures distinguish unresolved evidence from a broken dependency or bundle
contract. Do not choose a public code based only on the stage where a value was
noticed.

| Internal outcome or signal | Public result | Fixture use |
|---|---|---|
| `no_match` | `evidence.unavailable`, HTTP 422 | Authoritative lookup found no unique record. |
| `ambiguous` | `evidence.unavailable`, HTTP 422 | Authoritative lookup found multiple records; no candidate is selected. |
| Exact configured source-declared unresolved | `evidence.unavailable`, HTTP 422 | Provider returned its governed data-free unresolved outcome at the initial singular or search stage; Evidence does not claim whether it was no-match or ambiguous. |
| Host-private `required_fact_missing` | `evidence.unavailable`, HTTP 422 | A uniquely matched record legitimately lacks a requirement fact that the derivation marks required. |
| `adapter_input_error` | `service.unavailable`, HTTP 503 | Trusted preparation or its closed inputs violate the adapter contract. Credential acquisition and source access must not occur. |
| `source_protocol_error` | `source.unavailable`, HTTP 503 | The projected provider response violates its protocol, type, count, completeness, or fact-shape contract. |
| `derivation_input_error` | `evidence.unavailable`, HTTP 422 | Matched facts, returned-subject binding, governed namespace/contract, or derivation parameters are inconsistent. A returned-child mismatch is this class. It collapses publicly with the unresolved classes so a caller cannot learn that a record exists, and it is never an authoritative no-match or a signed `false`. |
| Source transport failure | `source.unavailable`, HTTP 503 | Credential, concurrency, timeout, redirect, status, media type, size, JSON, projection, or source transport failure stopped the lookup. An unopenable or too-old extract, and a statement the authorizer refused, that lacked a parameter, that exceeded a budget, or whose result exceeded a declared bound, are this class. |
| Audit, signing, output-gate, or other script failure | `service.unavailable`, HTTP 503 | Evidence failed closed within the Evidence service or one of its required release dependencies. A script fault raised while derivation is running reports the internal `derivation_input_error` category and stays in this public class. |

Each 503 class is pinned by the fixture's exact `publicProblem` expectation.
The two 503 codes have distinct static, value-free titles and disclose no provider, selector, fact,
script, or comparison detail. `no_match`, `ambiguous`, the host-private
required-value outcome, and derivation-input inconsistency over a uniquely
found record all collapse into the same 422 public shape, so a fixture can
never make the status code an existence oracle. A script must not throw
`source_protocol_error` merely to represent an ordinary missing optional fact,
and it must not convert malformed or incomplete provider data into `no_match`.

## Harness-wide assertions

The harness applies these assertions to every case whether or not they appear
under `expected`:

- preparation is after authorization and durable access audit, and before
  credential acquisition;
- no request-parts failure acquires credentials or reaches the source;
- zero or multiple provider results never run derivation or sign evidence;
- no case performs more calls than its acquisition permits, follows pagination,
  redirects, retries, or response-provided URLs; single permits one and
  search-then-fetch permits at most its fixed two;
- a source batch block does not change fixture semantics or bypass any ordinary
  requirement case; optimized-call behavior is proven in the generic source
  and runtime contract suite rather than represented by synthetic fixture keys;
- an error, failed audit, failed output gate, or failed signing never returns an
  unsigned success;
- expected facts and values are compared with redacted failure messages;
- selector values, source facts, supported values, secrets, and privacy canaries
  never appear in test names, snapshots, panic output, logs, audit, metrics,
  traces, HTTP problems, or diff diagnostics; and
- the privacy expectation is checked against the verified JWS payload and every
  captured diagnostic sink.

The harness may report the case id, stage, expected type, actual type, and a
value-free mismatch code. It must not print the mismatching protected value.

## Explaining a failing run

A fixture failure names the contract that broke and nothing else, which says
that a case failed but never which one or why. `evidence evaluate --fixture
<path> --explain` additionally prints, for every case, the stages it reached
and how each one ended.

The trace reports shapes only, within the value-free allowance above: response
and fact member names, response and value counts, source and concept
identifiers, and the declared form a concept requires. It never prints a
response value, a fact value, a derived value, or a selector value. It is
offline-only and no other subcommand accepts the flag; `serve` cannot reach
it. It changes no outcome, exit code, or message, and without the flag the
command's output is unchanged.

The line that ends a case is the one to read first. An unresolved lookup lists
the response members the extraction script actually saw, which is the whole
diagnosis when a script recognized nothing in a response it was given. An
output-gate rejection lists each declared concept, its form, and whether it is
required, which is what the gate checked the derived values against.

Adding `--explain-format json` renders the same trace for a machine reader.
The document is the whole of standard output, so it pipes without a trailing
summary line to strip, and the verdict and evaluated-case count that line
carries move inside it as `passed` and `evaluatedCases`. The exit code and the
operator message on standard error are the same in both forms.

Each case can also carry a closed expected-versus-observed diagnosis. A result
has one of `match`, `no-match`, `ambiguous`, `evidence-unavailable`,
`source-unavailable`, `service-unavailable`, `bundle-refused`, or
`selector-refused`. A matched value is reduced to a bounded classification such
as `boolean-true`, `integer`, or `structured`. `reasonCode` says which closed
evaluator outcome produced the observation, and `findingCodes` says which
authored expectation disagreed. None of these fields carries a source,
selector, SQL, credential, or governed result value.

For a controlled-category concept only, `categoryClasses` identifies an
allowed result by its zero-based concept position in the requirement and its
zero-based value position in that concept's captured governed codelist. The
field appears only after the output is proven to belong to that codelist. An
arbitrary string remains only the shape `string`; the trace never substitutes
raw category text or a concept identifier for an ordinal.

```sh
evidence --runtime "<candidate>/runtime.yaml" \
  evaluate --fixture "<path>" --explain --explain-format json \
  | jq -r '.cases[] | "\(.id)\t\(.failure // "passed")"'
```

`evidencectl fixtures run --project <candidate> --explain` asks the same of
every fixture a project references using the JSON form. The human report
pretty-prints each value-free document under its step line; `--json` places the
same document at that fixture's `trace` field. The driver totals
`evaluatedCases` from those documents and does not interpret Evidence
semantics.

A fixture's own `diagnosticsExclude` canaries are checked against both
rendered forms of the trace on every run, including a run that stopped on an
error, so a stage line that ever interpolated a protected value instead of its
shape fails the fixture that declared that value before the trace is printed.
Case identifiers are part of that surface: the trace puts one on a line of its
own, so an identifier carrying a control character is refused rather than
rendered.
