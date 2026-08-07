# Evidence Version 1 project fixture contract

Status: Implemented Version 1 executable fixture contract

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

## Case input vocabulary

Every case has a required `id` and exactly one of these eight tagged forms:

- `response`: raw provider JSON returned by the local mock. Rust applies the
  configured projection before extraction. The fixture never pre-projects or
  synthesizes an envelope.
- `responses`: the exact search-source and fetch-source response map for a
  `search-then-fetch` requirement. An unresolved search stops before fetch;
  the fetch response is evaluated only after a unique search match.
- `sourceFailure`: one closed mock failure, currently `timeout`,
  `connection-refused`, `invalid-media-type`, `oversized`, or `malformed-json`.
- `bundleMutation`: one named startup mutation below.
- `requestMutation`: one named authorization/request mutation below.
- `derivationMutation`: one named script-output mutation below.
- `derivationParameterMutation`: one closed mutation of a disposable copy of
  the requirement's derivation parameters before startup validation.
- `selectorOverrides`: one closed selector-input replacement that exercises
  preparation rejection or exact transport materialization.

The optional inputs shared by applicable forms are:

- `observed_at`;
- `purpose`, which selects one of the requirement's declared purposes and
  overrides any `common.purpose`.

The closed mutation names used by these projects are:

| Field and name | Exact harness action |
|---|---|
| `bundleMutation: duplicate-disclosure-family` | Give two enabled requirements the same unsafe disclosure family and require startup rejection. |
| `requestMutation: swap-subject-roles` | Exchange the child and candidate-parent role assignments without changing their profiles or origins. |
| `requestMutation: supply-grant-derived-candidate` | Add caller material for a role whose configured origin is the authenticated grant. |
| `derivationMutation: return-raw-reference` | Replace the disposable fixture derivation with one that returns the synthetic raw reference as a public value. |

Mutation cases never alter the reviewed project files on disk.

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
| `sourceRequestCount` | integer | Exact number of evidence-data requests. Version 1 permits `0`, `1`, or `2` according to the requirement's acquisition. |
| `expectedTransport` | object | Exact expanded path, encoded query string, and normalized body bytes for a transport-focused case. |

`expectedTransport` is accepted only for the `selectorOverrides` form.
Successful `response` and `responses` cases require `lookup: match`, `derivationRuns: true`,
and `signed: true`. The harness creates a fresh in-memory P-256 key for the
evaluation, signs the constructed Evidence, and verifies the JWS and exact
payload policy. The private key is never read from deployment secrets, written
to disk, or included in output. Unresolved and failing cases require
`signed: false` and the exact `derivationRuns` value.

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
| `no_match` | `evidence_not_available`, HTTP 422 | Authoritative lookup found no unique record. |
| `ambiguous` | `evidence_not_available`, HTTP 422 | Authoritative lookup found multiple records; no candidate is selected. |
| Host-private `required_fact_missing` | `evidence_not_available`, HTTP 422 | A uniquely matched record legitimately lacks a requirement fact that the derivation marks required. |
| `adapter_input_error` | `service_unavailable`, HTTP 503 | Trusted preparation or its closed inputs violate the adapter contract. Credential acquisition and source access must not occur. |
| `source_protocol_error` | `dependency_unavailable`, HTTP 503 | The projected provider response violates its protocol, type, count, completeness, or fact-shape contract. |
| `derivation_input_error` | `evidence_not_available`, HTTP 422 | Matched facts, returned-subject binding, governed namespace/contract, or derivation parameters are inconsistent. A returned-child mismatch is this class. It collapses publicly with the unresolved classes so a caller cannot learn that a record exists, and it is never an authoritative no-match or a signed `false`. |
| Source transport failure | `dependency_unavailable`, HTTP 503 | Credential, concurrency, timeout, redirect, status, media type, size, JSON, projection, or source transport failure stopped the lookup. |
| Audit, signing, output-gate, or other script failure | `service_unavailable`, HTTP 503 | Evidence failed closed within the Evidence service or one of its required release dependencies. A script fault raised while derivation is running reports the internal `derivation_input_error` category and stays in this public class. |

Each 503 class is pinned by the fixture's exact `publicProblem` expectation.
Both 503 codes share the safe title and disclose no provider, selector, fact,
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
