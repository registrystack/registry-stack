# Evidence Implementation Approach

Status: Approved Version 1 implementation approach
Date: 2026-08-09

Source-contract and local-smoke details: [SOURCE-TESTING.md](SOURCE-TESTING.md)

## Version 1 product shape

Version one is one runtime crate and one binary. The runtime depends on one
portable library for response verification, adopter tooling sits beside it
outside the frozen runtime contract, and product-owned contracts and fixtures
remain outside every crate:

```text
crates/registry-evidence/
  src/
    audit.rs
    auth.rs
    binding.rs
    bundle.rs
    config.rs
    contracts.rs
    kernel.rs
    lib.rs
    local_verification.rs
    main.rs
    model.rs
    observability.rs
    problem.rs
    rate_limit.rs
    rhai_runtime.rs
    runtime.rs
    secrets.rs
    selector.rs
    server.rs
    signing.rs
    source.rs
    values.rs
  tests/
    cli.rs
    deployment_projects.rs
    protected_registry_source.rs
    source_contracts.rs
    selector_conformance.rs
    security_contract_traceability.rs
    live_sources.rs
crates/registry-evidence-verifier/
  src/
    contracts.rs
    lib.rs
    model.rs
    sdjwt_vc.rs
    verifier.rs
crates/registry-evidencectl/
crates/registry-evidence-client/
crates/registry-evidence-client-node/
crates/registry-evidence-client-py/
products/evidence/
  contracts/
  fixtures/
  generated/
  reference/
  scripts/
```

The binary exposes four commands:

```text
evidence serve
evidence check
evidence evaluate --fixture <path>
evidence verify --jws <file> --jwks <file> --policy <file>
```

Do not create client, worker, adapter, policy, credential, or interoperability
crates in version one. What the prohibition forbids is carving a runtime
responsibility out into a separate crate, not shipping a relying-party SDK that
adds no Evidence semantics of its own. `registry-evidence-verifier` is the one
approved decomposition of the runtime, and it is closed: no further extraction
is approved. Rhai adapters and derivations are deployment-bundle artifacts, not
Rust crates. The adopter tooling, the relying-party client, and its Node and
Python bindings named above sit outside the frozen Version 1 runtime contract,
delegate every Evidence semantic decision to the runtime or to the portable
verifier, and add no Evidence semantics of their own.
`registry-evidencectl` reuses the relying-party client for request preparation
and the portable verifier for offline response verification; it continues to
delegate runtime evaluation, signing, bundle validation, and fixture evaluation
to the real `evidence` binary.

Production code is source-product neutral. `src/`, production Cargo features,
dependencies, public types, configuration schemas, routes, and CLI options
must contain no DHIS2-specific or OpenCRVS-specific behavior. Those product
names and shapes may appear only in tests, sanitized fixtures, test-only bundle
artifacts, and the local smoke guide. Event Search is an ordinary bounded JSON
`POST`; a Tracker request is an ordinary fixed-authority `GET` with prepared
query parameters and Rhai extraction.

## Dependency boundary

Reuse selected shared primitives without inheriting another product model:

| Crate | Version-one use |
|---|---|
| `registry-platform-audit` | Scoped pseudonymization and the shared audit writer: envelope, file and stdout destinations, rotation, and retention |
| `registry-platform-crypto` | `SigningProvider`, protected JWK handling, ES256 signing, RFC 7638 identifiers, and workload-local Transit signing |
| `registry-platform-oidc` | Strict access-token and JWKS verification for the reference authentication profile |
| `registry-platform-httpsec` | Security response headers where the existing contract fits |
| `registry-platform-httputil` | Bounded source-response body reads |
| `registry-platform-sdjwt` | Compact SD-JWT VC serialization for the SD-JWT VC response format |

Evidence must not depend on `registry-notary*`, `registry-platform-oid4vci`,
`registry-platform-replay`, `registry-platform-sts`, or Registry Manifest.

The governed bundle and closed operator runtime file are trusted and
startup-only. Use typed YAML and explicit secret references. Runtime
configuration binds only process-local listener, filesystem, audit-storage,
secret-mount, signer transport and pinned version, and TLS-trust paths; it is
not an override layer and cannot change the governed active public key. Do not
expand private key material or source credentials into either parsed YAML
document.

## Reference implementation defaults

These defaults unblock implementation without claiming that every deployment
must use them:

| Area | Reference default |
|---|---|
| Authentication | OIDC access token with exact issuer, audience, type, and algorithm allowlists |
| Principal | One configured claim, initially `sub`; missing claim denies with no fallback |
| Subject authority | Configured statutory-agency profile permits an authorized requester to use only named selector profiles and approved value origins |
| Subject selector | Closed identifier or compound field set with deployment-defined names, scalar types, bounds, and fixed source placements |
| Lookup outcome | Provider-owned `match`, `no_match`, or `ambiguous`; facts exist only on `match` |
| Source | One fixed HTTP JSON data request using field projection and denied redirects, or one reviewed SQL statement over a read-only SQLite extract the runtime mounts |
| Statement source | A reviewed statement artifact covered by the package sum file, a prepare-time authorizer verdict, required extract publication metadata, a package-declared maximum extract age, and declared row, statement-step, cell, and time bounds |
| Source authentication | Secret-referenced Basic, static Authorization header, static API-key header, or OAuth 2.0 client credentials by client secret or private-key JWT assertion; explicit local authoring may use no credential only at a canonical numeric-loopback HTTP origin. A statement source presents no credential at all |
| Audit | `registry-platform-audit` JSONL sink on explicitly durable storage, fail-closed |
| Signing | Flattened JWS JSON with one active ES256/P-256 key, RFC 7638 `kid`, explicit published and revoked sets, and a public JWKS endpoint |
| Response format | Signed JWS by default; exact `Accept: application/vnd.registrystack.evidence-unsigned+json` only when the bundle and complete matched grant permit it; the request-batch route has only `application/vnd.registrystack.evidence.request-batch+json` and signed JWS item results |
| Evidence storage | None |
| Runtime mutation | None |

The real identity provider, authority mapping, source contracts, reference
framework rules, audit storage, and verifier trust distribution remain
deployment inputs. Mocked contracts allow the generic runtime to be built
before those integrations are available.

## Runtime pipeline

The production path is fixed:

1. Parse and bound the JSON request, including the required canonical 43-byte
   base64url encoding of an exact 32-byte random request nonce.
2. Authenticate the token from configured issuer metadata.
3. Derive the principal only from the configured claim.
4. Resolve the requirement, purpose, audience, exact requested response format,
   and subject-authority profile.
5. Resolve each role's configured selector profile and obtain its values only
   from the profile's permitted origin: authenticated context, authenticated
   grant, or the bounded request.
6. Validate the exact field set, scalar types, bounds, role, and fixed source
   binding. Reject missing, unknown, or extra material, and values the
   acquiring Source's inputs schema refuses, as `request.selector-invalid`. A
   value a selector-bound source path segment cannot carry passes this step
   and is refused at path materialization. The `request.selector-invalid`
   refusals are returned during selector resolution, after the authorization
   decision of step 7 and before the access-attempt event of step 9, and
   count against the caller's selector-failure budget.
7. Make one authorization decision over requester, optional actor, requirement
   revision, purpose, role-bound selector profiles and value origins, subject
   authority, audience, and response format.
8. On authorization refusal after successful authentication, durably write a
   standalone minimal denial event with the
   `registry.evidence.audit.authorization-refusal/v2` discriminator and return
   the generic `403`. The event contains no requested requirement, purpose,
   subjects, unmatched authority, selector information, response protection,
   source, or evaluation material. If the audit append fails, return the
   generic `503` instead.
9. Capture the effective immutable acquisition limits and durably write the
   `/v3` access-attempt audit event. Its closed `executionBounds` contains the
   positive operation, deadline, and response-byte limits and at most one scoped
   keyed pseudonym over each complete canonical role and selector bundle. It
   contains no endpoint, credential, secret, or source value.
10. Materialize the selected stage's transport input from only the
    source-required authorized selectors, closed adapter parameters, and
    allowed prior facts. Validate the complete HTTP `RequestParts` or SQLite
    parameter map before touching the source.
11. For HTTP only, resolve the configured source credential. When required,
    acquire or reuse a bounded OAuth 2.0 client-credentials token through the
    Rust-owned credential provider. A SQLite stage has no credential step.
12. Execute the one Rust-owned evidence-data source operation: the fixed HTTP
    exchange, or the reviewed statement against the bound read-only extract.
13. Run bounded Rhai extraction and validate the closed `match`, `no_match`, or
    `ambiguous` result. Stop safely on either non-match outcome.
14. On `match`, run bounded Rhai derivation with only its declared authorized
    selector inputs and deterministic context.
15. Validate the complete concept-value result against the selected
    requirement.
16. Construct the Evidence JSON payload in Rust without selector profiles or
    values and with the exact request nonce.
17. For signed JWS, sign and serialize the exact final response bytes. For an
    explicitly authorized unsigned request, construct and serialize the closed
    self-identifying unsigned envelope without invoking the signer.
18. Before the acquisition deadline expires, admit the pseudonymized
    disclosure-release audit append with the closed response-protection mode
    and a signing key id only for JWS. That admission is the disclosure-begin
    boundary. Once admitted, let the durable append complete without
    cancellation and omit `executionBounds` from this terminal event.
19. Return those exact pre-audited bytes with their exact media type.

Any failure through transport-input validation in step 10 prevents credential
acquisition and source access. Any failure after source
access prevents evidence release. Audit failure prevents the applicable refusal
response, source access, or evidence response.
Signing failure on the signed path never produces an unsigned success response.
Authentication, malformed-request, and invalid-selector failures have no native
audit event and remain in the closed operational channel.

The multi-subject request-batch path wraps this pipeline without weakening it:

1. Parse one common requirement and purpose plus one to sixteen ordered items.
   Validate each complete subject set and every canonical nonce, including
   pairwise distinctness, before source access.
2. Authenticate the bearer token once, mint one operation identifier, reserve
   one evaluation instant, and debit the principal's request-rate bucket by the
   complete item count atomically. A failed debit charges nothing.
3. Resolve and authorize every item independently against the same token-derived
   audience and required signed-JWS format. Any failure aborts before source
   credential resolution or I/O. Items may match different grants or authority
   kinds.
4. Select the source strategy before any access audit, credential resolution,
   semaphore admission, or I/O. Sequential execution supports every existing
   audience-scoped acquisition and evaluates in request order. The optional
   one-call HTTP strategy requires both `source-batch` capability gates, a
   `single` acquisition, one fixed-path HTTP source with a batch block, and a
   complete item count within that source's `maximumItems`.
5. For each physical source call, durably record one batch-native access event
   containing bounded item indices and groups of identical authority plus
   pseudonymized subject sets. Once optimized execution begins, failure never
   retries through sequential fanout.
6. Map every condition the singular collapse contract exposes as
   `evidence-not-available` to that per-item outcome, including no-match,
   ambiguous, required-fact-missing, derivation-input-unresolved, and an exact
   declared unresolved outcome from a singular or search source stage. Construct
   and sign every available item as an ordinary flattened JWS at the common
   evaluation instant. Any other failure aborts without releasing completed
   items.
7. Serialize the complete closed response, enforce the 1 MiB exact-envelope
   ceiling, durably record one terminal release with every grouped item and
   ordered outcome, then return the same bytes. A post-authorization abort
   records one value-free terminal failure instead.

The route does not admit unsigned output, SD-JWT VC, holder keys, or the
holder-bound issuance batch. It remains a separate audience-scoped evaluation
operation even where both features are enabled in one deployment.

## Bundle and runtime contracts

The governed atomic bundle contains:

```text
evidence.yaml
adapters/
  source-a-prepare.rhai
  source-a-extract.rhai
queries/
  source-b.sql
derivations/
  requirement-a.rhai
schemas/
codelists/
fixtures/
```

The separate `runtime.yaml` binds the bundle directory, listener, secret root,
audit destination, signer transport and pinned key version, and logical TLS
trust profiles to local paths. The bundle and runtime hashes identify the exact
inputs loaded by the process. They do not prove trust. Deployment controls
establish trust by mounting both reviewed inputs read-only and starting a new
process for a new revision.

Bundle checking must validate:

- stable and unique requirement, concept, Evidence Type, source, adapter, and
  derivation identifiers;
- exact subject roles and cardinalities;
- selector profiles with one exact field set, stable deployment-defined field
  names, scalar types, byte bounds, and a maximum aggregate size;
- allowed selector profiles and value origins for every subject role and
  authority profile;
- closed source-required selector inputs, reviewed request-preparation scripts,
  and a source binding for every allowed role and profile combination;
- closed derivation selector inputs that are exact subsets of the selected
  requirement roles and profiles;
- fixed purposes, requester classes, audiences, and subject-authority paths;
- for HTTP, fixed scheme, host, method, fixed path or tagged selector/prior-fact-
  bound path template, fixed non-secret headers, fields, credentials, logical
  TLS trust-profile name, limits, and redirect policy;
- for an optional HTTP source batch block, fixed-path-only eligibility, a
  `maximumItems` ceiling of one through sixteen, distinct `prepare_batch/2` and
  `extract_batch/2` scripts, a closed response schema and projection, and the
  bundle's independent `source-batch` capability declaration;
- for SQLite, one reviewed statement, exact result columns and parameter
  origins, logical extract profile, publication-age policy, and row, cell,
  statement-step, elapsed-time, response-size, and concurrency bounds;
- fixed HTTP source-authentication scheme and, for OAuth, token endpoint,
  grant, credential placement, scope, bounds, and cache lifetime; extract
  sources carry no credential or authentication configuration;
- a closed runtime file with no governed-field override, complete bundle and
  logical trust-profile bindings, and no ambient proxy behavior;
- fact and concept schemas;
- derivation parameter types;
- codelist references and versions;
- successful Rhai compilation;
- for production and evidence-grade assurance, positive, negative, boundary,
  missing-data, no-match, ambiguous-match, and anti-reconstruction fixtures;
- combined disclosure safety of every simultaneously enabled definition.

The governed bundle declares `local`, `production`, or `evidence-grade`
assurance. Local may omit a requirement fixture reference during authoring but
retains every runtime authentication, authorization, immutability, source,
signing, audit, and disclosure control. Production and evidence-grade retain
the complete fixture gate. The assurance value is part of Evidence, JWS,
SD-JWT VC, discovery, audit, and strict verification policy.

## Source and credential boundary

Version one implements two coequal generic source executors: a fixed HTTP JSON
request executor, and a reviewed-statement executor over a read-only mounted
SQLite extract. Product-specific source crates, clients, and domain types are
out of scope for both. An `http-json` source definition declares a fixed
request and selects one generic authentication profile:

- no credential only under `assuranceProfile: local`, at a canonical numeric-
  loopback HTTP origin with an explicit non-zero port;
- HTTP Basic with username and password secret references;
- static Authorization header with a token secret reference and an optional
  fixed scheme, defaulting to Bearer;
- static API-key header with a fixed allowlisted header name and secret
  reference;
- OAuth 2.0 client credentials with a client identifier reference, a fixed
  HTTPS token endpoint, a fixed grant, optional fixed scope and audience, an
  optional RFC 8707 resource indicator, and exactly one client authentication
  form: a client secret reference with a fixed placement, or a private-key
  reference the runtime signs a JWT client
  assertion with.

Credential acquisition is not available to Rhai. OAuth token acquisition may
make a separate HTTP request, but it is not a second evidence-data lookup and
cannot contribute facts. Rust bounds its response, accepts only the configured
token shape, clamps cache lifetime to the returned expiry and configured
maximum, and never logs the request URL, query, body, response, token, client
identifier, or secret. A provider that requires credentials in query
parameters is supported only by an explicit credential-placement setting and
the same redaction rule.

Every configured `http-json` source stage has one Rust-fixed host, method,
fixed path or closed Rust-expanded complete-segment path template, fixed
non-secret headers, permitted query and body channels, response projection,
TLS trust profile, timeout, redirect denial, maximum response size,
concurrency limit, and one request ceiling.
After authorization and durable access-attempt audit, a reviewed preparation
script renders ordered logical query pairs and at most one JSON body from only
the source-required authorized selectors and the exact closed adapter context
of non-secret parameters plus empty or schema-validated prior facts.
Rust validates the result, percent-encodes query components exactly once,
expands any tagged selector-bound or fetch prior-fact-bound path segments
without script involvement, and
constructs the request before credential acquisition. It applies the configured
extended JSON Pointer allowlist after bounded parsing and before extraction.
The core does not normalize names or implement source matching semantics.

An HTTP source may additionally declare `batch` with `maximumItems`,
`prepareScript`, `extractScript`, `responseSchema`, and `projection`. This block
is a one-call optimization only. It inherits the ordinary source method, fixed
origin and path, authentication, fixed headers, TLS, redirect denial, timeout,
maximum response bytes, concurrency semaphore, and request preparation limits.
It is rejected beside a path template or without bundle `source-batch`
capability. Runtime capability is the independent operator gate, and a source
block whose runtime gate is absent fails runtime binding before serving.
Omission of the optional block and an outer item count above its ceiling select
ordinary sequential execution before I/O. SQLite, path templates, and
multi-stage acquisitions are also sequential. A started optimized execution
never falls back, retries, fans out, or splits the outer batch.

Private-CA files are runtime bindings for logical bundle trust-profile names.
Hostname and fixed-origin verification remain mandatory. Version 1 has no
application-level proxy and ignores ambient HTTP proxy environment variables.

A `sqlite-extract` source has no origin, no credential, and no transport
security, because it opens one local file. Its Rust-fixed boundary is the
reviewed statement artifact under `queries/`, covered by the package sum file and
holding exactly one statement; the declared result columns in result order; the
declared parameter bindings, each with exactly one origin, either an authorized
selector or the optional preparation script; and its `maximumRows`,
`maximumCellBytes`, `maximumStatementSteps`, timeout, response-byte, and
concurrency bounds. Rust binds every value into the prepared statement by
index, so no value is rendered into statement text and a statement's shape is
identical for every request it serves. A statement takes no query string and no
request body, so the optional preparation script's whole channel is one bounded
map of scalar parameter values, validated for shape, entry count, value kinds,
and sizes before any row is read.

SQLite's authorizer decides every action the compiled statement would take
while the statement is prepared. It permits reads and refuses every write,
schema, and control action, including `ATTACH`, `DETACH`, `PRAGMA`, and
extension loading, along with a closed denied-function list covering the whole
clock family. A denied action fails the bundle at load and is never a
request-time failure. Rust binds its one evaluation instant to the reserved
`evidence_now` parameter, which a bundle may not declare, so a statement
needing the current time reads it there and a fixture run pinned to an instant
reproduces exactly.

The bundle names a logical `extractProfile` and the closed runtime file binds
it to one absolute path under `sourceExtracts`, exactly as it binds a private
certificate authority. Startup refuses a profile the runtime did not bind and a
binding no source names. The bound file must be a regular, non-symlink file
this process cannot write; its digest and file identity are captured and rechecked during startup,
and it is opened read-only and immutable. Its reserved `evidence_extract` table must
carry exactly one publication row, and the source's `maximumExtractAgeSeconds`
is compared against the evaluation instant before a single row is read. The
statement's select list is its projection, so Rust maps the bounded result set
into a tree of the declared column names and nothing the statement did not
select exists to be removed.

The request asks the provider for only enough information to distinguish no
match, one match, or ambiguity and to produce the declared facts. Prefer a
count plus one minimized result. When the API cannot provide that shape,
request at most two minimally projected results and never follow pages. Rhai
may map their cardinality but must not score or choose between candidates. A
requirement derivation may compare minimized facts from one unique
authoritative record with its separately authorized selectors using a
deterministic, versioned rule.

A SQLite source instead names one logical extract profile and one bundle-fixed
statement. The runtime binds the profile to a regular, read-only, checkpointed
file, opens one connection per concurrency permit with `mode=ro` and
`immutable=1`, validates publication metadata, and prepares the statement under
the deny-by-default authorizer before serving. Rust binds selectors, optional
prepared scalars, and the reserved evaluation instant. This phase is complete
only when SQL text, extract paths, and source values never enter diagnostics,
logs, or audit.

A source that cannot expose this bounded lookup directly, or through a
publisher-produced extract, is not compatible with Version 1. It requires an
external governed integration service. Do not add a bulk read, local matching
database, probabilistic matcher, or candidate-ranking script to Evidence as a
workaround.

## Source-shape contract suite

The suite is five minimal local profiles. The four HTTP profiles exercise
different wire contracts through the same HTTP source executor; the statement
profile exercises the other transport. All five use the same evaluator, output
gate, signer, and audit path.

| Profile | Boundary shape | What it proves |
|---|---|---|
| `flat-rest` | Fixed JSON request and flat JSON object | Identifier and compound selector contracts plus direct fact extraction |
| `dhis2-tracker` | `GET` query, selected fields, pager, collection, nested attribute array, Basic auth | REST query encoding, compound selectors, cardinality, pagination refusal, and code-based extraction |
| `opencrvs-event-search` | OAuth client token, bounded JSON `POST`, nested event index, and country-configured declaration | Credential bootstrap, exact tracking-ID lookup, nested extraction, and selector-aware relational derivation |
| `search-chain` | Fixed JSON `POST` search, then a path-bound dereference member and a body-filtered search member in declared order | Ordered multi-stage acquisition, per-member fact-input projection through both the path and the body channel, a provider count read as a value rather than a cardinality guard, and a silently widened query reaching ambiguity |
| `sqlite-extract` | One reviewed SQL statement with declared result columns and named parameter bindings, over a read-only extract file materialized from a committed text seed | Bundle-fixed statement authority, the prepare-time authorizer verdict, one declared origin per parameter, the reserved evaluation instant, publication metadata and staleness refusal, and row, cell, statement-step, and time bounds |

These are compatibility-shaped mocks, not whole-product emulators or claims of
certified DHIS2 or OpenCRVS support. Fixtures are small, invented, and
hand-authored from public documentation. No captured live response is checked
in. A source-specific behavior is added to the mock only when Evidence relies
on it.

The profile names do not become runtime identifiers. Production code sees only
generic HTTP request material or a generic reviewed statement and bound extract,
plus transport-neutral bounded JSON. Basic, Bearer, and OAuth
client-credentials support must each have a generic contract and tests
independent of either named product.

`sqlite-extract` is the one row that is a runtime identifier, deliberately so:
it names the second transport as configuration names it rather than a mock wire
shape. Its cases build a real extract file from a committed text seed inside
the process that reads it, so the reviewed statement executes for real and
nothing is replayed. Version 1 ships no recorded source-shape fixture for it,
because such a fixture would carry a binary file rather than a readable
response. Production code still sees only generic SQL over a generic SQLite
file, generic publication metadata, and parsed values; no table or column name
is known to the runtime beyond the reserved `evidence_extract` metadata table.

The suite must prove at least:

- exact HTTP method, path, query, body, fields, headers, and authentication;
- exact SQLite statement, parameter origins and values, declared result
  columns, publication metadata, and resource bounds;
- identifier-only, no-identifier compound, additional-disambiguator, and
  multi-role selector profiles with deployment-defined field names;
- missing, extra, unknown, mistyped, oversized, or unauthorized selector input
  rejected before credential acquisition and source access;
- no fetch after a search returns zero or multiple results, and no request
  beyond the ceiling the acquisition fixes in configuration before any call is
  made: one call, two calls, or one per declared stage of a gated set;
- configured `pageSize` detects ambiguity rather than following pagination;
- no broad candidate list, score, near-match diagnostic, or comparison detail
  is returned to the caller, logs, audit, or evidence;
- malformed event-index envelopes and incomplete declarations fail closed;
- credentials, raw selector values, source values, and response bodies are
  absent from logs, audit, errors, snapshots, and assertion messages;
- `401`, `403`, `429`, `5xx`, timeout, redirect, invalid JSON, wrong media type,
  oversized response, missing fact, zero matches, and multiple matches;
- switching among source profiles and transports requires bundle, runtime
  binding, fixture, and Rhai changes only, with no domain branch in Rust.

The OpenCRVS shape may support an adult-status fixture because a birth record
can supply a date of birth. The DHIS2 shape should exercise a controlled code
or status instead, so the compatibility suite also resists adult-status
overfitting.

## Rhai contracts

The ordinary evaluation path uses three functions with separate
responsibilities. The optional fixed-path HTTP batch optimization adds two
source functions:

```text
prepare(source_required_selectors, adapter_context) -> RequestParts
extract(source_response, adapter_context) -> LookupResult
derive(facts, declared_authorized_selectors, evaluation_context)
    -> array<DerivedConceptValue>
prepare_batch(items, {parameters}) -> RequestParts
extract_batch(response, {parameters, slots}) -> array<{slot, result}>
```

`adapter_context` has the exact keys `parameters` and `prior_facts`.
`prior_facts` is empty except when Rust supplies the schema-validated search
FactSet to a fixed fetch source, whole or projected onto the allowlist that
stage declares.

`prepare_batch` receives one ordered exact `{slot, selectors}` map per logical
item. Selectors have the ordinary minimized source shape; `slot` is a
Rust-issued opaque integer used only for correlation. `extract_batch` receives
the batch projection after its response schema and bounds have passed, plus the
exact slot list but no selectors. It returns each slot exactly once with one
ordinary `LookupResult`; ordering may differ because Rust restores request
order. Missing, duplicate, extra, negative, non-integer, or out-of-range slots
abort the outer request as a source-protocol failure.

`LookupResult` is exactly `match(FactSet)`, `no_match`, or `ambiguous`. The
source adapter performs source-specific response parsing and cardinality
mapping. It is not separately given the request selector profile or values and
cannot make another source call, return candidates, or choose one row from an
ambiguous result. If a `record-transformed` source response repeats a selector
value, it is protected source data and cannot leave the declared fact boundary.
Rust rejects facts on a non-match outcome and does not invoke derivation unless
the outcome is `match`.

The requirement derivation implements country-specific, sector-specific, or
legal meaning over the uniquely matched facts. It may compare those facts with
only the authorized selector roles and fields declared by the derivation.
Preparation,
extraction, and derivation run in the same Evidence process as separate,
startup-compiled scripts in the immutable bundle.

The evaluation context contains only:

- the observation instant;
- legal local date and time resolved by Rust from the configured IANA timezone;
- fixed typed parameters from the selected requirement;
- bounded access to named, versioned bundle codelists.

Authorized selectors are a separate explicit derivation input. The evaluation
context never contains requester identity, actor identity, purpose, audience,
grants, tokens, credentials, source clients, logging handles, audit handles,
signing keys, filesystem access, network access, process access, ambient clock
access, or randomness.

### Primitive standard library

Rust provides a small, versioned set of pure and bounded primitives:

- typed ISO calendar dates and instants;
- comparison and calendar-safe addition for dates and durations;
- bounded numeric comparison and bucketing;
- controlled-code lookup in named bundle codelists;
- bounded list and set membership;
- explicit missing-value handling.

The library contains no operation named for a use case. For example, adult
status can be expressed conceptually as:

```text
attainment_date = add_calendar_years(date_of_birth, minimum_age_years)
adult_status = legal_date >= attainment_date
```

`minimum_age_years` comes from trusted YAML, not the caller. The bundle fixes
the exact reference framework, date semantics, timezone, and boundary fixtures.

Every primitive has explicit input and output types, maximum sizes, deterministic
behavior, and focused boundary tests. A primitive is added only for a generic
operation that cannot be expressed safely with the existing set. Adding a new
evidence definition should normally require no Rust change.

### Output gate

Rust accepts `array<DerivedConceptValue>` only when:

- every returned concept is declared by the selected requirement;
- every required concept is present exactly once unless its schema says
  otherwise;
- no extra concept or metadata field exists;
- each value matches its scalar, controlled-code, bounded-list, or reviewed
  structured schema;
- codelist, cardinality, string, collection, and total-result limits pass.

Rhai never creates the Evidence identifier, issuer, provider, requirement,
Evidence Type, purpose, audience, subject bindings, timestamps, configuration
revision, JWS headers, signature, or audit record.

## Required Version 1 acceptance tests

At minimum, pin these acceptance and negative cases:

1. Missing configured principal claim denies without `client_id` or `azp`
   fallback.
2. Unknown or unauthorized requirement, purpose, audience, selector profile,
   selector value origin, or subject path never acquires source credentials or
   contacts the source.
3. Caller-supplied identifier or compound selector value never creates
   authority.
4. Access-audit failure prevents the source request.
5. Each source operation remains fixed by trusted configuration: HTTP method,
   URL, fields, credentials, size, timeout, and redirect behavior; or SQLite
   statement, parameter origins, result columns, extract profile, and resource
   bounds.
6. Rhai cannot access network, filesystem, environment, credentials, clock,
   logging, audit, or signing material.
7. Extra, missing, mistyped, or oversized derived values are rejected.
8. Source data and disclosed values are absent from logs, audit, and errors.
9. Disclosure-audit failure prevents response release.
10. Signing failure returns a safe transient error and never falls back to
    unsigned evidence.
11. JWS verification fails after any protected-header or payload mutation.
12. A valid false boolean result is a success in either authorized response
    format, not an error.
13. `no_match`, `ambiguous`, and missing fact do not create an unintended
    existence oracle and use the same public failure by default.
14. Legal-timezone and calendar-boundary fixtures are deterministic.
15. Unsafe combinations, including threshold ladders and overlapping
    categories, are rejected at bundle review or validation.
16. Flat REST, DHIS2 Tracker-style REST, and OpenCRVS Version 2 Event
    Search-style JSON mocks all use the generic HTTP executor, while the
    sanitized extract uses the generic statement executor and joins the same
    transport-neutral evaluation path afterward.
17. Zero, one, and multiple results map consistently to `no_match`, `match`,
    and `ambiguous` across all HTTP shapes and the SQLite extract; facts exist
    only on `match`.
18. Event-index envelope errors and incomplete declaration data fail closed.
19. OAuth token requests and responses are absent from all diagnostics, and
    no placement can put client credentials in the token URL.
20. Live-source tests are ignored by default, read-only, and refuse missing or
    permissively stored credential files.
21. Adult status passes the complete path with before, on, and after-boundary
    dates in the configured legal timezone.
22. Residence region passes the complete path with valid, unknown, and
    overly precise codes and a pinned codelist version.
23. Professional licence status passes the complete path with multiple
    concepts, validity boundaries, and proof that exact dates and history are
    absent from evidence and diagnostics.
24. Legal-parent relationship passes the complete path with correct roles,
    swapped roles, unauthorized candidate substitution, false relationship,
    returned-child mismatch, missing relationship, ambiguous lookup, and
    ambiguous relationship facts.
    The selector-aware derivation proves exact governed membership; `false` is
    signed only after unique child resolution and a complete valid parent set.
25. All four definitions run together and under concurrency without state,
    subject, source, audit, limit, or result leakage.
26. At least one acceptance definition runs against both source transports
    with only bundle, runtime binding, fixture, and Rhai changes.
27. A repository boundary check rejects DHIS2 or OpenCRVS names and behavior in
    production Rust, Cargo dependencies and features, public configuration
    schemas, routes, and CLI options.
28. JSON Schema and OpenAPI drift checks reproduce committed artifacts exactly.
28a. Provider discovery compilation packages deterministic shared-profile bytes;
    startup rejects a missing, extra, or drifted package artifact; the route
    serves those exact packaged bytes without authentication or side effects;
    each independently searchable Evidence Type and compatible profile pair has
    a distinct derived binding identity that cannot be graph-merged into a false
    cross-requirement match; and closed-projection
    negatives prove source, authorization, credential, signing, audit, and
    internal deployment fields are absent. Publication-only changes move the
    package digest but not any assertion-semantic requirement revision.
28b. Each step of a planned signing-key rotation, publishing the next public
    key, activating it, and retiring the previous one, and an emergency
    revocation through `signing.revokedKeyIds` move the package digest but not
    any requirement revision, because key trust travels in the JWKS and the
    policy denylist rather than in the revision a relying party pins. An
    emergency identity-provider key revocation through
    `authentication.revokedKeyIds` likewise moves the package digest but not
    any requirement revision, because it changes which callers are accepted,
    not what an assertion means.
29. Every declared Supported Value form rejects wrong scalar types, unknown
    codes, invalid entity references, excessive precision, oversized strings,
    oversized lists, duplicate values where prohibited, and wrong
    cardinalities, and each valid form survives Evidence construction, JWS
    serialization, and verification without type loss.
30. `source-derived`, `field-projected`, and `record-transformed` definitions
    use the same executor and report their acquisition guarantees honestly.
31. A serving process cannot reload, mutate, merge, or fall back to another
    package digest at runtime.
32. No test, log, trace, metric, audit event, snapshot, panic, or failure
    artifact contains the canary credentials, raw selector values, source
    facts, or Supported Values used by the acceptance suite.
33. An identifier-only selector profile and a compound selector profile with no
    identifier both pass the complete service path.
34. Missing required, unknown, extra, mistyped, empty, oversized, and
    aggregate-oversized selector fields fail before credential acquisition or
    source access, with no protected value in the error.
35. Alternative sufficient field sets and sets with an additional
    disambiguating field require distinct named profiles and are never inferred
    from caller input.
36. At least one selector profile uses deployment-defined field names that have
    no person, identifier, EU, UK, DHIS2, OpenCRVS, or acceptance-case meaning
    to Rust.
37. Unicode and multipart name-like values pass as bounded opaque strings.
    Core behavior does not case-fold, transliterate, tokenize, apply phonetics,
    parse Western name order, or perform partial-date matching.
38. Provider ambiguity never causes a second data request, page traversal,
    retrieval beyond the configured maximum of two minimally projected
    results, candidate choice, derivation execution, or success response.
39. Candidate records, candidate counts beyond the closed outcome, scores,
    confidence, near-match hints, and field-by-field comparison results are
    rejected by the extraction boundary and absent from public responses.
40. Native audit records at most the selector-profile id and one scoped keyed
    pseudonym over each complete canonical role and selector bundle. Separate
    hashes of names, dates, addresses, identifiers, or other low-entropy fields
    fail redaction tests.
41. Context-derived and authenticated-grant-derived selector profiles reject
    caller-provided values; an authorized request-derived caseworker profile
    accepts only its configured closed field set.
42. Evidence and the JWS payload never echo selector profile ids or values, and
    audience-scoped subject bindings do not become globally stable identifiers.
43. Failed selector attempts are bounded per principal and authority profile
    without using raw selector values as metric or rate-limit labels.
44. All four initial assertion cases pass their assigned selector shapes and
    lookup outcomes through offline fixtures, local HTTP mocks or a local
    sanitized extract, the real router, both audit gates, signed JWS,
    explicitly authorized unsigned output, and strict verification on one
    revision.
45. Governed package and runtime configuration have separate closed schemas,
    package-digest verification, one-time read-only runtime capture, and negative
    tests proving runtime fields cannot override sources, authorization,
    disclosure, limits, signing, or audit policy.
46. Fixed paths and tagged selector or fetch prior-fact path templates pass exact encoding tests.
    Missing, extra, duplicated, slash, backslash, percent, control, empty, and
    dot-segment bindings fail before credential acquisition or source access.
47. Fixed non-secret headers, static Authorization header, and static API-key
    authentication pass generic exact-request and redaction tests. Forbidden,
    duplicate, framing, routing, forwarding, proxy, tracing, cookie, and
    authentication header collisions fail at startup.
48. System roots and logical private-CA trust profiles pass positive TLS tests.
    Unbound, malformed, insecure, symlinked, mutable, or hostname-bypassing CA
    configurations prevent readiness, and ambient HTTP proxy environment
    variables cannot redirect evidence-data or OAuth requests.
49. Extended JSON Pointer response projection passes flat, nested, array,
    literal-dot-key, missing-leaf, mistyped-intermediate, invalid-escape,
    duplicate, overlap, size-before-projection, and privacy-canary tests. Rhai
    sees only the projected tree while posture reflects the pre-projection wire
    response.
50. `parse_integer` accepts the documented ASCII grammar and leading zeroes and
    rejects empty, plus-prefixed, whitespace, non-ASCII, fractional,
    exponential, and overflowing values. Query values remain strings and no
    implicit value-to-string conversion is introduced.
51. Public request subjects are resolved uniquely by role rather than array
    position. Permutations produce the same authorized internal role order;
    duplicate, missing, unknown, or wrong-profile roles fail before credentials
    or source access.
52. The request nonce is exactly the canonical 43-character unpadded base64url
    encoding of 32 bytes; missing, duplicate, padding, noncanonical encoding,
    malformed alphabet, wrong length, and excessive length fail before
    credential acquisition or source access. Nonce canaries never reach
    authorization, Rhai, source preparation, source calls, logs, or audit.
53. Signed Evidence echoes the exact request nonce; changing the expected or
    signed nonce fails verification, and nonce reuse is not represented as
    replay prevention.
54. The verifier requires independently trusted expected subject roles and
    opaque bindings plus expected concept identifiers, forms, and cardinalities
    after signature verification. Missing, extra, duplicated, substituted, or
    wrong-key-version bindings and unexpected output fail; subject order alone
    is non-semantic.
55. Missing `Accept`, `*/*`, and exact signed media select JWS. Only exact
    unsigned media selects unsigned JSON. Duplicate, combined, parameterized,
    weighted, or unknown negotiation fails before source access.
56. Unsigned selection succeeds only when both the bundle and matched authority
    grant permit it. Caller selection, runtime configuration, or a different
    grant cannot create permission.
57. Signing or signed-release failure never returns unsigned output. An
    explicitly authorized unsigned request performs no signing operation and
    still requires the ordinary signing dependency to be ready.
58. The unsigned envelope has its exact vendor media type, schema, type,
    integrity marker, warning, closed nested Evidence, and no `protected`,
    `payload`, `signature`, or signing-key claim. The JWS verifier rejects it.
59. Both response formats serialize final immutable bytes and require durable
    disclosure-release audit before releasing them. Admission to that append is
    the final acquisition-deadline gate; an admitted append completes without
    cancellation and may return the exact bytes after expiry. Audit records the closed
    protection mode and conditionally requires or forbids `signingKeyId`
    without recording nonce, selectors, source values, or disclosed values.
60. All four coequal definitions pass signed and explicitly authorized unsigned
    paths through the same router, source executor, derivation, output gate,
    subject binding, minimization, and audit logic without domain branches.
61. Verification tooling re-verifies a stored signed response against a pinned
    trusted key, expected policy, request nonce, subject bindings, and output
    contract, and reports cryptographic authenticity separately from current
    validity.
62. Authenticated `GET /v1/evidence-definitions` returns only complete request
    shapes matching exactly one authority path for the verified caller and
    valid token-owned selector material. Unentitled callers receive an empty
    list; ambiguous shapes are omitted; source identifiers and plans, scripts,
    credentials, authority-profile names and tags, selector values, codelist
    values, and unrelated definitions are absent; no provider request or
    evidence-data audit event occurs.
63. An authorization refusal after successful authentication durably appends
    exactly one standalone minimal denial event with the
    `registry.evidence.audit.authorization-refusal/v2` discriminator before
    returning the generic `403`. The event contains the scoped requester
    pseudonym and optional actor pseudonym but omits the requested requirement,
    purpose, subjects, unmatched authority, selector information, response
    protection, source, and evaluation material. Append failure returns the
    generic `503`, no source credential is acquired, and no source request is
    made. Authentication, malformed-request, and invalid-selector failures
    create no native audit event.
64. A `search-then-fetch` requirement executes one fixed audited search and,
    only after a unique schema-valid match, one fixed audited fetch whose path
    may use a declared scalar search fact. Only the final fetch FactSet reaches
    derivation; the effective posture is the weaker source posture; search
    no-match or ambiguity makes no fetch; no intermediate fact enters audit;
    and no script or response can select transport or cause a third call.
65. A `search-then-fetch-set` requirement executes one fixed audited search
    and, only after a unique schema-valid match, one fixed audited call per
    declared member in declared order. Each member receives only its declared
    fact-input allowlist through every channel, including the body its
    preparation builds; derivation receives the union of the stage FactSets,
    whose names startup proved disjoint; an unresolved stage contacts no later
    member; and the disclosure-release event names every executed source in
    order.
66. A gated acquisition kind serves only where the bundle declares it and the
    operator separately enabled it in the runtime configuration, refused
    before the listener binds and reported by both `evidence check` and
    `evidencectl doctor`. The declared acquisition ceiling bounds the source
    exchanges and the transitions between stages as a dependency failure under
    its own safe category. The deadline also gates admission to terminal
    disclosure release. An already admitted durable append completes without
    cancellation, and a signed source's verified `validUntil` remains an
    independent bound.
67. A `sqlite-extract` source executes one package-fixed reviewed statement
    against the extract the runtime bound, returns the declared columns in
    result order beside the extract's own publication row, and presents no
    credential of any kind.
68. The prepare-time authorizer refuses every write, schema, and control
    action, `ATTACH`, `DETACH`, `PRAGMA`, extension loading, non-deterministic
    functions, and the whole clock family. A denied action fails the bundle at
    load and never at request time.
69. A second statement in the artifact, declared columns disagreeing with the
    real result columns, and statement parameters disagreeing with the declared
    bindings each fail at startup naming the statement artifact. The offline
    check settles everything a statement alone can settle and never reports a
    false failure; opening the bound extract settles the rest, and a source
    compiled without an extract materializes but refuses to run.
70. The reserved `evidence_now` parameter carries the one evaluation instant
    the assertion reports, in the rendering the assertion reports it. A bundle
    declaring that name is refused, and a fixture run pinned to an instant
    reproduces the same result.
71. Every statement parameter is filled from its one declared origin. A
    preparation script cannot fill a selector parameter, return a name the
    source never declared, reach the reserved name, or leave a declared
    prepared parameter unfilled, and a preparation script and a prepared
    parameter are refused unless declared together. The prepared parameter map
    is held to its declared entry count, value kinds, and sizes before any row
    is read.
72. The declared row, cell, statement-step, time, and response-byte bounds each
    refuse under their own closed cause, with the step and time bounds enforced
    inside the engine by the progress handler and a cell refused before an
    owned value is built. A cancelled request gives back its connection and its
    permit.
73. A bound extract must be a regular, non-symlink file this process cannot
    write, and its digest and file identity are captured and rechecked during startup. An extract
    profile the runtime did not bind, a binding no source names, and a path
    replaced between its digest and its opening each fail at startup by name
    and cause.
74. An extract with no reserved metadata table, with other than exactly one
    row, missing a column, or carrying a malformed field is refused at startup.
    The declared `maximumExtractAgeSeconds` is compared against the evaluation
    instant before any row is read, is inclusive at the bound, and refuses a
    stale extract as a dependency failure naming only its governed extract
    profile.
75. No rendering, diagnostic, log, snapshot, or audit record carries statement
    text, a bound parameter value, a result value, the extract path, or engine
    message text. A genuine syntax fault carries a line and a column counted in
    characters and no text, and an unknown table, an unknown column, and a
    refused statement are told apart without one.
76. Professional licence status passes over the statement transport through
    offline fixture evaluation against a real extract materialized from a
    committed text seed, using the same concept, derivation, output gate, and
    signing path the HTTP transport uses. No match, ambiguity, the row bound,
    staleness, and a missing parameter reach their request outcomes; the source
    contract suite proves a refused statement fails at startup. Extract columns
    the statement never selects are absent from every assertion and diagnostic.
77. `POST /v1/evidence/batch` requires exact
    `application/vnd.registrystack.evidence.request-batch+json`, accepts one
    through sixteen ordered items under one requirement and purpose, and
    rejects malformed, noncanonical, or repeated nonces before source access.
    The route accepts no holder keys, unsigned or SD-JWT VC format, or
    holder-bound issuance media type.
78. One batch authenticates the bearer token once, mints one operation, uses
    one evaluation instant for every available assertion, and atomically
    charges the principal's rate bucket by item count. An insufficient bucket
    charges nothing and contacts no source.
79. Selector resolution, complete request validation, and one full
    authorization decision per item finish before source credential resolution
    or I/O. Items may resolve through different grants or authority kinds;
    failure of any item aborts the outer request before access.
80. Sequential strategy supports `single`, `search-then-fetch`,
    `search-then-fetch-set`, SQLite, path templates, and ordinary fixed HTTP in
    exact request order. Omitted source batching, ineligible sources, and a
    complete batch above `maximumItems` select sequential execution before I/O.
81. The closed `registry.evidence-request-batch/v1`
    `EvidenceRequestBatchResponse` contains exactly one ordered member per
    request. Available members carry flattened signed JWS. Every condition the
    singular collapse contract exposes as `evidence-not-available` becomes
    that item outcome, including mixed and all-unavailable `200` envelopes.
    Every other failure returns the existing safe outer problem and releases no
    partial member.
82. Optimized source batching requires bundle and runtime `source-batch`
    capability, a `single` acquisition, one fixed-path `http-json` source, and
    its complete `batch` block. The one call reuses ordinary method, origin,
    path, authentication, headers, TLS, redirect, timeout, response,
    concurrency, and preparation bounds; the block cannot override them.
83. `prepare_batch` receives only ordered `{slot, selectors}` items and
    `{parameters}`. `extract_batch` receives only the validated projected
    response and `{parameters, slots}` and must return an exact slot bijection
    over ordinary lookup results. Missing, duplicate, extra, negative,
    non-integer, or out-of-range slots abort globally, and no optimized failure
    retries through sequential fanout.
84. `registry.evidence.audit.request-batch/v1` writes one access event before
    every physical source call with bounded item indices and item groups by
    identical authority plus pseudonymized subject set. It writes exactly one
    terminal release covering every ordered outcome or one value-free terminal
    failure on abort. An all-unavailable release carries no signing key id.
    Nonces, selectors, facts, bodies, and signed material are absent. The exact
    complete envelope is limited to 1 MiB, serialized before durable release
    audit, and returned byte-for-byte afterward.

Cases 67 through 76 are traced to their executable tests by the
`sec-statement-source-bounded` entry in
`contracts/security-test-traceability.yaml`, under invariant `V1-I43` of
`contracts/security-invariant-matrix.yaml`.

## Verification gates

During implementation, run package-scoped checks while iterating and the
complete package gate at every phase exit:

```text
cargo fmt --check
cargo check --locked -p registry-evidence --all-targets
cargo test --locked -p registry-evidence
cargo clippy -p registry-evidence --all-targets -- -D warnings
```

The deterministic source mocks are part of ordinary package tests. Public
demo tests live in a separate ignored integration-test target and run only
after the package suite succeeds:

```text
cargo test --locked -p registry-evidence --test source_contracts
cargo test --locked -p registry-evidence --test statement_source
cargo test --locked -p registry-evidence --test live_sources dhis2 -- --ignored
cargo test --locked -p registry-evidence --test live_sources opencrvs -- --ignored
```

The exact environment loading and live-data rules are in
[SOURCE-TESTING.md](SOURCE-TESTING.md). Live tests never run in CI, never use
credentials on the command line, and never turn an unavailable or changed
public demo into a product regression.

Before a PR, also run the root workspace checks selected by CI, the Evidence
contract command that regenerates and compares JSON Schema and OpenAPI, and the
source-product-neutrality check that scans production code and Cargo metadata.
The full release gate includes:

```text
cargo fmt --check
cargo metadata --locked --format-version 1
cargo check --locked --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
products/evidence/scripts/check-contracts.sh
products/evidence/scripts/check-source-neutrality.sh
products/evidence/scripts/check-verifier-portability.sh
```

Generated artifacts are reproduced from code, never hand-edited. If a shared
platform crate changes, run its affected consumer tests during iteration as
well as the final workspace gates.
