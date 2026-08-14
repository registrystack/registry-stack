# Evidence Implementation Approach

Status: Approved Version 1 implementation schedule and Definition of Done
Date: 2026-08-09

Source-contract and local-smoke details: [SOURCE-TESTING.md](SOURCE-TESTING.md)

## Outcome

Implement the complete Evidence Version 1 contract defined by `CONCEPT.md`.
The work is not complete when one assertion works. It is complete only when
the full API, bundle, source, authorization, Rhai, validation, signing, audit,
operations, and verification boundaries satisfy the Definition of Done in this
document across the complete acceptance-definition set.

No acceptance case is the architectural seed or an implementation milestone.
Adult status, controlled region, professional licence status, and legal-parent
relationship are coequal proofs of a generic engine from the first offline
phase onward. The implementation schedule stops at the Version 1 boundary. It
does not begin any capability listed under `CONCEPT.md` section 15, Future
profiles and guarded extensions.

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
    relay_shaped_source.rs
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
| `registry-platform-audit` | Keyed chain integrity, scoped pseudonymization, JSONL sink, and chain verification |
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
| Statement source | A reviewed statement artifact covered by the bundle hash, a prepare-time authorizer verdict, required extract publication metadata, a bundle-declared maximum extract age, and declared row, statement-step, cell, and time bounds |
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
   binding. Reject missing, unknown, or extra material.
7. Make one authorization decision over requester, optional actor, requirement
   revision, purpose, role-bound selector profiles and value origins, subject
   authority, audience, and response format.
8. On authorization refusal after successful authentication, durably write a
   standalone minimal denial event with the
   `registry.evidence.audit.authorization-refusal/v1` discriminator and return
   the generic `403`. The event contains no requested requirement, purpose,
   subjects, unmatched authority, selector information, response protection,
   source, or evaluation material. If the audit append fails, return the
   generic `503` instead.
9. Durably write the access-attempt audit event with at most one scoped keyed
   pseudonym over each complete canonical role and selector bundle.
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
18. Durably write the pseudonymized disclosure-release audit event with the
    closed response-protection mode and a signing key id only for JWS.
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
   `evidence_not_available` to that per-item outcome, including no-match,
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
  HTTPS token endpoint, a fixed grant, an optional fixed scope and audience,
  and exactly one client authentication form: a client secret reference with a
  fixed placement, or a private-key reference the runtime signs a JWT client
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
reviewed statement artifact under `queries/`, covered by the bundle hash and
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
this process cannot write; it is digested into the computed runtime revision
and opened read-only and immutable. Its reserved `evidence_extract` table must
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

## Version-one acceptance definition set

All four initial assertion cases in `CONCEPT.md` are mandatory, full-path
acceptance definitions. None is merely an illustrative fixture or a follow-up
generality check.

| Case | Input facts | Supported Values | Generic capability proved |
|---|---|---|---|
| Adult status | Date of birth or source-derived status | Boolean | Unary assertion, calendar arithmetic, legal-time boundary, and false-as-success semantics |
| Residence region | Official residence code or bounded address field | Controlled region code | Codelist mapping, geographic coarsening, and bounded category disclosure |
| Professional licence status | Licence state and validity dates | Active boolean plus controlled expiry bucket | Multiple concepts, time bucketing, and omission of exact dates and history |
| Legal-parent relationship | Child and candidate-parent roles plus an authoritative relationship fact | Relationship-confirmed boolean | Multiple role-bound subjects, subject substitution resistance, and relationship-specific semantics |

The test bundles deliberately vary selector shapes:

- adult status uses a compound person selector without an identifier;
- residence uses an opaque identifier profile;
- professional licence uses a compound sector selector;
- legal-parent relationship uses two role-bound selectors and exercises both an
  identifier profile and a no-identifier compound profile.

These are fixture choices, not product semantics. At least one additional
fixture uses deployment-defined field names that are not `given_name`,
`family_name`, `birth_date`, `person_id`, or another built-in-looking
vocabulary. Changing those names or mappings changes YAML, source fixtures, and
Rhai only.

Each case has a complete test-only bundle with YAML, Rhai extraction, Rhai
derivation, codelists where needed, positive, negative, boundary,
missing-record, missing-fact, source-failure, and anti-reconstruction fixtures.
Each must pass offline evaluation and the production service pipeline, including
authentication, authorization, source execution, access audit, output gating,
evidence construction, signing, release audit, and verification.

Production Rust contains no type, operation, field, route, feature, or branch
named for adult status, age thresholds, residence, licence, parentage, DHIS2,
or OpenCRVS. Adding or changing any acceptance definition changes test bundles
and Rhai, not the core domain model.

## Implementation schedule

This is a dependency sequence, not a set of partial product releases. Every
phase must preserve all acceptance definitions introduced in Phase 0.

### Phase 0: freeze Version 1 contracts and DoD

- Promote accepted contracts into tracked `products/evidence` material when
  Jeremi authorizes implementation.
- Freeze the CCCEV-to-JSON profile, public request, request-nonce, JWS, and
  unsigned-envelope response schemas,
  governed-bundle and runtime YAML schemas, their ownership split, bundle
  layout, selector-profile contract, `LookupResult` and derivation Rhai ABIs,
  generic primitive set, source contract, normalized
  authority context, authorization inputs, audit event schemas, problem codes,
  signing profile, content negotiation, response-format authorization, and
  verifier rules.
- Create the four acceptance-definition bundles, the HTTP source-shape mocks,
  and the sanitized SQLite extract contract before production architecture is
  written.
- Create identifier-only, no-identifier compound, additional-disambiguator,
  and multi-role selector fixtures before production architecture is written.
- Create conformance fixtures for every Supported Value form and every
  source-access posture declared for Version 1.
- Freeze the project fixture vocabulary, response-projection grammar, fixed
  header rules, tagged selector/prior-fact path-template rules, source-authentication
  profiles, private-CA bindings, and ambient-proxy rejection.
- Map every security invariant to its threat, Rust enforcement point, and
  negative test.
- Record the future-profile stop boundary from `CONCEPT.md` section 15.

Exit gate: every Version 1 contract and every DoD row is reviewable; no future
profile has a placeholder API, module, configuration field, or extension hook.

### Phase 1: generic offline kernel

- Create the single crate and binary with typed domain models, bundle loading,
  atomic hashing, and startup validation.
- Implement `evidence check` and fixture-only `evidence evaluate`.
- Implement bounded Rhai extraction and derivation, the domain-neutral
  primitive library, exact output gating, and deterministic Evidence JSON
  construction.
- Implement generic selector-profile parsing and validation without any
  identity field vocabulary or matching algorithm in Rust.
- Add fixture signing solely to verify the complete evidence model offline,
  including independently expected nonce, subject-binding, and output-contract
  checks.
- Run all four acceptance definitions through the same kernel.
- Run type, size, precision, code, reference, list, and cardinality fixtures
  for the complete Supported Value contract.

Exit gate: all four cases pass offline, including their boundary and negative
fixtures, and production Rust contains no case-specific branch or type.

### Phase 2: generic source boundary

- Implement the fixed-authority HTTP JSON data-request executor with bounded
  response parsing, denied redirects, timeouts, concurrency limits, reviewed
  query/body rendering, fixed non-secret headers, selector- or validated
  prior-fact-bound path
  templates, private-CA trust profiles, and exact client-side response
  projection.
- Implement the reviewed-statement executor over a read-only mounted SQLite
  extract, including exact statement/column/parameter agreement, a
  deny-by-default prepare-time authorizer, publication metadata and maximum
  age, strict value typing, a runtime-bound evaluation instant, and row, cell,
  statement-step, elapsed-time, response-size, and concurrency bounds.
- Implement the closed `single` and `search-then-fetch` acquisitions. The
  latter fixes two source identifiers, validates the search FactSet before the
  fetch, audits each call, and exposes no third-call or response-led routing
  surface.
- Implement generic HTTP Basic, static Authorization header, static API-key
  header, and OAuth 2.0 client-credentials providers using secret references,
  the last authenticating by client secret or by private-key JWT assertion.
- Bind credential-free source access to explicit local assurance and an exact
  numeric-loopback HTTP origin, with no authentication header on the wire.
- Implement strict provider-text `parse_integer` without enabling implicit
  query-value conversion or a provider-resolution DSL.
- Run flat REST, paged nested REST, and Event Search-shaped local mocks through
  the HTTP executor, and a sanitized published extract through the statement
  executor.
- Cover all four acceptance definitions across the source-shape matrix and run
  at least one definition against two different shapes using only YAML and
  Rhai changes.
- Prove identifier, compound no-identifier, additional-disambiguator, and
  multi-role selectors; prove zero, one, and multiple outcomes without broad
  candidate retrieval or candidate exposure.
- Add a repository check that rejects DHIS2 or OpenCRVS names, dependencies,
  features, modules, types, and branches in production source, Cargo metadata,
  and generated public contracts.
- Prove ambient proxy variables cannot redirect either evidence-data or OAuth
  requests, and prove unbound, malformed, mutable, or insecure private-CA files
  prevent readiness.
- Implement the reviewed-statement executor over a read-only mounted SQLite
  extract: one bundle-fixed statement artifact holding exactly one statement,
  a prepare-time authorizer verdict, declarative parameter bindings with one
  origin each, an optional bounded preparation map, the reserved evaluation
  instant, and declared row, cell, statement-step, timeout, response-byte, and
  concurrency bounds.
- Bind each logical extract profile to one runtime-named file, refuse an
  unbound profile and a binding no source names, refuse a symlinked,
  non-regular, or writable file, digest the bound file into the computed
  runtime revision, and prove the statement's result columns and parameters
  against the real extract at startup.
- Require the reserved publication-metadata row and refuse an extract past its
  bundle-declared maximum age against the evaluation instant, before any row is
  read.
- Run one acceptance definition over the statement transport against a real
  extract materialized from a committed text seed, and keep statement text,
  bound parameter values, result values, the extract path, and engine message
  text out of every diagnostic, log, snapshot, and audit record.
- Prove missing, unbound, writable, uncheckpointed, or metadata-invalid
  extracts prevent serving before any request reaches them.

Exit gate: all source contract tests pass on both transports, no
product-specific source code exists, and no source value, raw selector value,
credential, token, or response reaches logs, audit, errors, or disk. A denied
statement action, an unbound or unusable extract, and a disagreement between a
statement and the extract it reads fail before the deployment serves, and no
statement text, bound value, or extract path reaches a diagnostic.

### Phase 3: trust, authorization, audit, and signing

- Implement the strict OIDC reference profile and configured-principal claim
  with no claim fallback.
- Implement subject-authority profiles and one fail-closed authorization
  decision over requester, optional actor, requirement revision, purpose,
  role-bound selector profile and value origin, subject authority, and
  audience and requested response format.
- Durably record every authorization refusal after successful authentication as
  a standalone minimal denial event before returning the generic `403`; return
  the generic `503` if that audit append fails.
- Write the pseudonymized access-attempt audit durably before source access and
  the disclosure-release audit durably after final response serialization and
  before release.
- Bind local assurance to a local P-256 private JWK and production or
  evidence-grade assurance to a pinned-version Vault/OpenBao Transit signer
  through a workload-local Unix socket with no provider token in Evidence.
- Create the exact ES256 flattened JWS JSON response, derive the RFC 7638
  `kid`, publish active and planned-rotation keys, apply revoked identifiers
  before key selection, and define planned and emergency rotation windows.
- Bind enabled response formats into the immutable bundle and allowed formats
  into every authority grant; signed JWS remains mandatory and default.
- Run every acceptance definition through these boundaries.

Exit gate: every denial occurs before source access; an authenticated
authorization refusal is durably accountable before its `403`; audit or signing
failure prevents the applicable refusal, source access, or release; principal,
subject, purpose, audience, values, and keys obey the privacy and trust
invariants.

### Phase 4: native HTTP service and operations

- Implement authenticated `GET /v1/evidence-definitions`,
  `POST /v1/evidence`, `/health`, `/ready`, and the public JWKS endpoint with
  exact media types, strict `Accept` handling, `Vary: Accept`, and a closed
  `406` response-format problem.
- Implement the self-identifying unsigned envelope through the same authorized,
  minimized, audited path without a second evaluator or signing fallback.
- Add request and response limits, safe problem responses, per-principal rate
  controls, dependency timeouts, and shutdown behavior.
- Generate JSON Schema and OpenAPI from code and add drift checks, and publish
  the generated OpenAPI document unauthenticated at `GET /openapi.json`.
- Generate and seal one deterministic `catalog.jsonld` Registry Discovery
  provider description from the governed public allowlist, including only exact
  Evidence Type and compatible binding-and-response capability records with
  distinct derived binding identities, validate its exact
  regeneration before activation, and serve the packaged bytes unauthenticated at
  `GET /catalog.jsonld`, without source, authorization, signing, or audit work.
- Test all four acceptance definitions through the real router and HTTP client
  while multiple definitions are enabled in one process.

Exit gate: each acceptance case produces a verifiable signed assertion and an
explicitly authorized unsigned envelope through the same public operation, and
operational endpoints expose no protected data.

### Phase 5: privacy, isolation, and schema freeze

- Prove source minimization, existence-disclosure behavior, combined-definition
  inference controls, selector confidentiality, safe no-match and ambiguity
  collapse, script isolation, cross-definition state isolation, and safe
  concurrency and failure behavior.
- Prove payload or protected-header mutation fails verification; nonce,
  expected-subject, or expected-output-contract mismatch fails; and unsigned
  output is explicit, governed, self-identifying, and never a fallback from
  signed failure.
- Attempt the ignored, read-only DHIS2 and OpenCRVS public-demo smoke tests only
  after deterministic HTTP mocks and local extract tests pass, following
  `SOURCE-TESTING.md`.
- Freeze Version 1 schemas only after all four initial assertion cases and all
  negative security tests pass unchanged through the complete pipeline.

Exit gate: the complete Definition of Done is green except packaging and final
workspace gates, and any live-demo result is recorded only as pass, skipped, or
inconclusive without protected data.

### Phase 6: release readiness and stop

- Provide operator configuration, secret, bundle-mount, audit-storage,
  signing-key, key-rotation, backup, and verifier guidance for the supported
  deployment mode.
- Prove a clean build, package tests, generated-contract reproducibility,
  dependency policy, and the applicable workspace gates.
- Self-review the complete diff against the security acceptance matrix and the
  future-profile stop boundary.

Exit gate: the frozen runtime contract and its release evidence are complete.
The remaining adopter build phase may not change request, assertion,
authorization, source, signing, audit, or verification semantics.

### Phase 7: production build and optional Mint handoff

- Extend local authoring with an empty `fixtures/` directory and optional,
  exact question governance metadata without weakening local development.
- Compile one explicit production target into a create-only candidate. Reject
  symlinks, outside-project references, missing fixtures, incomplete
  governance or authority, invented URIs, unresolved review markers,
  unauthenticated or plain-HTTP sources, unknown fields, and existing outputs.
- Delegate candidate validation to the real `evidence` binary with private
  temporary validation material. Run `evidence check` and every referenced
  fixture before atomic publication; retain no secret, request, audit, source,
  or local-development residue.
- Add the target-host ceremony for independently provisioned secrets, real
  startup, retained signed-response verification under independent production
  policy, and audit-chain verification.
- Add the optional read-only Mint compatibility check. It compares only
  mechanical protocol bindings and pin tests for every mismatch without
  printing protected values.
- Document, but do not generate, the Compose adapter and the released-bare-
  binary tutorial journey. State Mint's single-process, memory-only replay
  cache limit.

Exit gate: every Definition of Done row is satisfied with focused tests,
contract and source-neutrality checks, documentation checks, and grouped
workspace verification on one revision. Future profiles require new concept
approval and are not continuation tasks for this schedule.

## Definition of Done

Evidence Version 1 is done only when every row below is satisfied on the same
revision. A passing adult-status demonstration, a working endpoint, or a green
subset of tests is not completion. No requested Version 1 behavior may remain
as a stub, TODO, partially implemented path, undocumented manual step, or
follow-up issue.

| Area | Done when |
|---|---|
| Scope and architecture | One `registry-evidence` crate and one `evidence` binary implement the complete Version 1 path without any `registry-notary*`, PDP, credential-issuance, replay, worker, or interoperability subsystem dependency. |
| Public contracts | The CCCEV-aligned Evidence JSON profile, Registry Discovery provider-publication profile, singular and multi-subject request schemas, request nonce, selector schemas, flattened JWS, unsigned, and request-batch responses, exact content negotiation, governed-bundle and runtime YAML schemas, closed `prepare/2`, `extract/2`, `prepare_batch/2`, `extract_batch/2`, and selector-aware `derive/3` Rhai ABIs, projection and fixture contracts, audit events, problem codes, JSON Schema, and OpenAPI are reviewed, versioned, generated where applicable, and protected by CI drift tests. Subject-array order is not semantic; Rust resolves unique roles and emits declaration order internally. |
| Initial assertion cases | Adult status, residence region, professional licence status, and legal-parent relationship each pass offline and through the real HTTP service, including authentication, authorization, response-format permission, source access, both audit gates, output validation, signed JWS, explicitly authorized unsigned output, and strict verification. The multi-subject request-batch path exercises the same domain-neutral resolution and signing path without adding a preferred definition or domain branch. |
| Generic domain model | The four cases use one model and operation. Production Rust has no adult, age, residence, licence, parentage, personal-name-part, national-identifier, or other acceptance-case or jurisdiction-specific type, field, operation, route, feature, or conditional. Deployment-defined selector field names are opaque stable names. |
| Source-product neutrality | Production code, Cargo metadata, and generated public contracts have no DHIS2 or OpenCRVS module, type, dependency, feature, configuration variant, route, CLI option, or conditional. Product names and shapes appear only in tests, sanitized fixtures, test-only bundles, and design or local-smoke documentation. |
| Bundle and Rhai | Startup rejects incomplete, inconsistent, mutable, or uncompilable governed bundles and runtime files and serves only their one immutable revision. Runtime bindings cannot override governed fields. Every role and authority path has a complete selector-profile and source binding. Rhai preparation, extraction, and derivation are deterministic, bounded, and fresh per invocation. Preparation receives only source-required authorized selectors and the exact adapter context `{parameters, prior_facts}`; extraction sees only the bounded projected response and that same context; `prior_facts` is empty except for the schema-validated search FactSet supplied to a fixed fetch, whole or projected onto the allowlist that stage declares. Batch preparation receives only ordered opaque slots with minimized selectors plus `{parameters}`; batch extraction receives only the bounded projected response plus `{parameters, slots}` and returns an exact slot bijection over ordinary lookup results. Derivation sees only the final matched facts, its declared authorized selector inputs, and the closed evaluation context. No script receives network, filesystem, environment, ambient clock, randomness, credentials, authorization objects, logs, audit, signing material, or source-selection authority. Extraction returns only `match(FactSet)`, `no_match`, or `ambiguous`; derivation runs only on a final `match`. |
| Values and validation | Every Version 1 Supported Value form declared in `CONCEPT.md` passes positive, negative, boundary, size, cardinality, Evidence construction, JWS serialization, and verification tests. The four initial assertion cases exercise boolean, controlled-code, time-bucket, multiple-concept, and multi-subject behavior through the full service. |
| Selector and matching boundary | Identifier-only, compound no-identifier, additional-disambiguator, and multi-role selector profiles pass the complete service. Each profile has one exact field set. Missing, extra, unknown, mistyped, oversized, unauthorized, or wrong-origin values fail before credential acquisition and source access. Provider results are limited to `match`, `no_match`, and `ambiguous`; Evidence never performs broad candidate retrieval, scoring, or selection. Reviewed deterministic derivation may compare authorized selectors with facts from one unique authoritative record. Explicit false relationship evidence requires a complete valid relationship set. A source that lacks count metadata may return at most two minimally projected results solely to distinguish ambiguity. |
| Source minimization | Rust executes only the requirement's closed `single` or `search-then-fetch` acquisition, or a kind added after that surface froze where the bundle declares it and the operator separately enabled it. Each stage has fixed transport authority, a fixed or closed selector/prior-fact-bound path, fixed non-secret headers, bounded reviewed query/body rendering, explicit response projection, one durable pre-access audit, and no retry. Search facts are schema-validated before every fixed fetch and never persist; a fetch reads only the prior facts its acquisition gives that stage; no response can choose transport or add a call the configuration did not fix. Request batches run sequentially in order unless both capability gates and one fixed-path HTTP source batch block authorize exactly one optimized call within its ceiling. Strategy is fixed before I/O, and optimized failure never fans out. The effective posture is the weakest among the acquisition's sources. Basic, static Authorization header, static API-key, and OAuth client-credentials authentication and all three postures pass generic contract tests through the same HTTP executor. Credential-free execution is a separate local-only exception pinned to an exact numeric-loopback HTTP origin. |
| Statement source minimization | A `sqlite-extract` source executes exactly one bundle-fixed reviewed statement, held to one statement per artifact and covered by the bundle hash, against the one extract file the runtime bound, and Rust binds every value into it by index so no value is ever rendered into statement text. SQLite's authorizer decides every action the compiled statement would take while it is prepared, permitting reads and refusing every write, schema, and control action, `ATTACH`, `DETACH`, `PRAGMA`, extension loading, non-deterministic functions, and the whole clock family; a denied action fails the bundle at load rather than at request time. The reserved `evidence_now` parameter carries the same evaluation instant the assertion reports, and a bundle declaring that name is refused. Every declared parameter has exactly one origin, so a preparation script cannot fill a selector parameter, return a name the source never declared, reach the reserved name, or leave a declared prepared parameter unfilled, and a preparation script and a prepared parameter are refused unless declared together. Startup proves the statement's real result columns and parameters against the bundle over the extract it will read, refuses an extract profile the runtime did not bind and a binding no source names, and refuses a symbolic link, a non-regular file, a file this process could write, and a path replaced before it was opened; the bound file's digest enters the computed runtime revision. The reserved `evidence_extract` table must carry exactly one publication row, and the declared `maximumExtractAgeSeconds` is compared against the evaluation instant before a single row is read. Row, cell, and response-byte bounds are enforced as the result is read, the statement-step and time bounds by the progress handler inside the engine, and a cancelled request returns its connection and its permit. The transport holds no credential of any kind, and no diagnostic, log, snapshot, or audit record carries statement text, a bound or result value, the extract path, or engine message text. |
| Authentication and authority | Strict OIDC verification and the configured principal claim fail closed. One authorization decision binds requester, optional actor, requirement revision, purpose, every role's selector profile and value origin, subject authority path, audience, and requested response format. Possessing selector values or discovery metadata, or choosing an API media type, creates no authority. Authenticated discovery lists only complete shapes matching exactly one authority path and valid token-owned selector material; unentitled, ambiguous, and invalid-context shapes are absent. Every denial occurs before credential acquisition or source access. |
| Privacy and audit | After successful authentication, every authorization refusal is durably accepted as a standalone minimal denial event before the generic `403`; sink failure returns the generic `503`. The event contains only the operation and event identifiers, assurance profile, bundle revision, scoped requester pseudonym, optional actor pseudonym, closed denial category and decision, timestamp, and duration. The pseudonym scope binds operator trust domain, requested purpose, and authenticated audience while omitting those inputs. The event omits untrusted requested requirement, purpose, subjects, unmatched authority, selector information, response protection, source, and evaluation material. Authentication, malformed-request, and invalid-selector failures remain operational-only. One access-attempt audit is durably accepted before every actual source stage. Rust serializes final immutable response bytes, durably accepts disclosure-release audit, then releases those exact bytes. Request batches use their distinct audit schema, one access event per physical call with bounded item groups by authority and subject set, and one terminal release with every ordered outcome or one value-free terminal failure. An all-unavailable release carries no signing key id. Sink failure blocks the applicable step. Audit records stage source identity but never prior facts or intermediate identifiers, records the closed response-protection mode and a signing key only for a release that signed at least one assertion, and uses at most one scoped keyed pseudonym over each complete canonical role and selector bundle. Neither audit, logs, errors, metrics, nor traces contain credentials, tokens, request nonces, raw selector values, per-field quasi-identifier hashes, source values, Supported Values, signed material, or raw subject identifiers. |
| Evidence and response integrity | Rust alone constructs Evidence, signed flattened JWS, the unsigned envelope, and the request-batch envelope. Signed JWS is mandatory and default, uses ES256/P-256, RFC 7638 service key identifiers, allowlisted protected headers and trusted key resolution, has verifiable nonce, independently expected subjects and output contract, audience, policy, and validity, and publishes usable active and planned-rotation public keys while revoked identifiers override cached selection. Request-batch available items are signed JWS only, stay in request order, and the exact complete envelope is bounded to 1 MiB, pre-audited, and returned unchanged. Deployable assurance uses a pinned non-exportable Transit signer whose public key matches the governed active JWK and passes startup sign-and-verify. Unsigned JSON is self-identifying, requires bundle and complete matched grant permission plus exact singular API selection, and makes no later-verification claim. Signed failure never falls back to unsigned or partial batch release. |
| Failure and operations | Stable safe errors, reviewed existence-disclosure semantics, public collapse of `no_match` and `ambiguous` by default, request limits, per-principal and failed-selector-attempt rate controls, authenticated requester-scoped discovery, unauthenticated closed provider publication, health, readiness, dependency timeouts, and graceful shutdown work without exposing protected data. Discovery performs no source access and exposes no source plan, scripts, credentials, internal authority metadata, selector values, codelist values, protected operations, or unrelated definitions. Readiness fails for missing bundle, selector binding, credential, audit, or signing dependencies required by the configured deployment. |
| Multiple definitions | All four definitions run concurrently in one process and one trust domain without script state, limits, identifiers, subjects, source responses, audit context, or results crossing definition boundaries. Unsafe combined disclosure and mutually distrustful issuer configurations are rejected. |
| Verification evidence | Focused invariant tests, all package tests, contract drift checks, dependency policy, formatting, package and workspace check, Clippy with warnings denied, and workspace tests pass. Security-sensitive behavior has a named threat, enforcement point, and negative test. |
| Local compatibility smoke | After deterministic mocks pass, the read-only DHIS2 and OpenCRVS smoke tests are attempted when local credentials and approved demo selectors are available. Unavailability may be recorded as inconclusive; authenticated schema drift or excess disclosure is investigated and cannot be ignored. No credential or live-data artifact enters the repository or test output. |
| Operability | An adopter can author, test, deploy, and maintain a source integration from the configuration, adapter API, fixture contract, complete DHIS2/OpenCRVS-shaped projects, and the complete SQLite extract project without editing Rust. The documented extract handoff covers publication metadata, canonical time representation where lexical comparison is used, checkpointing, least-data conversion, immutable mounting, new-path replacement, restart, and fixture/startup verification. An operator can independently bind the immutable governed bundle to listener, secret, audit, private-CA, extract, and Transit proxy paths for each environment without overriding evidence semantics, configure authentication, authority mappings, source bindings, planned and emergency signing rotation, audit epochs, rate limits, and verifier trust using documented supported paths, and let an authenticated consumer discover the exact revision-bound request shapes it may invoke. Static onboarding still owns token acquisition, human and legal descriptions, endpoint trust, and verifier policy. |
| Production build | An editable project remains local until its author supplies exact governance metadata, stable concept identifiers, and one synthetic fixture per question. `evidencectl build` consumes one explicit closed production target, follows no symlink or outside-project reference, creates no secret or runtime residue, delegates bundle validation and every fixture to the real `evidence` binary, atomically publishes only a complete candidate, and reproduces identical bundle bytes and revision from identical inputs. It creates no keys, callers, approvals, deployments, or network side effects. |
| Target-host handoff | A reviewed candidate with independently provisioned owner-only production secrets passes `evidencectl doctor`, `evidencectl fixtures run`, and real startup. One authorized synthetic-subject HTTP request yields a signed assertion that `evidence verify` accepts only under independent `production` policy and trusted keys; the resulting access and disclosure audit events pass `evidence verify-audit`. |
| Optional Mint pairing | External HTTPS OIDC builds without Mint. When Mint is selected, `mint check`, the paired read-only doctor check, registered-client token acquisition, and Evidence acceptance pass. Issuer, JWKS URI, audience, algorithm, token type, and all configured claim-name mismatches fail generically without keys, tokens, credentials, selectors, or source values in output. Mint remains a single process with a memory-only replay cache. |
| Compose and bare-binary journey | The maintained Compose guidance mounts the candidate bundle unchanged and read-only, uses a distinct container runtime revision, separate read-only secrets, persistent audit storage, a private listener, and operator TLS. It documents service UID and secret modes, public-HTTPS Mint routing, and image provenance without generating Compose output. The production and optional-Mint tutorials execute from released bare binaries and include a real Curl boundary. |
| Stop boundary | No capability from `CONCEPT.md` section 4 or section 15 is implemented or stubbed beyond the explicitly closed acquisition kinds, each of which fixes every call it may make in configuration before any call is made. This includes document evidence, credential lifecycle, OID4VCI, status lists, presentation verification, nonce or replay storage beyond stateless request-nonce echo and comparison, OOTS XML or AS4, agents or MCP, federation, workflow, a public requester-entitlement or definition catalog, searchable, mutable, aggregate, or federated catalogs, runtime bundle mutation, script-selected transport, response-led or general multi-call planning, an evidence-data call no declared acquisition fixed, response-led multi-source fulfillment, a policy engine, application database, message broker, or worker process. The package-derived public provider advertisement remains inside the boundary as a closed publication for external indexing, not a catalog runtime. |

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
    bundle revision but not any assertion-semantic requirement revision.
29. Every declared Supported Value form rejects wrong scalar types, unknown
    codes, invalid entity references, excessive precision, oversized strings,
    oversized lists, duplicate values where prohibited, and wrong
    cardinalities, and each valid form survives Evidence construction, JWS
    serialization, and verification without type loss.
30. `source-derived`, `field-projected`, and `record-transformed` definitions
    use the same executor and report their acquisition guarantees honestly.
31. A serving process cannot reload, mutate, merge, or fall back to another
    bundle revision at runtime.
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
45. Governed bundle and runtime configuration have separate closed schemas,
    independent startup digests, read-only lifetime enforcement, and negative
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
    disclosure-release audit before releasing them. Audit records the closed
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
    `registry.evidence.audit.authorization-refusal/v1` discriminator before
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
    its own safe category, without ever cancelling a durable audit append.
67. A `sqlite-extract` source executes one bundle-fixed reviewed statement
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
    write, and its digest enters the computed runtime revision. An extract
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
    singular collapse contract exposes as `evidence_not_available` becomes
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
The final DoD gate includes:

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

## Explicitly deferred

The Version 1 schedule and DoD stop before every item below. Do not add
implementations, stubs, placeholder schemas, empty modules, feature flags, or
extension APIs for them:

- Rego or a Rhai authorization-policy interface;
- caller-defined predicates or thresholds;
- broad candidate retrieval, fuzzy or probabilistic scoring, best-match
  selection, matching weights or thresholds, phonetic candidate comparison,
  deduplication, and an Evidence-wide identity policy;
- script-selected sources, URLs, methods, paths, path-binding origins, headers,
  credentials, retries, page traversal, response-led routing, or general
  multi-call source planning;
- any acquisition beyond the closed kinds this release defines, including a
  lookup no declared acquisition fixed, or response-led multi-source
  fulfillment where a response chooses how many sources are called or which
  one comes next;
- evidence or raw-source persistence;
- document retrieval or multipart responses;
- OID4VCI, credential lifecycle, status lists, revocation, presentation or
  key-binding verification, wallet onboarding, or holder-scoped subject
  identifiers. The SD-JWT VC response format is a serialization of the same
  stateless assertion under `contracts/sd-jwt-vc-profile.yaml`, and the optional
  holder key is embedded without ever being validated as possession;
- nonce or replay storage beyond stateless request-nonce echo and comparison;
- OOTS XML, AS4, Evidence Broker, or DSD runtime code;
- federation, agents, MCP, workflow, or public, cross-requester, searchable,
  mutable, or federated catalog endpoints;
- runtime bundle upload, mutation, hot reload, or approval workflows;
- an application database, message broker, or worker process.
