# Evidence Source Testing

Status: Approved Version 1 source-testing contract
Date: 2026-08-09

## Purpose

Evidence must prove that its source boundary is generic without building a
connector framework or emulating entire source products. Testing therefore has
four ordered layers:

1. offline requirement fixtures for extraction and derivation semantics;
2. deterministic local HTTP mocks for materially different source contracts;
3. deterministic local SQLite extracts that execute each reviewed statement;
4. explicit, read-only local smoke tests against public demo systems.

Only the first three layers run in ordinary CI. A live smoke test supplements
the deterministic contracts. It never replaces them and never decides whether
a commit is correct.

## Compatibility matrix

| Profile | Request | Response | Authentication | Generality pressure |
|---|---|---|---|---|
| `flat-rest` | Reviewed JSON preparation with identifier or compound selectors | Flat JSON object | Static Authorization header | Closed selector inputs and direct fact extraction |
| `dhis2-tracker` | `GET` with prepared filters, fixed `fields`, and `pageSize` | Pager, `trackedEntities` collection, nested attributes | HTTP Basic | Query rendering, encoding, cardinality, collection handling, and controlled codes |
| `opencrvs-event-search` | Prepared bounded JSON `POST` for one tracking ID | Nested event index and country-configured declaration | OAuth 2.0 client credentials, then Bearer | Credential bootstrap, exact event lookup, nested extraction, and relational derivation |
| `search-chain` | One fixed JSON `POST` search, then two declared members in declared order: one path-bound dereference, one filtered search in a JSON body | Flat dotted response keys, a provider count, and a bounded result page per stage | Static Authorization header per stage, and per-source OAuth 2.0 client credentials for the dereference member | Ordered multi-stage acquisition, per-member allowlisted projection, a provider count consumed as a value, and silently widened queries |
| `sqlite-extract` | One reviewed SQL statement with declared named parameter bindings, bound by index | One result tree of the declared columns in result order, beside the extract's own publication row | None; the transport holds no credential | Bundle-fixed statement authority, the prepare-time authorizer verdict, the reserved evaluation instant, publication metadata and staleness, and row, cell, statement-step, and time bounds |

A single-stage row and a multi-stage row are different claims about the same
product. The first says one bounded request shape still works. The second says
an ordered chain still works, that each later stage receives only its own
allowlisted projection of the validated search FactSet, and that a stage which
does not resolve stops the acquisition. Passing either never implies the other,
and neither may be reported as the other.

Four of these rows are HTTP wire shapes. `sqlite-extract` is the second
transport rather than a wire shape, so it is the transport's own configuration
name rather than a test-only one. Its cases execute one reviewed statement
against a real extract file instead of replaying a mocked response, so it makes
no claim about any HTTP row and no HTTP row makes a claim about it.

The product names identify compatibility-shaped test profiles. They do not
promise a maintained vendor connector, reproduce a whole server, or certify
support for every release and configuration.

The optional source-batch optimization is a second execution strategy over an
existing `http-json` row, not another compatibility profile. Its deterministic
contract suite must prove:

- bundle and runtime `source-batch` gates plus a complete fixed-path source
  block are all required before the optimized strategy is selected, and an
  incomplete two-author gate fails startup;
- omission, path templates, SQLite, multi-stage acquisition, and an item count
  above `maximumItems` select ordinary sequential execution before I/O;
- the one optimized request reuses the ordinary method, origin,
  authentication, headers, TLS, redirect, timeout, response, semaphore, and
  preparation limits;
- `prepare_batch` sees only ordered opaque slots, minimized selector objects,
  and closed parameters;
- batch projection and response-schema validation occur before
  `extract_batch`, and each returned match satisfies the ordinary fact schema;
- extraction returns an exact slot bijection, with reordering restored and
  every missing, duplicate, extra, negative, non-integer, or out-of-range slot
  rejected for the complete operation; and
- no optimized failure retries through sequential fanout or releases a partial
  response.

At least one local HTTP mock must compare sequential and optimized evaluation
of the same synthetic item set, including mixed and all-unavailable results,
and assert equal ordered logical outcomes. No live demo is used to prove this
strategy because a public endpoint's acceptance of a bulk request is not a
stable dependency contract.

They are test-only names. Production Rust, Cargo dependencies and features,
public configuration schemas, routes, and CLI options contain no DHIS2 or
OpenCRVS specialization. The compatibility test must fail if either product is
introduced into production source, Cargo metadata, or generated public
contracts.

The DHIS2 profile follows the reviewed version 2.43 Tracker contract. A live
operator selects an approved current instance from the official DHIS2 demo
catalog rather than relying on a repository-pinned public hostname. The check
requests only configured fields and sets a result limit that can distinguish
one match from ambiguity. It does not follow pages to enumerate people.

The OpenCRVS profile follows the documented Event Search flow: acquire a
short-lived system-client token, then submit one bounded JSON search for an
exact child tracking ID. Malformed envelopes, zero results, multiple
results, and incomplete configured declaration facts all fail according to the
reviewed requirement rule.

The `search-chain` profile is named for its shape, not for a product. It models
one fixed search followed by two declared fetch members against a single mock.
Its response keys are literally dotted strings, so a projection segment is the
whole dotted string and both the projection and the extract treat the dot as
data rather than as a path separator. One member takes its whole input through a
path binding, the other through the JSON body its own preparation builds, and
one response carries a provider count consumed as a value rather than as a
cardinality guard.

The `sqlite-extract` profile is also named for its shape. Its fixture builds a
small invented database in a temporary directory, adds the reserved publication
row, makes the completed file read-only, and runs the bundle's reviewed
statement. The result is never prerecorded. Replaying rows would test the
extraction script while leaving the SQL, its parameter bindings, and its time
boundaries unproved.

Fixture seed SQL is trusted executable project input and is not sandboxed as
untrusted code. Run only reviewed project seeds in an isolated local
environment. Never import or evaluate a foreign bundle as a fixture.

Transport mixing is part of the compatibility matrix, not an implementation
detail. The current evaluator executes a SQLite statement only when it is the
initial source and refuses later SQLite stages; it therefore cannot prove every
order the serving runtime accepts. Such a project cannot complete the supported
production/evidence-grade build journey and must not be presented as deployable
assurance through a manual bypass. Version 1 completion requires deterministic
HTTP to HTTP, HTTP to SQLite, SQLite to HTTP, and SQLite to SQLite coverage, a
mixed-transport gated member set, real statement execution at every SQLite
stage, and a build/serving gate for any acquisition the harness cannot execute.

A multi-stage shape has more than one way to be right, so the profile states
which cell of this table it occupies. Naming an uncovered cell is worth more
than a matrix that reads as complete.

| Property | Instances |
|---|---|
| Member request kind | path-bound dereference (covered) / filtered search in a JSON body (covered) |
| Search fact kind | reference (covered), count (not covered), completeness attestation (not covered) |
| Member fact kind | reference (not covered), count (covered), attested boolean (covered) |
| Negative capability | attested set completeness (covered), or none, in which case zero stays `no_match` (covered at the search stage only, never as a whole chain) |
| Credential | static Authorization header (covered) / per-source OAuth client credentials (covered) |

The uncovered cells are deliberate. No profile yet carries a search whose own
fact is a count or a completeness attestation, a member whose fact is a
reference a further stage would dereference, or a chain in which no stage
attests set completeness at all. A dereference-shaped chain over the
`dhis2-tracker` profile is a deliberate follow-up rather than part of this row.

Which fields a deployment made filterable is a provider-side precondition
Evidence cannot validate offline, so a mis-declared member field does not
present as a configuration error. It presents as `ambiguous` when the provider
silently ignores the unknown clause, widens the request, and answers with a
count far above one; as `no_match` when the widened or narrowed request answers
with zero; and as an ordinary source outage when the field is known but
unindexed and the deployment answers `5xx`. The `total > 1` to `ambiguous`
extract rule is the guard that keeps the first case honest: an extract that took
the first result of a widened page would turn a mis-declared field into a
confident wrong answer instead of a refusal.

The chain adds no absence-as-fact rule. Zero results stay `no_match` and can
never be read as a conclusive negative. The one sanctioned reading of zero as a
counted zero is a later stage consuming a provider count after an earlier stage
established the subject in that same register with a real `match`.

The matrix includes four generic selector contracts independent of those
product-shaped profiles:

- one opaque identifier;
- one compound selector with no identifier;
- one compound profile with an additional configured disambiguator;
- one relationship request with two independently role-bound selectors.

Selector field names, exact field sets, scalar types, value origins, and
permitted script inputs come from trusted test YAML. Reviewed preparation
scripts render the wire request. The core does not know what a
name, civil identifier, licence number, or birth date means. Alternative
sufficient field sets use separate named profiles instead of caller-selected
field combinations.

## What the deterministic tests contain

The HTTP profiles use small local mocks and invented, obviously synthetic raw
provider responses. The SQLite profile builds an invented extract from
reviewable seed SQL and executes the reviewed statement. Rust applies the same
configured extended JSON Pointer projection used in production before
extraction. A `field-projected` fixture
models a wire response containing only requested fields. A
`record-transformed` fixture may contain additional fields before local
projection.
Every `record-transformed` fixture also includes at least one unrelated
synthetic canary to prove excess transient data cannot cross extraction,
derivation, error, audit, log, metric, trace, snapshot, or evidence boundaries.
Do not capture a public demo response and redact it after the fact.

The shared cases are:

- one exact match;
- no match;
- two matches or a total count greater than one;
- identifier-only and no-identifier compound selectors;
- missing, extra, unknown, mistyped, empty, oversized, and unauthorized
  selector values rejected before credentials or source access;
- an additional disambiguating field accepted only as a distinct configured
  profile, never as a caller-added field;
- two role-bound selectors with swapped-role and substitution failures;
- required fact absent;
- wrong fact type or controlled code;
- malformed JSON and wrong media type;
- for a source declaring `unresolvedProblem`, the one exact 404
  `application/problem+json` six-member tuple as data-free unresolved, plus
  undeclared, wrong-status, wrong-media, duplicate-member, missing, extra,
  mistyped, tuple-mismatch, and oversized negative cases as dependency
  failures;
- one complete-project `declaredUnresolved: true` case bound to that source,
  expecting only the data-free unavailable result. It carries no lookup label
  because the provider has already hidden whether the upstream state was no
  match or ambiguity; the one neutral case satisfies both fixture coverage
  categories while the `unresolvedProblem` tuple and negative cases prove
  exact wire matching;
- `401`, `403`, `429`, and `5xx`;
- timeout, redirect, and response larger than the configured maximum;
- credentials rejected without any credential value in diagnostics;
- raw selector values and source values absent from logs, audit, errors, and
  snapshots; audit may contain only the configured profile id and one scoped
  keyed pseudonym over the complete role and selector bundle.
- broad candidates, scores, near-match hints, and comparison diagnostics absent
  from evidence, errors, responses, logs, and audit;
- exact relationship membership succeeds and fails using an independently
  authorized candidate selector, while incomplete parent sets, mismatched
  namespaces, role substitution, and ambiguous child lookup stop without an
  authoritative negative assertion.

Profile-specific cases include:

- DHIS2 pager and `trackedEntities` shape, nested attribute lookup by configured
  identifier, fixed `fields`, and refusal to enumerate a second page;
- OpenCRVS token expiry, malformed token response, exact child-event body,
  bounded event result, configured declaration fields, and missing or malformed
  parent references.
- `search-chain` stage ordering, one request per declared stage plus one
  credential bootstrap each, a dotted key whose value is an object, a silently
  widened query reaching `ambiguous` without reading the first result, a filter
  on an unindexed field presenting as a source outage that stops the chain
  before any member request, a counted zero staying a `match`, and proof that a
  search fact a member did not declare reaches neither its path, its query, nor
  the body its preparation built.
- fixed and tagged selector/prior-fact-bound path expansion, fixed headers, Basic,
  static Authorization header, static API-key, OAuth client credentials in both
  its client-secret and private-key JWT forms, system-root and private-CA TLS,
  projection conflicts, and proof that ambient proxy variables are ignored.
- the explicit local credential-free boundary, including exact numeric-
  loopback origin validation and absence of an authentication header.
The `sqlite-extract` profile has no mock, because it has no wire to mock. Its
cases commit a text seed of SQL and materialize it into a temporary extract
file inside the process that reads it, so the reviewed statement executes for
real against a real SQLite file and nothing is replayed. A seed is reviewable
in a diff and no table name arrives inside an opaque binary. The materialized
file is made unwritable before it is opened, because the runtime refuses a
writable extract rather than warning about one.

Statement cases include:

- one exact match, no match, two rows reaching `ambiguous`, and one row past
  the declared row bound failing as a dependency rather than as ambiguity;
- write, `ATTACH`, `DETACH`, `PRAGMA`, extension-loading, non-deterministic,
  and clock actions refused by the prepare-time authorizer;
- a second statement in the artifact, declared columns disagreeing with the
  real result columns, and statement parameters disagreeing with the declared
  bindings;
- the reserved evaluation instant reaching the statement, a pinned instant
  reproducing the same result, and a bundle declaring the reserved name refused;
- a selector parameter a preparation script tried to fill, a parameter name the
  source never declared, and a declared prepared parameter left unfilled;
- the row, cell, statement-step, time, and response-byte bounds, and a
  cancelled request giving back its connection and its permit;
- an extract with no metadata table, with other than exactly one row, missing a
  column, or carrying a malformed field;
- an extract published exactly at the declared bound, one past it, and one
  dated after the evaluation instant;
- a bound path that is a symbolic link, a non-regular file, a writable file, or
  a file replaced between its digest and its opening;
- statement text, bound values, result values, the extract path, and engine
  message text absent from every rendering, diagnostic, and audit record, with
  a genuine syntax fault carrying a line and column and no text.

Extract columns no statement selects carry the same kind of unrelated synthetic
canary a `record-transformed` fixture carries, and the reference project's
privacy expectation forbids that value in any assertion or diagnostic. The
statement is what keeps it true: a column that was never selected cannot reach
a fact, a derivation, or a later defect.

The HTTP mocks assert every received wire request, and the SQLite tests assert
the statement artifact, exact bound parameter map, and resulting declared
columns. Preparation Rhai sees only the source-required authorized selectors
and the exact context containing closed parameters and `prior_facts`.
Extraction Rhai sees only the bounded projected JSON response and that same
context. `prior_facts` is empty for a single or
search call and is exactly the validated search FactSet for a fetch. Under a
declared member set it is instead the projection of that validated search
FactSet onto the member's own allowlist, so no member sees a search fact it did
not declare or any fact produced by another member. Neither script can inspect
credentials, request headers, URLs, or the source client.

Extraction maps the response to exactly `match(FactSet)`, `no_match`, or
`ambiguous`. It may interpret a provider result count or at most two minimally
projected results when the provider cannot return count plus one result. It
must not receive a broad candidate set or select between results. Derivation
runs only on `match` and may compare the facts with only its declared
authorized selector inputs using the reviewed requirement rule. Search
`ambiguous` stops without derivation, fetch, page traversal, or a success
response in any format. A single acquisition makes one request; a
search-then-fetch acquisition makes at most its two fixed audited requests; a
declared member set makes at most one plus its declared member count, and an
execution is always a prefix of the declared sequence because a stage that does
not resolve stops the acquisition.

The same suite runs every initial assertion case from `CONCEPT.md` through the
complete Evidence service. At least one case runs against both transports with
only bundle, runtime binding, fixture, and Rhai changes, proving that a source
swap does not require Rust changes.

Across those cases, adult status uses a no-identifier compound selector,
residence uses an identifier profile, professional licence uses a compound
sector selector, and legal-parent relationship uses a child record reference
plus an independently role-bound candidate reference. These assignments exist
only in test bundles and do not create production domain types.

## Local public-demo smoke tests

For the operator-facing first checkpoint, expected outputs, and the explicit
post-checkpoint gap list, see [`FIRST-CURL-TEST.md`](FIRST-CURL-TEST.md). For
the same deterministic path exercised through the SD-JWT VC response format and
its offline verifier, see [`SD-JWT-VC-DEMO.md`](SD-JWT-VC-DEMO.md). Both are
mock-backed and credential-free, so neither is a live test and neither depends
on the required order for live tests.

Live tests are implemented in a separate ignored integration-test target. The
required order is:

```text
cargo test --locked -p registry-evidence
cargo test --locked -p registry-evidence --test live_sources dhis2 -- --ignored
cargo test --locked -p registry-evidence --test live_sources opencrvs -- --ignored
cargo test --locked -p registry-evidence --test live_sources opencrvs_chain -- --ignored
```

The package test includes `source_contracts` and `statement_source`; it must be
green before any live command is run. The `opencrvs` filter is a substring and
therefore also selects `opencrvs_chain`; append `--exact` to run only the
single-stage check.

The statement transport adds no command to that sequence and has no live
counterpart. Its extract is a local file the tests build for themselves, so
`statement_source` and the reference project's fixture run are the whole proof,
and there is no public demo whose availability could make the result
inconclusive.

The live target requires an explicit profile name and local configuration. It
must skip, rather than improvise, when required values or an approved synthetic
subject selector are absent.

Live tests are read-only. They may authenticate, request a token, and perform a
bounded record lookup. They must not create, update, register, certify, print,
archive, or delete records. They must not use a browser session, a human login,
or interactive two-factor credentials. OpenCRVS may itself record the
system-client search in its remote audit log; that expected server-side audit
effect and any request quota are part of the operator's decision to run the
test.

### DHIS2 public demo

Select an approved current instance from the official demo catalog:
`https://dhis2.org/demo/`

The local profile accepts these names, with values supplied outside the
repository:

```text
DHIS2_BASE_URL
DHIS2_USERNAME
DHIS2_PASSWORD
DHIS2_TEST_PROGRAM_ID
DHIS2_TEST_ORG_UNIT_ID
DHIS2_TEST_TRACKED_ENTITY_ID
```

The owner-only file path is supplied through
`EVIDENCE_DHIS2_LIVE_ENV_FILE`. The smoke test first verifies authentication
through a safe metadata request, then performs one fixed Tracker read scoped by
the reviewed program, organisation unit, and synthetic/demo tracked-entity
selector with minimum `fields`. It never searches broadly to find a convenient
person. Public demonstration credentials are intentionally not reproduced in
repository material.

### OpenCRVS public demo

The owner-only file path is supplied through
`EVIDENCE_OPENCRVS_LIVE_ENV_FILE`. Its exact required keys are:

```text
OPENCRVS_CLIENT_ID
OPENCRVS_SECRET
OPENCRVS_URL
OPENCRVS_TEST_TRACKING_ID
```

The selector value and any alternative tracking or national identifier remain
local. They are never placed in a fixture, test name, snapshot, log, audit
record, error, or command line.

The live runner derives only the documented authentication and event-search
hosts from the configured base domain. It requests a client-credentials token
and then makes one bounded, exact event lookup that consumes only the count and
facts needed by the test. It does not retrieve a certificate or perform a
broad person search.

`opencrvs_chain` is the multi-stage companion. It reads the same owner-only file
and requires no additional key: every later stage takes its input from the
validated search FactSet rather than from configuration. It reuses the same
strict token bootstrap, then makes one bounded search followed by its declared
members in the declared order, each carrying only the record reference the
search produced. It asserts wire shape, stage ordering, and body-channel
minimization only: that each member request opens no query channel, that its
body is the exact bounded clause shape, and that a country-configured
declaration field the members did not declare appears nowhere in those bytes.
It never asserts that an assertion is produced. This demo data set has no union
register, so a member returning zero results is a passing outcome, and a
demo record that is not in the state a member filters for is likewise expected.

These live checks prove only that the selected demo version still accepts the
documented authentication and bounded lookup shape. The DHIS2 check does not
run the deployable adult-status derivation or prove its complete minimization
and response-protection path. The OpenCRVS check does not prove country-specific parent
reference fields, authoritative relationship-set completeness, parent
membership semantics, or the deployable family requirements. The chain check
proves only ordering and body-channel minimization on the wire; it proves no
assertion, no derivation, and no negative capability. Deterministic
mocks and executable project fixtures own those contracts. A passing live
check must not be described as certification of a complete deployment project.

### Direct curl diagnosis

Use these snippets only to diagnose an upstream API when the ignored live test
cannot establish why a deployment differs. They are not Evidence service
acceptance proof: they do not exercise authorization, audit, scripts, output
validation, signing, or disclosure release. Run them in a shell that does not
record terminal input. Values are prompted, sent to `curl` through standard
input with `--config -`, held only in shell memory, and unset at the end. The
commands print only shape, cardinality, and exact-match booleans.

For a bounded DHIS2 Tracker collection lookup:

```bash
(
  set -eu
  trap 'unset EVIDENCE_DIAG_EXPECTED DHIS2_BASE_URL DHIS2_USERNAME DHIS2_PASSWORD DHIS2_PROGRAM_ID DHIS2_ORG_UNIT_ID DHIS2_TRACKED_ENTITY_ID DHIS2_USER_CONFIG DHIS2_PROGRAM_CONFIG DHIS2_ORG_CONFIG DHIS2_ENTITY_CONFIG' EXIT HUP INT TERM
  curl_config_escape() { sed 's/\\/\\\\/g; s/"/\\"/g'; }
  curl_config_value_is_safe() {
    [[ $1 != *$'\n'* && $1 != *$'\r'* ]] &&
      ! printf %s "$1" | LC_ALL=C grep -q '[[:cntrl:]]'
  }
  read -rp 'DHIS2 HTTPS base URL: ' DHIS2_BASE_URL
  read -rp 'DHIS2 username: ' DHIS2_USERNAME
  read -rsp 'DHIS2 password: ' DHIS2_PASSWORD; printf '\n'
  read -rsp 'Program id: ' DHIS2_PROGRAM_ID; printf '\n'
  read -rsp 'Organisation unit id: ' DHIS2_ORG_UNIT_ID; printf '\n'
  read -rsp 'Tracked entity id: ' DHIS2_TRACKED_ENTITY_ID; printf '\n'
  test -n "$DHIS2_USERNAME" && test -n "$DHIS2_PASSWORD" || { printf 'Non-empty credentials required\n' >&2; exit 1; }
  if ! curl_config_value_is_safe "$DHIS2_USERNAME" || ! curl_config_value_is_safe "$DHIS2_PASSWORD"; then
    printf 'Credential contains a prohibited control byte\n' >&2
    exit 1
  fi
  printf %s "$DHIS2_BASE_URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$' || { printf 'Conservative HTTPS base URL required\n' >&2; exit 1; }
  for value in "$DHIS2_PROGRAM_ID" "$DHIS2_ORG_UNIT_ID" "$DHIS2_TRACKED_ENTITY_ID"; do
    printf %s "$value" | grep -Eq '^[A-Za-z0-9._:-]{1,256}$' || { printf 'Conservative identifier shape required\n' >&2; exit 1; }
  done
  DHIS2_USER_CONFIG=$(printf '%s:%s' "$DHIS2_USERNAME" "$DHIS2_PASSWORD" | curl_config_escape)
  DHIS2_PROGRAM_CONFIG=$(printf %s "$DHIS2_PROGRAM_ID" | curl_config_escape)
  DHIS2_ORG_CONFIG=$(printf %s "$DHIS2_ORG_UNIT_ID" | curl_config_escape)
  DHIS2_ENTITY_CONFIG=$(printf %s "$DHIS2_TRACKED_ENTITY_ID" | curl_config_escape)
  export EVIDENCE_DIAG_EXPECTED=$DHIS2_TRACKED_ENTITY_ID
  curl --config - <<EOF | jq '{collection_shape_ok: ((.trackedEntities | type) == "array"), cardinality_ok: ((.trackedEntities | type) == "array" and (.trackedEntities | length) <= 2), exact_match_ok: ((.trackedEntities | type) == "array" and (.trackedEntities | length) == 1 and .trackedEntities[0].trackedEntity == env.EVIDENCE_DIAG_EXPECTED)}'
silent
show-error
fail
no-location
max-redirs = 0
proto = "=https"
connect-timeout = 5
max-time = 15
get
user = "$DHIS2_USER_CONFIG"
header = "Accept: application/json"
data-urlencode = "program=$DHIS2_PROGRAM_CONFIG"
data-urlencode = "orgUnits=$DHIS2_ORG_CONFIG"
data-urlencode = "trackedEntities=$DHIS2_ENTITY_CONFIG"
data-urlencode = "fields=trackedEntity"
data-urlencode = "pageSize=2"
data-urlencode = "page=1"
data-urlencode = "totalPages=true"
url = "${DHIS2_BASE_URL%/}/api/tracker/trackedEntities"
EOF
)
```

For OpenCRVS client-credentials bootstrap and one bounded Event Search request:

```bash
(
  set -eu
  trap 'unset EVIDENCE_DIAG_EXPECTED OPENCRVS_DOMAIN OPENCRVS_CLIENT_ID OPENCRVS_CLIENT_SECRET OPENCRVS_TRACKING_ID OPENCRVS_CLIENT_ID_CONFIG OPENCRVS_CLIENT_SECRET_CONFIG OPENCRVS_TOKEN_RESULT OPENCRVS_ACCESS_TOKEN OPENCRVS_TOKEN_CONFIG OPENCRVS_BODY OPENCRVS_BODY_CONFIG' EXIT HUP INT TERM
  curl_config_escape() { sed 's/\\/\\\\/g; s/"/\\"/g'; }
  curl_config_value_is_safe() {
    [[ $1 != *$'\n'* && $1 != *$'\r'* ]] &&
      ! printf %s "$1" | LC_ALL=C grep -q '[[:cntrl:]]'
  }
  read -rp 'OpenCRVS deployment domain, without scheme: ' OPENCRVS_DOMAIN
  read -rp 'OpenCRVS client id: ' OPENCRVS_CLIENT_ID
  read -rsp 'OpenCRVS client secret: ' OPENCRVS_CLIENT_SECRET; printf '\n'
  read -rsp 'Child tracking id: ' OPENCRVS_TRACKING_ID; printf '\n'
  test -n "$OPENCRVS_CLIENT_ID" && test -n "$OPENCRVS_CLIENT_SECRET" || { printf 'Non-empty credentials required\n' >&2; exit 1; }
  if ! curl_config_value_is_safe "$OPENCRVS_CLIENT_ID" || ! curl_config_value_is_safe "$OPENCRVS_CLIENT_SECRET"; then
    printf 'Credential contains a prohibited control byte\n' >&2
    exit 1
  fi
  printf %s "$OPENCRVS_DOMAIN" | grep -Eq '^([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$' || { printf 'Conservative deployment domain required\n' >&2; exit 1; }
  printf %s "$OPENCRVS_TRACKING_ID" | grep -Eq '^[A-Za-z0-9._:-]{1,256}$' || { printf 'Conservative tracking-id shape required\n' >&2; exit 1; }
  case "$OPENCRVS_DOMAIN" in gateway.*|register.*|auth.*|events.*) OPENCRVS_DOMAIN=${OPENCRVS_DOMAIN#*.} ;; esac
  OPENCRVS_CLIENT_ID_CONFIG=$(printf %s "$OPENCRVS_CLIENT_ID" | curl_config_escape)
  OPENCRVS_CLIENT_SECRET_CONFIG=$(printf %s "$OPENCRVS_CLIENT_SECRET" | curl_config_escape)
  OPENCRVS_TOKEN_RESULT=$(
    curl --config - <<EOF | jq -ce 'if ((.access_token | type) == "string" and (.access_token | length) > 0 and ((.token_type // "Bearer") | ascii_downcase) == "bearer") then {token_shape_ok: true, access_token: .access_token} else error("token shape rejected") end'
silent
show-error
fail
no-location
max-redirs = 0
proto = "=https"
connect-timeout = 5
max-time = 15
get
request = "POST"
data-urlencode = "client_id=$OPENCRVS_CLIENT_ID_CONFIG"
data-urlencode = "client_secret=$OPENCRVS_CLIENT_SECRET_CONFIG"
data-urlencode = "grant_type=client_credentials"
url = "https://auth.$OPENCRVS_DOMAIN/token"
EOF
  )
  printf %s "$OPENCRVS_TOKEN_RESULT" | jq '{token_shape_ok}'
  OPENCRVS_ACCESS_TOKEN=$(printf %s "$OPENCRVS_TOKEN_RESULT" | jq -er .access_token)
  if ! curl_config_value_is_safe "$OPENCRVS_ACCESS_TOKEN"; then
    printf 'Token contains a prohibited control byte\n' >&2
    exit 1
  fi
  OPENCRVS_TOKEN_CONFIG=$(printf 'Authorization: Bearer %s' "$OPENCRVS_ACCESS_TOKEN" | curl_config_escape)
  export EVIDENCE_DIAG_EXPECTED=$OPENCRVS_TRACKING_ID
  OPENCRVS_BODY=$(jq -cn '{query: {type: "and", clauses: [{eventType: "birth", status: {type: "exact", term: "REGISTERED"}, trackingId: {type: "exact", term: env.EVIDENCE_DIAG_EXPECTED}}]}, limit: 2, offset: 0}')
  OPENCRVS_BODY_CONFIG=$(printf %s "$OPENCRVS_BODY" | curl_config_escape)
  curl --config - <<EOF | jq '{collection_shape_ok: ((.results | type) == "array" and (.total | type) == "number"), cardinality_ok: ((.results | type) == "array" and (.results | length) <= 2 and .total <= 2), exact_match_ok: ((.results | type) == "array" and (.results | length) == 1 and .total == 1 and .results[0].trackingId == env.EVIDENCE_DIAG_EXPECTED)}'
silent
show-error
fail
no-location
max-redirs = 0
proto = "=https"
connect-timeout = 5
max-time = 15
request = "POST"
header = "$OPENCRVS_TOKEN_CONFIG"
header = "Content-Type: application/json"
header = "Accept: application/json"
data = "$OPENCRVS_BODY_CONFIG"
url = "https://events.$OPENCRVS_DOMAIN/events/search"
EOF
)
```

## Credential and live-data rules

The live runner must:

1. Require a credential file outside the repository or values injected by a
   secret manager.
2. Refuse a credential file readable or writable by group or other users. On
   Unix, `0600` is the expected mode.
3. Parse an exact allowlist of `KEY=value` entries. Do not execute or `source`
   the file as shell code.
4. Reject duplicate, unknown, empty, or malformed required keys.
5. Never accept credential values as command-line arguments.
6. Disable HTTP debug output and redact complete token URLs, query strings,
   authorization headers, request bodies containing credentials, and token
   responses.
7. Keep tokens and source responses in memory only for the bounded request and
   never write recordings, snapshots, failure artifacts, or temporary files.
8. Print only the profile, safe phase, HTTP status category, duration, and
   pass, skip, or inconclusive result.

## Interpreting outcomes

| Result | Interpretation |
|---|---|
| Contract mock fails | Product or test-contract regression; blocks completion |
| Mock passes, live authentication fails | Local credential, client scope, or demo state issue |
| Mock passes, live response shape differs | Possible upstream version or configuration drift; inspect public documentation before changing fixtures |
| Live server is unavailable, rate-limited, or times out | Inconclusive public-demo result, not a product failure |
| Live test returns more data than configured | Minimization failure; stop and review before retaining any output |
| Live chain member returns zero results | Expected on a demo without the register the member searches; not a product failure and not a negative fact |
| Live chain stages reach the wire out of the declared order | Ordering failure; stop and review before any deployment relies on the chain |

Any upstream-driven contract change is first represented as a new sanitized
mock case. Only then may the source configuration or Rhai adapter change. Core
Rust changes require evidence that the behavior is generic across more than one
source shape.

## Public references

- DHIS2, [Tracker API 2.43](https://docs.dhis2.org/en/develop/using-the-api/dhis-core-version-243/tracker.html).
- OpenCRVS, [Record Search clients](https://documentation.opencrvs.org/v1.8/technology/interoperability/create-a-client/record-search-clients).
- OpenCRVS, [Authenticate a client](https://documentation.opencrvs.org/technology/interoperability/authenticate-a-client).
