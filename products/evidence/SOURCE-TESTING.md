# Evidence Source Testing

Status: Approved Version 1 source-testing contract
Date: 2026-11-02

## Purpose

Evidence must prove that its source boundary is generic without building a
connector framework or emulating entire source products. Testing therefore has
four ordered layers:

1. offline requirement fixtures that execute reviewed Adapter pack routes and
   assertion derivation semantics;
2. deterministic local HTTP mocks for materially different pack routes;
3. deterministic local SQLite extracts that execute each reviewed statement
   through the shared Adapter engine;
4. explicit, read-only local smoke tests against public demo systems.

Only the first three layers run in ordinary CI. A live smoke test supplements
the deterministic contracts. It never replaces them and never decides whether
a commit is correct.

## Proof matrix

Every AssertionDefinition names one Source. The Source binds one digest-pinned
Adapter pack route to one target connection and maps only authorized selector
fields into the route's closed inputs. The route owns the complete bounded
provider interaction and returns one schema-validated private FactSet or one
closed lookup outcome. Evidence has no second source execution language.

| Maintained proof | Route shape | What the proof establishes |
|---|---|---|
| Standalone and operator examples | One HTTP route over a synthetic register | Thin Source binding, minimized selector input, exact request replay, private fact projection, and derivation |
| FHIR example | One bounded FHIR read per route | Provider identity checks, bounded nested data, typed private facts, and the Reference fixture form |
| DHIS2 Tracker reference | Two Source bindings to routes in the maintained Adapter pack | Exact pack capture, route compilation, deterministic exchange replay, and expected facts without Evidence product specialization |
| Protected-read reference | One protected Registry HTTP route | Exact replay of match, no-match, ambiguous, unresolved, and pre-derivation refusal outcomes |
| Surviving-spouse acceptance project | One route with three fixed provider endpoints | One complete reviewed multi-operation program, exact exchange order, prefix stopping, and no per-stage Evidence authority |
| SQLite extract reference | One route through the shared `sqlite-extract` component | Real immutable extract execution, statement authorization, publication freshness, typed columns, and resource bounds |
| Host-protocol tests | Explicit protocols pinned by a pack endpoint | Closed access attribution and signed-Evidence verification without exposing protocol metadata as facts |

Product names identify compatibility-shaped tests. They do not promise a
maintained vendor connector, reproduce a whole server, or certify every provider
release and configuration. Production Evidence code, public project grammar and
CLI options remain source-product neutral.

Request-batch evaluation preserves request order and executes the selected
Source route independently for each logical item. Authorization, acquisition,
derivation, signing and release audit remain per item, and an outer failure
releases no partial envelope. A pack may contain bounded reviewed control flow,
retries or multiple sends, but those remain one route under the shared operation,
deadline and response-byte budgets. They do not create another Evidence source
or batching contract.

The maintained DHIS2 reference captures the current `dhis2-tracker` Adapter
pack exactly and binds two Evidence Sources to two of its routes. Its fixtures
replay each complete route with synthetic responses and compare the resulting
typed facts. The optional live check separately confirms that a selected public
demo still accepts the bounded Tracker request shape; it does not prove the
pack, derivation, authorization, audit or disclosure path.

The maintained OpenCRVS recipe exports an Adapter pack, Source fragment and
synthetic fixture project. Its fixed route builds one bounded Event Search
request for an exact tracking identifier and projects only the reviewed facts.
The optional live check covers that upstream authentication and request shape,
not the complete Evidence route or relationship semantics.

The SQLite reference builds a small invented database in a temporary directory,
adds the reserved publication row, captures the completed file as an immutable
snapshot and executes the statement pinned by the Adapter pack. The result is
never prerecorded. Replaying rows would leave the SQL, its parameter bindings
and its time boundaries unproved.

Fixture seed SQL is trusted executable project input and is not sandboxed as
untrusted code. Run only reviewed project seeds in an isolated local
environment. Never import or evaluate a foreign bundle as a fixture.

The maintained cases include four generic selector contracts independent of
the provider-shaped packs:

- one opaque identifier;
- one compound selector with no identifier;
- one compound profile with an additional configured disambiguator;
- one relationship request with two independently role-bound selectors.

Selector field names, exact field sets, scalar types and value origins come from
trusted project YAML. A Source maps only named authorized fields into a pack
route's closed input schema; the route decides their provider placement. The
Evidence core does not know what a name, civil identifier, licence number or
birth date means. Alternative sufficient field sets use separate named profiles
instead of caller-selected field combinations.

## What the deterministic tests contain

HTTP fixtures use small local mocks and invented synthetic provider
responses. Each acquisition transcript contains exact intercept declarations
and an ordered `exchanges` list. Every send must match and consume one exchange;
an unexpected send, mismatch or unconsumed exchange fails the case. The offline
host compiles the captured pack route before replay and never interprets a raw
provider response as an already resolved FactSet.

Two current fixture forms share that replay engine. They are not interchangeable
YAML spellings:

- A Reference acquisition case records the transcript under `acquisition` and puts
  lookup, fact, value, public-problem, signing, derivation and request-count
  expectations in the nested `expected` object. The FHIR and protected-read
  references use this form.
- A coequal acceptance acquisition case declares `coequalAcceptanceDefinition: true`,
  records the transcript under `source` and keeps `expectedLookup`,
  `expectedValue` or `expectedValues`, `expectedPublicProblem`,
  `derivationRuns` and `signedSuccess` at the case top level. The standalone
  acceptance projects use this form.

For example, a Reference case uses this shape:

```yaml
- id: active
  acquisition:
    intercepts:
    - type: endpoint
      endpoint: fhir
    exchanges:
    - request:
        endpoint: fhir
        method: GET
        path: /Coverage/coverage-synthetic
        headers:
          accept: application/json
      response:
        status: 200
        body:
          resourceType: Coverage
          id: coverage-synthetic
          status: active
          beneficiary:
            reference: Patient/patient-synthetic
  expected:
    lookup: match
    value: true
    derivationRuns: true
    signed: true
```

The equivalent control placement in a coequal acceptance case is:

```yaml
coequalAcceptanceDefinition: true
cases:
- id: positive
  source:
    intercepts:
    - type: endpoint
      endpoint: register
    exchanges:
    - request:
        endpoint: register
        method: GET
        path: /people/adult
      response:
        status: 200
        body:
          total: 1
          record:
            record_id: adult
            birth_date: '1980-01-01'
            residence_region: north
            address_canary: synthetic-address-private-canary
  expectedLookup: match
  expectedValue: true
  derivationRuns: true
  signedSuccess: true
```

When a maintained coequal fixture or its pinned Adapter pack changes, refresh
the fact assertion through the owning evaluator rather than transcribing it:

```text
evidencectl fixtures record-facts PROJECT \
  --target TARGET \
  --fixture fixtures/requirement.yaml \
  --write
evidencectl test PROJECT --target TARGET --fixture fixtures/requirement.yaml
```

Review the facts-only fixture diff between those commands. The recording run
must use the same pinned pack and target that the ordinary fixture run will
verify. It records only the final schema-validated Adapter `Match` facts,
removes a stale fact assertion from verified non-match cases, and leaves
`expectedValue` or `expectedValues` unchanged. Do not derive fact names or
values positionally from outputs and do not decode the recorded provider body
as a substitute for executing the pack.

The SQLite Reference fixture builds an invented extract from reviewable seed SQL
and executes the pinned statement. A `field-projected` posture means the provider
returned only the selected fields. A `record-transformed` posture permits a
broader provider record before the pack's private projection. Fixtures for the
latter include an unrelated synthetic canary and forbid that value in evidence
and diagnostics. Do not capture a public demo response and redact it after the
fact.

An Adapter pack endpoint that selects the `registry-lookup-v1` host protocol may
declare one unresolved Problem tuple: status `404`, an absolute HTTPS `type`,
and a closed `code`. Only an HTTP `404` with exactly one `Content-Type` header whose media type is
`application/problem+json` (compared case-insensitively, parameters such as
`charset` ignored), and a JSON object containing the string members `type`,
`title`, `detail`, `code`, and `traceId` and the number `status`, may be
classified as data-free `unresolved`. Members the classifier does not know are
ignored, so a later minor release of the source may add some. The body `type`,
`status`, and `code` must match the declared tuple, and the body must be
non-empty and at most 64 KiB.

Missing, duplicate, or other media types and malformed, missing-member,
duplicate-member, mistyped, tuple-mismatched, empty, or oversized bodies remain
protocol or dependency failures. A non-`404` response does not enter this
classifier. Provider error content never downgrades any of these failures to
`unresolved`.

The shared cases are:

- One exact match, `no_match`, `ambiguous` and, where the selected host protocol
  defines it, data-free `unresolved`;
- Identifier-only and compound selectors;
- Missing, extra, unknown, mistyped, empty, oversized, and unauthorized
  selector values rejected before credentials or source access;
- An additional disambiguating field accepted only as a distinct configured
  profile, never as a caller-added field;
- Two role-bound selectors with swapped-role and substitution failures;
- Missing, extra or mistyped private facts refused before derivation;
- Malformed provider JSON, wrong media type and response-schema drift;
- `401`, `403`, `429`, and `5xx`;
- Timeout, redirect, and response larger than the configured maximum;
- Credentials rejected without any credential value in diagnostics;
- Raw selector values and source values absent from errors, diagnostics,
  traces, snapshots, logs, metrics and audit;
- Broad candidates, scores, near-match hints, and comparison diagnostics absent
  from evidence, errors, responses, logs, and audit;
- Exact relationship membership succeeds and fails using an independently
  authorized candidate selector, while incomplete parent sets, mismatched
  namespaces, role substitution, and ambiguous child lookup stop without an
  authoritative negative assertion.

Pack-specific cases include:

- DHIS2 pager and `trackedEntities` shape, nested attribute lookup by configured
  identifier, fixed `fields`, and refusal to enumerate a second page;
- OpenCRVS exact child-event body, bounded event result, configured declaration
  fields, and missing or malformed parent references;
- FHIR resource identity, patient reference, controlled status and bounded
  coding arrays;
- The surviving-spouse route's three fixed endpoints, exact send order, prefix
  stopping and complete-set checks;
- Fixed headers, Basic, static Authorization, static API-key and OAuth client
  credentials, system-root and private-CA TLS, projection conflicts, and proof
  that ambient proxy variables are ignored;
- The explicit local credential-free boundary, including exact numeric-
  loopback origin validation and absence of an authentication header.
The SQLite profile has no HTTP mock, because it has no wire to mock. Its
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
  and clock actions refused by the statement authorizer;
- a second statement in the artifact, declared columns disagreeing with the
  real result columns, and statement parameters disagreeing with the declared
  bindings;
- the reserved evaluation instant reaching the statement, a pinned instant
  reproducing the same result, and a bundle declaring the reserved name refused;
- a route-supplied selector parameter, a parameter name the endpoint never
  declared, and a declared required parameter left unfilled;
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
columns. Evidence resolves and minimizes selector values before the pack route
begins, validates the closed route input schema, records durable acquisition
intent, then permits the route to use only its reviewed endpoints. Pack code
does not receive Evidence grants, credentials, source clients, signing keys or
release authority.

The route returns exactly `match(FactSet)`, `no_match`, `ambiguous` or, when its
reviewed protocol admits it, the data-free `unresolved` outcome. Only `match`
carries facts. Those facts must satisfy the route's pinned fact schema before
the Evidence derivation Function runs. The derivation may receive only its
separately declared authorized selector inputs. A non-match, ambiguity,
unresolved outcome, pack fault, schema fault or budget failure releases no
private facts and no assertion. Routes that contain multiple sends execute only
their reviewed control-flow prefix and remain inside one shared operation,
deadline and response-byte budget.

The acceptance suite runs adult status, residence region, professional licence,
legal-parent relationship and surviving-spouse status as coequal definitions
through the same pack-backed Evidence kernel. Relationship cases use separately
authorized subject roles and refuse incomplete authoritative sets. These
assignments exist only in maintained projects and do not create production
domain types.

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
cargo test --locked -p registry-evidence --test live_sources opencrvs -- --ignored --exact
```

The package test includes the pack source contracts, maintained pack replays,
host protocols and SQLite pack suites. It must be green before any live command
is run.

The statement transport adds no command to that sequence and has no live
counterpart. Its extract is a local file the tests build for themselves, so
the SQLite pack suites and the reference project's fixture run are the whole
proof, and there is no public demo whose availability could make the result
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

These live checks prove only that the selected demo version still accepts the
documented authentication and bounded lookup shape. The DHIS2 check does not
run the deployable adult-status derivation or prove its complete minimization
and response-protection path. The OpenCRVS check does not prove country-specific parent
reference fields, authoritative relationship-set completeness, parent
membership semantics, or the deployable family requirements. Deterministic
mocks and executable project fixtures own those contracts. A passing live check
must not be described as certification of a complete deployment project.

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

Any upstream-driven contract change is first represented as a new sanitized
mock case. Only then may the source configuration or Rhai adapter change. Core
Rust changes require evidence that the behavior is generic across more than one
source shape.

## Public references

- DHIS2, [Tracker API 2.43](https://docs.dhis2.org/en/develop/using-the-api/dhis-core-version-243/tracker.html).
- OpenCRVS, [Record Search clients](https://documentation.opencrvs.org/v1.8/technology/interoperability/create-a-client/record-search-clients).
- OpenCRVS, [Authenticate a client](https://documentation.opencrvs.org/technology/interoperability/authenticate-a-client).
