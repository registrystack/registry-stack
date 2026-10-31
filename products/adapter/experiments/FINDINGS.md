# Adapter API transformation experiments: findings

The opening assessment records the pre-runtime state on 2026-10-30.
The dated executed Increment 1 rerun below supersedes its runtime-absence
claims and records the current proof and its limits.

Run on 2026-10-30 by the lead reviewer's session, before the Increment 1
runtime exists. Each experiment is authored config only (pack, project,
runtime config, fixtures, scripts), checked with `adapterctl check`; no Rust
was changed. Fixtures are documented from the public specification of each
API, never captured from a live system.

The question each experiment asks: can the authoring model express this real
API shape without new Rust, and do the checks refuse what is wrong and accept
what is right?

The headline: every experiment passes `check`, but passing `check` does not
mean the pack could run. Most findings are documents `check` accepts that the
runtime contract (CONCEPT sections 7 and 8, as they stood) could not execute
as written, because the exchange contract between the facade, the pack, and
the profile was unspecified.

## Experiments

| Experiment | Source shape | Target profile | Result |
|---|---|---|---|
| `fhir-r4-patient-source` | FHIR R4 `GET /Patient?identifier=`, searchset Bundle paged by `link[relation=next]`, `loop` with `doWhile` plus `enrich`, OAuth2 client credentials | `breg-records` | check exit 0 (10 files) |
| `fhir-r4-conditional-create` | FHIR conditional create (`If-None-Exist`) as the idempotent write, `idempotentConsumer` | `breg-records` | check exit 0 (9 files) |
| `graphql-cursor-source` | GraphQL with Relay cursor paging (`pageInfo { hasNextPage endCursor }`), API key header | `case-api` | check exit 0 (13 files) |
| `rest-offset-mtls` | REST offset and limit paging with a total cap, mTLS plus `private_key_jwt`, `circuitBreaker` with `onFallback`, `doTry`/`doCatch` mapping 404 | `breg-records` | check exit 0 (13 files) |
| `second-target-profile` | experiment 4's pack, unchanged | own `fhir-facade` profile | check exit 0 (13 files) |

Probes were edited copies of each experiment that each change one thing. They
confirmed the checks that work: upstream budgets refuse at the exact worst
case (experiment 1: 20 refused, 21 accepted, 10 pages x 1 send x 2 plus one
401 resend), write-without-idempotency, multiple non-safe sends,
redelivery over a non-safe send, closed HTTP methods, response-schema
mismatch, the secret reference shape, and the error-class vocabulary.

## Gaps in the model

Each gap names what the API needs, the Camel construct that expresses it, and
its status in CONCEPT section 8.10 as it stood.

| Id | Needed | Camel | CONCEPT before | Rank |
|---|---|---|---|---|
| G-FACADEIN | A defined place on the exchange for the caller's path parameters, query, cursor, limit, filters, and request record | REST DSL: a path parameter arrives as a header of the same name (`manual/rest-dsl.html`) | 8.2 said the consumer places them "on it", not where | P0 |
| G-SCRIPTABI | What a Rhai entrypoint receives and returns | languages see the whole exchange | silent | P0 |
| G-NEXTCURSOR | A construct that fills the envelope's `nextCursor`; without one a paged source drains everything or hits the loop bound | none, the facade contract is ours | "the engine owns encoding" only | P0 |
| G-PROBLEMS | Packs raise neutral outcomes and the profile maps them to its codes; today a pack must know the profile's problem codes, so D17 fails for errors | none | engine-filled problem slots had no pack-side source | P0 |
| G-RAISE | Raise a problem from a `choice` branch, an `onFallback`, or a status inside a 200 | `throwException` (`components/next/eips/throwException-eip.html`) | absent from 8.10 and from the not-ported list | P0 |
| G-REQHEADERS | Request headers: `Accept: application/fhir+json`, `Prefer`, `If-None-Exist` | the http component maps message headers through a `HeaderFilterStrategy` (`components/next/http-component.html`) | 8.2 covered response headers only | P0 |
| G-NEXTLINK | Follow an opaque next link the source returns, on the endpoint's own origin | `toD`, or the http component's `CamelHttpUri` header override | not ported | P0 |
| G-EXCHANGE | Whether properties survive `enrich` and `direct:`, and whose clauses handle an error raised in a `direct:` target | `direct:` shares the exchange; enrich sends a copy; error handlers are route scoped (`manual/error-handler.html`) | unstated; 8.6's own pagination pattern depends on it | P0 |
| G-FIXTURES | A facade request, several upstream exchanges per entry, request and response headers, JSON `null`, a problem assertion | `adviceWith` and `mock` | the replay row exists; the format cannot carry what replay needs | P1 (changes with G-FACADEIN, G-NEXTCURSOR, G-PROBLEMS) |
| G-BREAKERCLASS | Keep a 404 from counting as a breaker failure | resilience4j `recordException` and `ignoreException` (`resilience4jConfiguration-eip.html`) | absent | P1 |
| G-IDEMCLAIM | `idempotentUpstream` is a bare claim the check cannot verify | none | unstated | P1 |
| G-COMPARE | The inline languages have no comparisons, so a status test needs a one-line Rhai script | Simple has comparisons | unstated | P1 |
| G-JSONPATH | Whether a selector yields a node list or a single value | `camel-jsonpath` result types | undefined | P1 |
| G-LOOPTIMING | When `doWhile` is evaluated, and `copy` semantics | `loop-eip.html`; resolved from `LoopProcessor` at `camel-4.23.0`: tested before every iteration, the first included; `copy: false` chains out to in | not recorded; the core doc said after each iteration, which is wrong | P1, resolved in CONCEPT 8.6 |
| G-LOOPFIRST | A pagination predicate that holds before the first fetch: `fhir-r4-patient-source` (`fhirNextUrl` absent) and the maintained `dhis2-tracker` pack (`totalPages` unset) both stop before page one under Camel's timing; the offset experiments hold under both readings | `LoopProcessor.run()` evaluates the predicate first | 8.6 silent on timing | P1, fixed by seeding before the loop: dhis2-tracker in X2, the experiment in the 8.11 migration |
| G-LOOPCLASS | `loop.maximum-iterations-reached` is in the code but not in the 8.7 hierarchy | n/a | missing | P1 |
| G-CONTENTTYPE | Which media types count as JSON (`application/fhir+json`, `application/vnd.api+json`) | data formats | unstated | P1 |
| G-TIMEOUT | No connect or read timeout per endpoint | http `connectTimeout`, `responseTimeout` | absent | P1 |
| G-TOKENTLS | The token endpoint has no mTLS or CA setting (RFC 8705) | n/a | 10.2 silent | P1 |
| G-BOUNDS | `maximum_total` unchecked against the loop bound; `maximumIterations` cannot be templated | n/a | unstated | P1 |
| G-GQLQUERIES | One query per graphql endpoint | `query`, `queryFile`, `queryHeader` per send | narrower | P2 |
| G-GQLRESPONSE | Unwrapping `data`, and partial-error behaviour | "errors in the response do not fail the exchange" (`components/next/graphql-component.html`) | diverges, `data` not covered | P2 |
| G-METHODS | No DELETE or HEAD | http methods | closed set | P2 |
| G-SCRIPTRULES | Script restrictions (for example the `use` keyword) undocumented | n/a | silent | P2 |
| G-TEMPLATEINT | Template integers reach scripts as strings | n/a | unstated | P2 |
| G-ORIGIN | A pack cannot see the configured origin | n/a | by design, record it | P2 |
| G-FILTERNAMES | Facade filter names | n/a | unstated | P2 |
| G-NAMES | FHIR camelCase members and capitalized resource types fail the record-field identifier pattern | n/a | by design for the declared model | P2 |
| G-ENVELOPE-1 | Per-record wrapping (`{"resource": ...}`) | n/a | absent | P2, P1 if D17's second-profile promise is meant for Increment 1 |
| G-ENVELOPE-2 | Record members spread at the envelope's top level | n/a | absent | same |
| G-ENVELOPE-3 | A cursor inside a URL string (`link[].url`) | n/a | absent | same |
| G-ENVELOPE-4 | Conditional members | n/a | absent | same |

## Check defects

Each with the minimal document that shows it. Status is at the branch tip
when the experiments ended; "fixed" items were fixed by the Increment 0
staff-review round that was running in parallel.

| Id | Defect | Minimal document | Status |
|---|---|---|---|
| C1 | Path not origin-relative | `path: https://other.example.invalid/Patient`, or `path: "{next}"` filled from a property | open |
| C2 | `okStatusCodeRange` unvalidated | `okStatusCodeRange: banana`, `200-299,404` | open |
| C3 | Header reads and writes unbounded; would forward the caller's token (security) | `setHeader: {name: Authorization, value: {header: Authorization}}` before a send; `query: {identifier: {header: CamelHttpResponseCode}}` | open |
| C4 | Endpoint-wide `idempotentUpstream` covers a POST naming no operation | a send with no `operation` on an endpoint with one idempotent operation | fixed |
| C5 | Redelivery over a `direct:` target that POSTs | `maximumRedeliveries` over `to: direct:postTransaction` | fixed |
| C6 | One redelivery defect reported twice, once at a template id | `/routes/createPatient` and `/routes/patient-create` | open |
| C7 | Script-uncompilable pointer lacks `/routeTemplates/N` | `/steps/7/rhai` | open |
| C8 | A script that does not parse, or has no matching entrypoint, passes in some slots | `fn find_variables(exchange) { let x = ; }` | open |
| C9 | GraphQL query file unchecked | `queryFile: scripts/to-case.rhai`; a file holding `this is not graphql {{{`; `operationName: NoSuchOperation` | open |
| C10 | API key header name unchecked | `headerName: Cookie`, `headerName: "X Api: Key"` | open |
| C11 | HTTP parameters accepted on a `graphql:` send | `httpMethod`, `path`, `pathParameters`, `query` on `graphql:` | open |
| C12 | Unbound path placeholder | `path: /regions/{region}/households/{id}` with only `id` bound | open |
| C13 | `tokenEndpoint` is a bare string (security) | `tokenEndpoint: http://auth.example.invalid/oauth2/token`, `not a url at all` | open |
| C14 | Problem code outside the profile passes | `family: totally.made-up`, `source.not-found` under `case-api` | in flight |
| C15 | Malformed envelopes pass, and the fixture body check is skipped on a derivation failure | `responseEnvelope: '{"resourceType": "Bundle",,, "entry": {{records}}}'`; `problemEnvelope: '<OperationOutcome code="{{problemCode}}"/>'` | in flight |
| C16 | Envelope literals do not constrain the result schema | an expected body with `resourceType: Patient` against an envelope fixing `Bundle` | open |
| C17 | Relative or wrong paths pass | `path: /fhir/Basic` for a search, `path: fhir/Basic/{whatever}` for a read | open |
| C18 | A problem body built in `onFallback` or `choice` passes as a success body | `onFallback` producing an OperationOutcome | open, resolved by G-RAISE |
| C19 | Write safety reads `httpMethod` only; a GraphQL mutation redelivered three times without an idempotent consumer passes | graphql mutation endpoint, `maximumRedeliveries: 3` | open |
| C20 | A POST search counts as a write | a FHIR `POST /_search` | open (Part 1 P2-5) |
| C22 | Committed schemas drift from the model | `adapterctl schemas --check` fails on the fixture and pack schemas | in flight |
| C23 | The `dhis2-tracker` pack still spelled its `upstream` too-large class in camelCase after the kebab respell, so its check fails | `pack.yaml` lines 123, 216, 308 | in flight |
| O8 | `dhis2-tracker` `shape-records.rhai` calls `to_record`, defined in another file | found by reading, not probed | open |
| O9 | `dhis2-tracker` maps every `upstream.http` on the read to a 404 not-found | the read route's `onException` | open |

## Ranking and disposition

P0, blocks the Increment 1 runtime design: G-FACADEIN, G-SCRIPTABI,
G-NEXTCURSOR, G-PROBLEMS, G-RAISE, G-REQHEADERS, G-NEXTLINK, G-EXCHANGE. The
lead reviewer resolved all eight in CONCEPT section 8.11 (the exchange
contract) and the related lines in sections 7, 8.6, 8.7, and 8.10.

P1: G-FIXTURES and every check defect above that is open; the check defects
are Increment 0 scope (authoring checks) and were routed to the orchestrator
as staff-review round 6. The remaining P1 gaps are Increment 1 scope.

P2: as ranked in the table.

## Rerun at the branch head (2026-10-30, 06:40 and 07:00)

The experiments were respelled to the head vocabulary, with no change in
meaning:

- `routeTemplateRef` became `routeTemplate`.
- Template parameter names became local identifiers (`identifier_system`,
  `region_code`, `page_size`, `maximum_total`, `case_type`).
- Error classes became kebab case (`upstream.too-large`,
  `loop.maximum-iterations-reached`).
- `slidingWindowSize` became `slidingWindowCalls`.
- The fixture provenance and intercept discriminator became `type`.
- The enrich aggregation strategy became the tagged form
  (`type: json-array-append`).
- Each pack digest was repinned.

Upstream wire names (`filter[regionCode]`, `attributes.regionCode`, FHIR
members) were left as the source spells them.

The first rerun refused four of the five experiments, each on one new check
defect, C24. Round 6 fixed it, and the second rerun passes all five:

| Experiment | Result |
|---|---|
| `fhir-r4-patient-source` | check exit 0 (9 files) |
| `fhir-r4-conditional-create` | check exit 0 (8 files) |
| `graphql-cursor-source` | check exit 0 (12 files) |
| `rest-offset-mtls` | check exit 0 (12 files) |
| `second-target-profile` | check exit 0 (12 files) |

New check defects found by the rerun:

| Id | Defect | Minimal document | Status |
|---|---|---|---|
| C24 | The http `query` map was keyed by local identifiers, so upstream wire names were refused. Query names belong to the source; path parameter keys stay local identifiers because they name placeholders in the pack's own path | `query: {_format: {constant: json}}`, `query: {"filter[region]": ...}` | fixed in round 6 |
| C25 | CONCEPT 8.6 named the breaker window `slidingWindowSize`, while the model reads `slidingWindowCalls` | CONCEPT section 8.6, breaker defaults | fixed in CONCEPT |

Passing `check` still does not mean the packs run: the gaps above wait for
the Increment 1 runtime, and each experiment is replayed there (DoD item 9).

## Executed Increment 1 rerun (2026-10-31)

The five experiments now execute through the native `adapter` binary over an
isolated PostgreSQL journal schema and a socket upstream double. The run used
only the committed documented fixtures. It did not contact FHIR, GraphQL,
JSON:API, or any other external service, and it does not turn documented
fixtures into captured evidence.

For every experiment, the native `adapterctl` binary ran all three acceptance
commands before the facade request:

- `check` exited 0 with a complete, diagnostic-free report.
- `fixtures replay` exited 0 with `drive: completed` and the fixture's exact
  entry and upstream-exchange counts.
- `verify --live` exited 0 with `drove: 0`. It reported one waited binding for
  each FHIR experiment and two for each GraphQL/JSON:API experiment, all as
  `caller-sourced`. These waits are authoring verdicts, not transport probes.
  The native runtime journey below is the execution proof.

The native results were:

| Experiment | Native upstream transcript | Facade result |
|---|---|---|
| `fhir-r4-patient-source` | OAuth2 client-credentials token request, then both documented FHIR search pages with exact methods, paths, queries, and bodies | 200, exactly the fixture's two Patient records and closed `breg-records` envelope |
| `fhir-r4-conditional-create` | OAuth2 client-credentials token request, transaction Bundle POST, then the exact Patient read-back | 201, exactly the fixture's created Patient and closed `breg-records` envelope |
| `graphql-cursor-source` | Exact GraphQL POST document and variables with the declared static API-key header | 200, fixture case values in the closed `case-api` envelope; the upstream cursor was sealed rather than disclosed |
| `rest-offset-mtls` | RFC 7523 assertion token request and JSON:API search over TLS that required the generated client certificate | 200, exactly the fixture's two households and closed `breg-records` envelope |
| `second-target-profile` | The same private-key-JWT and mutual-TLS JSON:API transcript over the unchanged pack | 200, exactly the fixture values in the distinct closed `fhir-facade` envelope |

The OAuth token replies used the fixture's synthetic bearer token with
`expires_in: 300`. The private-key JWT was cryptographically verified against
its public JWK, including issuer and audience, and the mutual-TLS server
required a CA-signed client certificate on both token and data connections.
Before each accepted facade request, a token signed by an untrusted key was
refused with 401 and caused zero upstream requests. This proves inbound JWT
verification precedes every source effect; no caller token was forwarded.

Focused execution command and result:

```text
cargo test --locked -p registry-adapter --features postgres-test --test experiments_served
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
