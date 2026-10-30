# Experiment 3: Relay-style GraphQL source on the case-api profile

Status: experiment, not a maintained pack. Authored from the Relay
connection and object-identification specifications
(https://relay.dev/graphql/connections.htm,
https://relay.dev/graphql/objectidentification.htm) and the GraphQL over
HTTP draft (https://graphql.github.io/graphql-over-http/draft/) only; no
server was contacted. Nothing here changes Rust.

## What it tries to express

`cases-find` and `cases-get` on the second test profile, `case-api`
(`products/adapter/profiles/case-api/profile.yaml`), answered from a GraphQL
case system behind a static API key:

- `cases-find`: one Relay connection page per facade call
  (`cases(first:, after:, status:)` with `pageInfo { hasNextPage endCursor }`),
  the facade's `pageStateToken`/`maxResults` passed through as the Relay
  `after`/`first`, and the request envelope's `query` record mapped to the
  `status` enum filter.
- `cases-get`: `node(id:)` (Relay object identification), where a missing
  node is a `200` with `data.node: null`, mapped to the profile's
  `cases.missing` 404.
- Problem bodies in the case-api vocabulary (`family`, `message`,
  `httpStatus`).

## What it proves

- A GraphQL source with its query document, operation name, and variables
  script is expressible over the `graphql` component, and `check` pins the
  query files in the `queryFiles` inventory.
- A second, deliberately foreign profile (POST search, different paging
  names, different problem envelope) binds without new Rust.
- Budget arithmetic for a static API key has no token-refresh term: 1 send x
  (1 + 1 redelivery) = 2 per route.
- A GraphQL read sent as `httpMethod: POST` (the GraphQL over HTTP default)
  is refused for its redelivery and, on the POST facade, as a write (probe
  `e3-query-over-post`), which is itself a classification defect (below).

## What it could not express (gaps)

1. **Facade inputs.** The variables script assumes the facade cursor and
   page size arrive as headers named after the profile's pagination
   parameters (`pageStateToken`, `maxResults`) and the request envelope's
   record as the body. Nothing defines either.
2. **Facade `nextCursor`.** `scripts/next-cursor.rhai` computes the Relay
   `endCursor` into the property `nextCursor`, but no construct hands a
   route value to the envelope's `{{?nextCursor}}` slot. CONCEPT section 7
   says the engine owns cursor encoding, and does not say where the value
   it encodes comes from.
3. **Whether the graphql component unwraps `data`.** The scripts try both
   `body.data.cases` and `body.cases`. GraphQL over HTTP can answer `200`
   with an `errors` array and partial `data`; nothing says whether that
   raises `upstream.http`, `upstream.malformed`, or passes as success.
4. **Ending the exchange with a problem from a plain step.** The `cases-get`
   missing-node branch builds the `cases.missing` body in a `choice`
   branch. CONCEPT section 7 validates every final body against the success
   schema, so at runtime that branch fails; Camel's `throwException`
   (https://camel.apache.org/components/next/eips/throwException-eip.html)
   is not ported. `check` passes it. Experiment 4 shows the workaround
   (raise `validation` on purpose).
5. **Problem vocabulary is the profile's.** Every handled clause spells the
   case-api envelope members (`family`, `message`, `httpStatus`) and codes.
   The same pack cannot serve `breg-records` without rewriting every clause,
   which contradicts D17 ("a pack knows a source system"). Experiment 5
   probes this from the other side.
6. **One query per endpoint.** A `graphql` endpoint carries exactly one
   `queryFile`, `operationName`, and `variables`, so two queries over one
   origin and one key are two endpoints, and the runtime config repeats the
   origin and the key reference for each.
7. **Fixtures.** A fixture cannot hold JSON `null`, so the documented
   `data.node: null` answer cannot be recorded (first draft:
   `error[config.null-value] .../find-first-page.yaml:75:17 /entries/1/upstreamResponse/body/data/node`);
   and an expected problem response is validated against the success schema
   (probe `e3-problem-fixture`, five `adapter.fixture.response-schema`
   errors), so a fixture cannot assert a mapped error at all. The committed
   fixture holds the `cases-find` page only.

## Check defects found

- **GraphQL send safety.** A `graphql` `to` without `parameters` counts as
  safe because the non-safe test reads `httpMethod`. A GraphQL mutation
  bound to the `cases-file` write, sent twice, with `maximumRedeliveries: 3`
  and no `idempotentConsumer`, passes (probe `e3-mutation-write`). With
  `httpMethod: POST` the read query is refused instead (probe
  `e3-query-over-post`).
- **Write classification by facade method.** The write rule keys on the
  profile operation's HTTP method, so the POST search `cases-find` counts as
  a write (`adapter.route.write-without-idempotency /bindings/0/route` in
  probe `e3-query-over-post`). The redelivery finding is also reported twice,
  once at the template id `/routes/find-cases` and once at the instance.
- **Endpoint variables script unchecked.** A variables script that does not
  parse, and one without the named entrypoint, both pass (probe
  `e3-variables-broken`).
- **Query files unchecked.** `queryFile` may name a `.rhai` script, a query
  file holding `this is not graphql {{{` passes, and `operationName:
  NoSuchOperation` is never matched against the document (probe
  `e3-queryfile-script`).
- **API key header name.** `headerName: Cookie` and `headerName: "X Api:
  Key"` pass (probe `e3-header-names`); the reserved list covers only
  `authorization`, `connection`, `content-length`, `expect`, `host`,
  `transfer-encoding`, and header-name syntax (RFC 9110 token) is not
  checked. (Token syntax landed 2026-10-30 as
  `adapter.pack.invalid-header-name` / `adapter.route.invalid-header-name`;
  the reserved list has since grown too.)
- **Problem codes unchecked.** A handled clause answering `source.not-found`
  (a breg-records code) or `totally.made-up` under `case-api` passes (probe
  `e3-foreign-problem-code`), though CONCEPT 8.7 requires "a code from the
  profile's problem code list".
- **HTTP parameters on a graphql send.** `path`, `pathParameters`, and
  `query` on a `graphql:` `to` pass (probe `e3-graphql-http-parameters`).
  (Landed 2026-10-30 as `adapter.route.graphql-send-members`; the pack now
  declares `graphql: query` on its endpoint operations and names the
  operation on each send, which also makes the queries count as safe
  upstream.)

## Check run

```
adapterctl check products/adapter/experiments/graphql-cursor-source/project.yaml \
  --profile products/adapter/profiles/case-api/profile.yaml \
  --runtime products/adapter/experiments/graphql-cursor-source/runtime.yaml
Authoring check passed.
0 errors, 0 warnings in 13 files
exit=0
```

Probe outputs are recorded verbatim in the findings report returned with these
experiments, not in this directory.
