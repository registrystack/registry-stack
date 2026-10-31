# Source shape: Relay-style GraphQL source on the case-api profile

A source-shape fixture, not a maintained pack. It holds one upstream API
shape against the authoring check, the compiler, fixture replay, and the
served runtime. Authored from the Relay connection and
object-identification specifications
(https://relay.dev/graphql/connections.htm,
https://relay.dev/graphql/objectidentification.htm) and the GraphQL over
HTTP draft (https://graphql.github.io/graphql-over-http/draft/) only; no
server was contacted.

## The shape

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
- `adapterctl compile --check` holds the committed `generated/openapi.json`
  (the profile's read-only POST with a closed request body), and
  `adapterctl fixtures replay` replays `fixtures/find-first-page.yaml`;
  `products/adapter/scripts/check-contracts.sh` runs both.
- `crates/registry-adapter/tests/experiments_served.rs` (feature
  `postgres-test`, run by `products/adapter/scripts/test-postgres.sh`)
  serves the shape through the real Adapter binary against a socket
  upstream.

## Recorded gaps

These were recorded against the authoring model when the shape was written;
the pack's comments and fixture point here. `CONCEPT.md` holds the current
contract for each construct.

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
   is not ported. `check` passes it. The `rest-offset-mtls` source shape
   shows the workaround (raise `validation` on purpose).
5. **Problem vocabulary is the profile's.** Every handled clause spells the
   case-api envelope members (`family`, `message`, `httpStatus`) and codes.
   The same pack cannot serve `breg-records` without rewriting every clause,
   which contradicts D17 ("a pack knows a source system"). The
   `second-target-profile` source shape probes this from the other side.
6. **One query per endpoint.** A `graphql` endpoint carries exactly one
   `queryFile`, `operationName`, and `variables`, so two queries over one
   origin and one key are two endpoints, and the runtime config repeats the
   origin and the key reference for each.
7. **Fixtures cannot assert a mapped error.** An expected problem response
   is validated against the success schema, so the `cases-get` not-found
   entry (a Relay `node: null` answer mapped to `cases.missing`) is refused
   with `adapter.fixture.response-schema`. The committed fixture holds the
   `cases-find` page only.

## Check

```
adapterctl check products/adapter/fixtures/source-shapes/graphql-cursor-source/project.yaml \
  --profile products/adapter/profiles/case-api/profile.yaml \
  --runtime products/adapter/fixtures/source-shapes/graphql-cursor-source/runtime.yaml
```
