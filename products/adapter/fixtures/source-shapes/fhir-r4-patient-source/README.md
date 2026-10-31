# Source shape: FHIR R4 Patient search as a records source

A source-shape fixture, not a maintained pack. It holds one upstream API
shape against the authoring check, the compiler, fixture replay, and the
served runtime. Authored from the public FHIR R4 specification only; no
server was contacted.

## The shape

`records-search` on the `breg-records` profile, answered from a FHIR R4
server's `GET /Patient?identifier=<system>|` searchset:

- OAuth 2.0 client credentials (`oauth2-client-credentials`) to the FHIR
  server's token endpoint (SMART Backend Services style scope
  `system/Patient.read`).
- A searchset Bundle drained page by page through `Bundle.link[relation=next]`
  (https://hl7.org/fhir/R4/http.html#paging), bounded by `loop` with
  `maximumIterations: 10`.
- Only `entry[search.mode = match]` kept (`_include` results dropped).
- Patient mapped to the record type (`national_id` from the identifier with
  the configured system, `family_name`/`given_names` from the official
  HumanName, `birth_date`, `gender`).

## What it proves

- The loop, enrich-with-`direct:`, `jsonArrayAppend` aggregation with
  `uniqueBy`, `choice`, `setProperty` with `jsonpath`, and Rhai mapping are
  enough to drain a cursor-by-link API **when** the next request can be
  rebuilt from static path and query keys.
- The static worst-case budget arithmetic is exact: 10 iterations x 1 send x
  (1 + 1 redelivery) + 1 refreshed-401 resend = 21. Budget 20 is refused,
  21 passes.
- The fixture response-schema check catches an undeclared member in the
  expected facade body.
- `adapterctl compile --check` holds the committed `generated/openapi.json`,
  and `adapterctl fixtures replay` replays both documented pages in
  `fixtures/search-two-pages.yaml`; `products/adapter/scripts/check-contracts.sh`
  runs both.
- `crates/registry-adapter/tests/experiments_served.rs` (feature
  `postgres-test`, run by `products/adapter/scripts/test-postgres.sh`)
  serves the shape through the real Adapter binary against a socket
  upstream.

## Recorded gaps

These were recorded against the authoring model when the shape was written;
the pack's comments and scripts point here. `CONCEPT.md` holds the current
contract for each construct.

1. **Following the opaque `next` link.** FHIR says the next link is opaque
   and absolute. The `to` step has no dynamic URI (Camel `toD`), query keys
   are static, and a `pathParameters` value encodes one segment. The pack
   therefore rebuilds HAPI FHIR's continuation (`GET /?_getpages=..&
   _getpagesoffset=..`) from the link with `scripts/next-page-token.rhai`.
   That is server-specific; a Firely, Azure, or IBM FHIR server uses a
   different continuation shape. Camel: https://camel.apache.org/components/next/eips/toD-eip.html.
2. **Request headers.** `Accept: application/fhir+json` cannot be sent; the
   pack falls back to `_format=json`. `to.parameters` has no `headers`
   member, and whether a `setHeader` reaches the upstream request is
   undefined. Camel http forwards message headers through a
   HeaderFilterStrategy: https://camel.apache.org/components/next/http-component.html.
3. **Script input view.** No document says what a `setBody`/`setProperty`
   `rhai` expression receives. The scripts assume the exchange map
   (`exchange.body`, `exchange.properties`, `exchange.headers`).
4. **Facade paging.** `records-search` has `cursor` and `limit`, but no
   construct produces `nextCursor` from a route, so the route drains the
   whole searchset; past 10 pages it raises
   `loop.maximum-iterations-reached` instead of returning a page.
5. **Facade filters.** The search parameters a caller supplies have no
   declared exchange names, so the identifier value is a template parameter,
   not a caller filter.
6. **jsonpath cardinality.** Whether `setProperty` with a filter jsonpath
   yields a node list or a single value is undefined; `fhirNextUrl` assumes a
   single value, `pages` a list.
7. **Next-link origin.** The base URL never enters the exchange, so a pack
   cannot check that a `next` link stays on the configured origin.

The script profile also refuses anonymous functions (closures) and the Rhai
reserved word `use` as a property name, so `name.use` is written
`name["use"]`.

## Check

```
adapterctl check products/adapter/fixtures/source-shapes/fhir-r4-patient-source/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --runtime products/adapter/fixtures/source-shapes/fhir-r4-patient-source/runtime.yaml
```
