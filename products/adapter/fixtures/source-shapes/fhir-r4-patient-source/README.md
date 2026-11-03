# Source shape: FHIR R4 Patient search as a records source

A source-shape fixture, not a maintained pack. It holds one upstream API
shape against the authoring check, the compiler, fixture replay, and the
served runtime. The synthetic fixtures remain documented examples. A
bounded controlled acceptance also exercised this exact shape against HAPI
FHIR 8.12.0 serving FHIR 4.0.1; that does not establish general FHIR server
compatibility.

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
- A bounded controlled HAPI FHIR 8.12.0 acceptance served this shape through
  the normal Adapter facade, returned both search pages, and read back the
  same two Patient resources from the provider. This is evidence for the
  retained HAPI-specific shape only.

## Recorded gaps

These were recorded against the authoring model when the shape was written;
the pack's comments and scripts point here. `CONCEPT.md` holds the current
contract for each construct.

1. **Retained HAPI-specific continuation.** The current grammar can follow
   an absolute source link through origin-pinned `httpUri`, without exposing
   Camel `toD`. This older pack still rebuilds HAPI FHIR's continuation
   (`GET /?_getpages=..&
   _getpagesoffset=..`) from the link with `scripts/next-page-token.rhai`.
   That is server-specific; a Firely, Azure, or IBM FHIR server uses a
   different continuation shape. The controlled acceptance therefore covers
   HAPI 8.12.0 only. Camel: https://camel.apache.org/components/next/eips/toD-eip.html.
2. **Request headers.** The current endpoint model can allowlist `Accept`
   under `requestHeaders`, and a preceding `setHeader` then sends
   `Accept: application/fhir+json`. This older shape still falls back to
   `_format=json`, so it does not exercise that supported header path. Camel
   http forwards message headers through a HeaderFilterStrategy:
   https://camel.apache.org/components/next/http-component.html.
3. **Script input view.** The current script ABI documents the read-only
   `exchange` map (`body`, lowercase `headers`, and `properties`). This pack's
   scripts now rely on that supported ABI; the original grammar gap is
   resolved.
4. **This example still drains every page.** The current facade contract
   supports `AdapterContinuation` and `AdapterNextContinuation`, but this
   pack does not use them. It drains the whole searchset; past 10 pages it
   raises
   `loop.maximum-iterations-reached` instead of returning a page.
5. **Facade filters.** The current contract exposes declared search filters
   through `AdapterFilters`; this project declares the required `national_id`
   filter and the facade places it there. The original grammar gap is
   resolved.
6. **JSONPath and script values.** The current expression and script ABI
   define JSON arrays as Rhai arrays and preserve returned values in their
   selected slots. This example still assumes that `$.link` supplies an
   array and that the filtered `entry` selection supplies the matching
   resources; the controlled two-page run exercised those assumptions.
7. **Next-link origin.** Current `httpUri` sends enforce the configured
   endpoint origin and base path at runtime. This older pack does not use
   `httpUri`; it extracts only HAPI continuation values and sends them through
   fixed path and query keys. That avoids following an arbitrary origin but
   retains the HAPI-specific limitation in item 1.

The script profile also refuses anonymous functions (closures) and the Rhai
reserved word `use` as a property name, so `name.use` is written
`name["use"]`.

## Check

```
adapterctl check products/adapter/fixtures/source-shapes/fhir-r4-patient-source/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --runtime products/adapter/fixtures/source-shapes/fhir-r4-patient-source/runtime.yaml
```
