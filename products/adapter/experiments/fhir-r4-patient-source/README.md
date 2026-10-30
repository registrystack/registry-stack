# Experiment 1: FHIR R4 Patient search as a records source

Status: experiment, not a maintained pack. Authored from the public FHIR R4
specification only; no server was contacted. Nothing here changes Rust.

## What it tries to express

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
  21 passes (probes `e1-budget20`, `e1-budget21`).
- The fixture response-schema check catches an undeclared member in the
  expected facade body (probe `e1-fixture-extra`).

## What it could not express (gaps)

1. **Following the opaque `next` link.** FHIR says the next link is opaque
   and absolute. The `to` step has no dynamic URI (Camel `toD`), query keys
   are static, and a `pathParameters` value encodes one segment. The pack
   therefore rebuilds HAPI FHIR's continuation (`GET /?_getpages=..&
   _getpagesoffset=..`) from the link with `scripts/next-page-token.rhai`.
   That is server-specific; a Firely, Azure, or IBM FHIR server uses a
   different continuation shape. Camel: https://camel.apache.org/components/next/eips/toD-eip.html.
2. **Request headers.** `Accept: application/fhir+json` cannot be sent; the
   pack falls back to `_format=json`. `to.parameters` has no `headers`
   member (probe `e1-request-header`), and whether a `setHeader` reaches
   the upstream request is undefined (probe `e1-setheader-accept` passes
   silently). Camel http forwards message headers through a
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
8. **Fixtures.** An entry is one upstream exchange with no facade request,
   so the two-page drain cannot be replayed; `fixtures/search-two-pages.yaml`
   records the first page only.

## Check defects found

- `path` is not required to be origin-relative: `path: https://other.example.invalid/Patient`
  and `path: "{next}"` filled from a property both pass (probe `e1-absolute-path`).
- `okStatusCodeRange: banana` passes (probe `e1-status-range`).
- `setHeader` of `Authorization` (from the inbound `Authorization` header)
  passes, and a `header:` expression may read `Authorization` or
  `CamelHttpResponseCode` without any declared readable set (probes
  `e1-setheader-accept`, `e1-undeclared-header-inline`).
- The script profile refuses anonymous functions (closures) and the Rhai
  reserved word `use` as a property name (`name.use` must be `name["use"]`);
  the first check run reported
  `error[adapter.pack.script-uncompilable] ... (scripts/to-records.rhai):62:17 /steps/7/rhai  the script does not parse`.
  The pointer omits the template id, and neither restriction is documented
  for authors.

## Check run

```
adapterctl check products/adapter/experiments/fhir-r4-patient-source/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --runtime products/adapter/experiments/fhir-r4-patient-source/runtime.yaml
Authoring check passed.
0 errors, 0 warnings in 10 files
exit=0
```

Probe outputs are recorded verbatim in the findings report returned with these
experiments, not in this directory.
