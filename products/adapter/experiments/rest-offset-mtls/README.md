# Experiment 4: offset-paged REST source behind mTLS

Status: experiment, not a maintained pack. Authored from the public JSON:API
1.1 specification (https://jsonapi.org/format/) and RFC 7523 / RFC 8705
only; no server was contacted. Nothing here changes Rust.

## What it tries to express

`records-search` and `records-get` on the `breg-records` profile, answered
from a JSON:API household registry:

- Offset pagination with bracketed query keys: `GET /households?filter[regionCode]=..&page[offset]=..&page[limit]=..`
  (https://jsonapi.org/format/#fetching-pagination), `meta.total` as the
  upstream count.
- A hard total cap: when `meta.total` exceeds the deployment's
  `maximum_total` (1000), the whole search is refused, never truncated.
- Mutual TLS to the registry (`mtlsIdentity`), a private root bundle
  (`caBundleRef`), and an OAuth 2.0 client-credentials grant authenticated
  with a signed client assertion (`oauth2-private-key-jwt`, RFC 7523).
- A circuit breaker around every send, whose rejection (`breaker.open`) maps
  to `source.unavailable` 503.
- An upstream 404 on the read mapped to `source.not-found` 404 **without**
  counting as a breaker failure: `doTry`/`doCatch` sits inside the breaker,
  so the breaker sees a success.

## What it proves

- Bracketed JSON:API query keys (`"page[offset]"`) are accepted as static
  query keys; the fixture's percent-encoded query matches them.
- The `loop` over `to: direct:fetch-household-page` with exchange properties
  as the paging state (`pageOffset`, `upstreamTotal`, `households`) is
  expressible, and the budget counts the send behind the `direct:` hop:
  10 iterations x 1 send + 1 refreshed-401 resend = 11. Budget 10 is
  refused (probe `e4-budget10`); the read's 2 is exact (probe
  `e4-budget-get1`).
- `doCatch` naming a class outside the closed hierarchy is refused (probe
  `e4-docatch-bogus`); a plain path as `caBundleRef` is refused (probe
  `e4-plain-ca`).
- The runtime config can express mTLS plus private-key JWT on the upstream
  endpoint.

## What it could not express (gaps)

1. **Ending the exchange with a problem from a plain step.** CONCEPT section
   7 validates every final route body against the success schema, and
   `onFallback` output "is validated like any route output" (8.7). So a
   `choice` branch or a fallback cannot answer `source.not-found` or
   `source.unavailable`; only a handled clause can. Camel's
   `throwException` (https://camel.apache.org/components/next/eips/throwException-eip.html)
   is not ported, so the pack raises `validation` on purpose
   (`scripts/is-present.rhai`) for a handled `validation` clause to catch.
   The first draft (kept as probe `e4-fallback-problem`) built the problem
   bodies in `onFallback` and in a `choice` branch, and `check` passed it.
2. **Breaker failure classification.** resilience4j's `recordExceptions` and
   `ignoreExceptions` (https://camel.apache.org/components/next/eips/resilience4jConfiguration-eip.html,
   https://resilience4j.readme.io/docs/circuitbreaker) are not in 8.7, so
   every raised class counts as a failure, a 404 included. The `doTry`
   inside the breaker is the only way to keep a "not found" from opening
   the breaker; it works only for the single-send read, not for a 4xx in
   the middle of a page loop. `onFallback` cannot tell rejection from
   failure either.
3. **Error propagation across `direct:`.** The page fetch lives in the
   plain route `fetch-household-page`; the clauses that map its
   `breaker.open`, `upstream.*`, and `validation` live on the calling
   template. No document says whether an error raised in a `direct:`
   target is handled by the caller's clauses. I believe Camel hands it back
   to the caller, whose route-scoped `onException` then applies, but the
   exception-clause page (https://camel.apache.org/manual/exception-clause.html)
   does not say so for `direct:`; unverified.
4. **Paging state across `enrich`.** The CONCEPT's paging pattern
   (`enrich` per page with `jsonArrayAppend`) cannot carry the offset and
   total back to the loop predicate if the resource exchange is a copy.
   Camel's enrich page (https://camel.apache.org/components/next/eips/enrich-eip.html)
   documents only the aggregation strategy combining "the original exchange
   and the resource exchange", not what happens to properties, so
   the pack uses `to: direct:` and repeats `jsonArrayAppend` with `uniqueBy:
   id` by hand in `scripts/append-page.rhai`. Swapping in `enrich` passes
   `check` (probe `e4-enrich-loop`), so the check cannot tell the
   difference either.
5. **The total cap is unchecked against the loop bound.** `maximum_total`
   50000 with `maximumIterations: 10` and `page_size: 100` passes (probe
   `e4-maxtotal-over-reach`): the route then raises
   `loop.maximum-iterations-reached` after 1000 records instead of answering.
   `maximumIterations` cannot be a template parameter (probe
   `e4-maxiter-template`, `config.expected-integer`), so the two bounds
   cannot be derived from one value.
6. **Template integers are strings at runtime.** A template parameter is
   placed only inside a quoted `constant`, so `page_size` and `maximum_total`
   reach the scripts as text and need `parse_int`.
7. **Token endpoint transport.** RFC 8705 section 2 has the client
   authenticate to the token endpoint over mTLS; `caBundleRef` and
   `mtlsIdentity` bind the upstream endpoint only, and nothing says whether
   the token request uses them. A token endpoint on a private CA cannot be
   reached.
8. **Upstream response content type.** A fixture's `upstreamResponse` takes
   only `status` and `body`; `headers` is refused (first check run:
   `error[config.unknown-key] .../fixtures/search-first-page.yaml:35:7 /entries/0/upstreamResponse/headers`),
   so `application/vnd.api+json` cannot be recorded or replayed, and
   CONCEPT does not say which content types the http component parses as
   JSON.
9. **Facade inputs.** As in experiment 1: the region filter is a template
   parameter, not a caller filter, and the read assumes the record id
   arrives as the `recordId` header.

## Check defects found

- `tokenEndpoint: http://auth.example.invalid/oauth2/token` passes, and so
  does `tokenEndpoint: not a url at all` (probes `e4-token-http`,
  `e4-token-garbage`). The field is a `String`, not a `Url`, in
  `crates/registry-adapter-core/src/auth.rs`, so a client assertion can be
  sent in the clear. (Landed 2026-10-30 as
  `adapter.runtime.insecure-origin` on the token endpoint origin and
  `config.invalid-value` at the reader for a value that is no URL.)
- An unbound path placeholder passes: `path: /regions/{region}/households/{id}`
  with only `id` in `pathParameters` (probe `e4-unbound-placeholder`).
  (Landed 2026-10-30 as `adapter.route.path-parameter-mismatch`: send paths
  write `{{name}}` and both directions of the correspondence are checked.)
- `okStatusCodeRange: 200-299,404` passes (probe `e4-status-range`); as in
  experiment 1 the value is not validated at all. (Landed 2026-10-30 as
  `adapter.route.invalid-status-code-range`, validated as Camel writes it.)
- A problem body built outside a handled clause (in `onFallback`, in a
  `choice` branch) passes (probe `e4-fallback-problem`), though the runtime
  contract would validate it as a success body.

## Check run

```
adapterctl check products/adapter/experiments/rest-offset-mtls/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --runtime products/adapter/experiments/rest-offset-mtls/runtime.yaml
Authoring check passed.
0 errors, 0 warnings in 13 files
exit=0
```

Probe outputs are recorded verbatim in the findings report returned with these
experiments, not in this directory.
