# Source shape: a second target profile over an unchanged pack

A source-shape fixture, not a maintained profile or pack. The profile is
authored from the public FHIR R4 specification
(https://hl7.org/fhir/R4/bundle.html, https://hl7.org/fhir/R4/http.html#paging,
https://hl7.org/fhir/R4/operationoutcome.html); no server was contacted.

## The shape

D17 says "the same DHIS2 pack serves a `breg-records` deployment and a
later GovStack deployment unchanged" (CONCEPT section 7). This shape
writes a third facade profile, `fhir-facade` (`profile.yaml`), and binds an
existing pack to it without touching the pack:

- `pack.yaml` and `scripts/` are byte copies of the `rest-offset-mtls`
  `jsonapi-households` pack (same digest,
  `sha256:993b64ddd49a122dade6ae198e5d72209c89d87a13fd737ef01e2761bd025e28`).
- `fhir-search-type` answers a searchset Bundle with `entry` and a `next`
  link; `_page_token` and `_count` are the paging parameters.
- `fhir-read` answers one resource with `resourceType` and `id`.
- Problems answer an OperationOutcome whose codes are FHIR IssueType codes
  (`not-found`, `transient`, `processing`, `exception`), with no `status`
  member (FHIR carries the status on the HTTP response only).

## What it proves

- A third profile with its own operation ids, underscore query parameter
  names (`_page_token`, `_count`), problem codes, and a problem envelope
  without a `status` slot is pure configuration: `check` accepts it.
- The engine-side search and read routes bind to it with no pack change.
- The envelope's result slot is validated against the bound record type:
  the fixture's `entry` items are checked against `household`.
- `adapterctl compile --check` holds the committed `generated/openapi.json`
  (FHIR paths, the Bundle envelope, `_page_token` and `_count`), and
  `adapterctl fixtures replay` replays `fixtures/search-first-page.yaml`
  (the `rest-offset-mtls` transcript compared against this profile's
  envelope); `products/adapter/scripts/check-contracts.sh` runs both.
- `crates/registry-adapter/tests/experiments_served.rs` (feature
  `postgres-test`, run by `products/adapter/scripts/test-postgres.sh`)
  serves the same pack to this profile's closed shape through the real
  Adapter binary against a mutual-TLS socket upstream.

## Recorded gaps

These were recorded against the profile vocabulary when the shape was
written; the profile, runtime config, and fixture point here. `CONCEPT.md`
holds the current contract for each construct.

1. **Per-record wrapping.** FHIR wraps every Bundle entry as `{"resource":
   ...}`. The `records` slot fills a whole array with bare records and has
   no item template, so the FHIR-correct expected body is refused
   (`adapter.fixture.response-schema` at
   `/entries/0/expectedFacadeResponse/body/entry/0/resource`). The committed
   fixture asserts the non-FHIR shape the vocabulary does produce.
2. **Record members at the top level.** A FHIR read puts the resource's own
   members beside `resourceType` and `id`. The `record` slot is one member
   value, so the profile nests the record in an `extension`. A spread form
   (`{"resourceType": .., "id": .., {{record}}}`) is not JSON.
3. **Field and type names.** FHIR member names are camelCase
   (`resourceType`, `birthDate`) and resource types are capitalized
   (`Patient`). Record field and record type names must match
   `^[a-z][a-z0-9_-]{0,63}$` (`config.invalid-value`), and the record type
   is what fills `{type}` in the facade path, so `/fhir/Patient` cannot be
   served. There is no per-profile name mapping.
4. **Cursor inside a URL.** R4 `Bundle.link.url` is an absolute URL. A slot
   is a whole member value or a whole JSON value; `"url":
   "https://../household?_page_token={{?nextCursor}}"` is not a valid slot
   use.
5. **Conditional members.** With no next page, `{{?nextCursor}}` drops the
   `url` member but leaves `{"relation": "next"}` in the `link` array, which
   is invalid FHIR (`link.url` is 1..1). There is no conditional array item
   or object.
6. **Problem vocabulary lives in the pack.** The pack's handled clauses
   build breg-records problem bodies (`type`, `title`, `status`, `code`
   with `source.*` codes). Under `fhir-facade` the codes are not in
   `problems` and the body is not an OperationOutcome, yet `check`
   passes, both for the copied pack and for the maintained `dhis2-tracker`
   pack. Either the runtime refuses every mapped error, or a FHIR caller
   receives a breg-records problem. CONCEPT section 7 says the engine fills
   `problemCode`, `problemTitle`, `problemDetail`, and `status`, but no pack
   construct supplies those values: the pack writes the whole body. D17
   does not hold for errors.
7. **Fixtures are profile-bound.** A fixture entry names a profile
   operation and asserts a facade body in the profile's envelope, so a
   pack's fixture corpus cannot move with the pack: the `dhis2-tracker`
   fixtures against `fhir-facade` give `adapter.fixture.unknown-operation`.
   Upstream exchange and record result would need to be split from the
   envelope assertion to reuse them.

## Check

```
adapterctl check products/adapter/fixtures/source-shapes/second-target-profile/project.yaml \
  --profile products/adapter/fixtures/source-shapes/second-target-profile/profile.yaml \
  --runtime products/adapter/fixtures/source-shapes/second-target-profile/runtime.yaml
```
