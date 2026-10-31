# PACKS stream scratch: port record

Decisions made while authoring the kobotoolbox and odk-central job
packs, in the port-record form. Nothing here is a claim about a live
source; every upstream shape is documentation-derived and probe-gated
in the pack READMEs.

## Scope

Two reviewed job packs, rung 1 of the source ladder: `http` only, one
route shape each, no writes, no delete or patch endpoints, no
`_validation_status` handling beyond read-only passthrough inside the
captured value. One page per route run; the runner advances the cursor.
Both routes are `ongoing` scans with `key-deduplicated` recovery:
Kobo's offset pages and Central's `$skiptoken` pages may both shift
between reads when submissions arrive or are edited while a job runs.

## The deployment-scoping question (the one real gap)

A source route carries no template parameters and an `AdapterJob`
carries none either, but both sources scope their reads to a
deployment-owned object: Kobo's asset uid in the data path, Central's
project id and form id in the OData path. The format's honest slot for
a deployment path is the endpoint binding's `baseUrl`: the engine
pins the origin plus its base path
(`crates/registry-adapter/src/component/http/uri.rs`, `PinnedOrigin`)
and every send stays under it, so each deployment binds the
endpoint's base URL to the data path it owns and the pack sends
`path: /`. This is recorded in both pack headers and both example
runtime configs. If the job compiler later grows a parameters block
on the job definition, these base-path bindings should move there.

## KoboToolbox

- Endpoint and path: the maintained v2 API names the submissions
  listing `GET /api/v2/assets/{uid}/data/` (the v1 name
  `/assets/{uid}/submissions/` was renamed to `data` in v2;
  kobotoolbox/docs `source/migrating_api.md`, published under
  https://support.kobotoolbox.org/api.html). The brief's
  `/submissions/` spelling is the v1 name; the pack follows the
  documented v2 name via the deployment's base path plus `path: /`
  (the trailing slash is Django's).
- Query: `format=json`, `limit=100` (the documented default page size;
  the server's configurable maximum must not be raised by a pack),
  `start=<offset>` from the job cursor. Keys and values are engine
  percent-encoded, so the wire form is `format=json&limit=100&start=0`.
- Reply: `{count, next, previous, results}` (the paginator's envelope).
  The pack reads `results` only and never follows the reply's `next`
  URL: the cursor is the pack's own `{offset}` object, so paging stays
  origin-pinned by construction.
- Item mapping: key = `_id` as text (hypothesis), revision = `_uuid`
  (hypothesis), value = the submission object as returned. The 401
  answer maps to `credential.rejected` by the engine's auth plan
  (`crates/registry-adapter/src/auth/plan.rs` answers a 401 under a
  non-OAuth2 kind with `CredentialRejected`); the pack adds no clause.
- Redelivery: one retry on `upstream.timeout` and `upstream.connection`
  after 2 seconds, mirroring the dhis2-tracker read clauses. A GET is
  safe to repeat.

## ODK Central

- Endpoint: the OData entity set of one form, bound as the endpoint's
  base path (for example
  `https://central.example.invalid/v1/projects/1/forms/fixture-form.svc/Submissions`).
  First send: `path: /` with `$top=100` and `$count=true`. Continuation
  send: the `httpUri` origin-pinned link from the cursor's `nextLink`,
  no path, no query (CONCEPT 8.11.5; the pin admits a link whose path
  equals or sits under the base path, `is_under` in
  `crates/registry-adapter/src/component/http/uri.rs`). `@odata.nextLink`
  is used as written by the engine's pinned-link rules.
- Item mapping: key = `__id` (documented key, probe-gated), revision =
  `__system/updatedAt` (probe-gated), value = the entity object.
- Auth: `basic` declared; the session-token alternative
  (`POST /v1/sessions`, then `Authorization: Bearer`) is documented in
  the README, not declared, mirroring the dhis2 PAT note. Central's own
  docs call Basic "allowed, but strongly discouraged"
  (https://docs.getodk.org/central-api-authentication/), so the README
  says the deployment should prefer the session token once the engine
  grows a bearer-token credential kind that owns the session exchange;
  `static-authorization` pins a scheme plus one static value and a
  24-hour session token is not static, so the honest answer today is
  Basic plus the note.
- Repeats sketch: `odk-repeats` reads one page of a repeat entity set
  (the deployment binds the endpoint base path to that entity set, for
  example `.../Submissions.children.child`), same paging, key =
  parent reference + row position within the page, both parts
  probe-gated (the OData page names no parent-reference member and no
  within-parent ordinal).

## Fixtures

The maintained fixture artifact (`AdapterFixture`) is facade-shaped:
an entry carries a `facadeRequest` against a profile operation and an
`ExpectedFacade`. A job route has neither. Until the engine stream's
job compiler defines the job-mode fixture format, the fixtures in
`packs/kobotoolbox/fixtures/` and `packs/odk-central/fixtures/` keep
the stable envelope (apiVersion, kind, id, pack, upstreamVersion,
provenance, intercepts) and carry a provisional entry shape
(`jobRun.cursor`, the ordered upstream exchanges, and `expected` as
the item page or the error class), marked provisional in each file
header. They are reviewable documents and offline replay targets once
the format lands; they are not runnable fixtures today. Provenance is
`documented` throughout, with the documentation URL as the reference.

Fixture layout lives inside each pack directory
(`packs/<id>/fixtures/`) because `products/adapter/fixtures/` is the
shared facade-fixture ground this stream does not own; the integrator
may move the suites there when the job replay runner lands.

## Validation performed

- `cargo test -p registry-adapter-core` stays green (no code changed).
- Every authored YAML parses (python3 yaml).
- Script digest pins computed with `shasum -a 256` over the file bytes,
  spelled exactly as the dhis2 pack spells them.
- What could not be executed: `adapterctl job check` does not exist
  yet (parallel engine stream). The exact files it should check are
  listed in the stream report and in each example's header comment.
