# odk-central pack

A reviewed job pack for the governed-ingestion mode
(`products/adapter/CONCEPT.md` sections 17.1 and 17.2): it acquires
ODK Central submissions over the Central OData endpoints, one page per
route run, and returns the item contract
`{items: [{key, revision, value}], next}`. No compiled knowledge, no
writes, no delete or patch endpoint.

Unproved state, stated plainly: no ODK Central server has been
reached. Every upstream shape here is synthesized from the published
documentation, every fixture under `fixtures/` is synthetic with
`documented` provenance, and `testedVersions` is empty: the Central
documentation names feature versions (the `$skiptoken` nextLink since
v2023.4) but pins no server version this pack was run against. The
pack is unproved until a controlled deployment answers the probe
questions below.

## What the routes read

Two source routes over one `odk-odata` HTTP endpoint:

- `odk-submissions`: the Submissions entity set of one form's OData
  service, `GET /v1/projects/{projectId}/forms/{xmlFormId}.svc/Submissions`,
  one page per run (https://docs.getodk.org/central-api-odata-endpoints/).
  The first run sends `$top=100&$count=true`; a continuation follows
  the reply's `@odata.nextLink`, which since Central v2023.4 carries a
  `$skiptoken` opaque cursor. The link is handed on as written and the
  next run sends it through the engine's origin-pinned link rules
  (CONCEPT 8.11.5): the engine parses it once and refuses it with
  `egress.refused` unless it stays inside the endpoint's origin and
  base path. No `$expand`, no `$filter`, no `$select`.
- `odk-repeats`: a sketch, not a finished route. Central exposes
  repeats as separate entity sets (for example
  `Submissions.children.child`), so the deployment binds the endpoint
  base path to one repeat entity set and this route reads one page of
  it with the same send shapes. Its key composition rests on two
  unproved members, see the probe questions; treat the route as the
  sketch a controlled deployment refines.

Deployment scoping: the project, form, and entity set a job reads are
deployment values. A source route carries no template parameters, so
the runtime config binds the `odk-odata` endpoint's `baseUrl` to the
entity-set URL of the deployment's own form, origin plus base path,
and the pack sends `path: /` for the first page. A Central nextLink
carries the entity-set path itself, which the pin admits (a link
whose path equals the base path is under it). See
`products/adapter/examples/odk-central-job/runtime.example.yaml`.

## Authentication

Central accepts Basic auth over HTTPS (its own docs call it "allowed,
but strongly discouraged" because every request re-verifies the
password, https://docs.getodk.org/central-api-authentication/) and
bearer session tokens minted by `POST /v1/sessions`, expiring by
default after 24 hours. An endpoint declares one kind, so this pack
declares `basic`. The session-token alternative needs a credential
kind that owns the session exchange (mint once, carry
`Authorization: Bearer`, re-mint on expiry); a `static-authorization`
pin carries one static value and a 24-hour session token is not
static. So the statement is: Basic today, over mandatory TLS, and the
session-token credential is an engine capability to ask for, not a
pack edit.

Central answers 401 without a `WWW-Authenticate` challenge; the
engine's authentication plan raises the uncatchable
`credential.rejected` before any route step sees it.

## Item mapping

- `key`: the entity's `__id` (the documented OData key; Central's
  field table maps it to the submission `instanceId`). Probe-gated.
- `revision`: `__system/updatedAt`. Hypothesis: changes on edit.
  Probe-gated.
- `value`: the entity object exactly as the page returned it.
- `odk-repeats` keys: `<parent>/<absolute row position>`, where the
  parent reference `__parent-id` and the within-parent ordinal are
  both hypotheses; the consumer's fallback is the repeat row's own
  `__id`, carried unchanged inside `value`.

A page whose entities lack the mapped members fails rather than
producing weaker items.

## Probe questions

The pack is unproved until a controlled deployment confirms each of
these (CONCEPT 17.7: every behavior that rests on documentation rather
than a probe is listed as unproved):

1. `__id` as the item key. Documented as the entity's key
   (`PropertyRef Name="__id"`, mapped to the submission `instanceId`
   in Central's field table,
   https://docs.getodk.org/central-api-odata-endpoints/). Probe: is
   `__id` the submission instance UUID, unique and stable, on the
   deployment's Central version?
2. `__system/updatedAt` as the item revision. The same field table
   maps Central's `updatedAt` to `__system/updatedAt`. Probe: does it
   change on every edit, and is it present on all entities?
3. `@odata.nextLink` and `$skiptoken` stability. Since Central v2023.4
   the nextLink carries a `$skiptoken` opaque cursor (same page).
   Probe: does replaying a nextLink after upstream inserts or edits
   re-read or skip rows only within what the `key-deduplicated`
   declaration covers, and does a skiptoken expire?
4. Repeat-table parent reference and ordinal. The OData page names no
   member by which a repeat entity references its parent submission
   and no within-parent ordinal; the sketch reads `__parent-id` and
   composes `<parent>/<position>`. Probe: what is the actual
   parent-reference member of a repeat entity, is there a stable
   within-parent ordinal ("repeat index"), and if not, should the key
   fall back to the repeat row's own `__id`?
5. Session-token credential. The docs describe `POST /v1/sessions`
   and the bearer header (same auth page). Probe (engine side): what
   does a session-owning credential kind need, and does Central's
   default 24-hour expiry fit the deployment's job cadence?

## Fixtures

`fixtures/` carries six synthetic suites (`documented` provenance,
reference = the documentation URLs, upstreamVersion = unverified):
two full Submissions pages (the second through the pinned nextLink),
one short page, one empty page, a 401 suite expecting the
`credential.rejected` class, and one repeat-table page for the sketch.
The maintained `AdapterFixture` artifact is facade-shaped (a profile
operation per entry); a job route has neither, so these files keep the
stable envelope and carry a provisional job entry shape, marked in
each header. They become runnable when the job compiler's fixture
format lands; they are reviewable documents today.

## What this pack waits on

The job compiler and `adapterctl job check` land in the parallel
engine stream. Until then nothing here can be checked beyond the pack
reader and the core test suite. The files the job check should read:
this `pack.yaml` with its `scripts/`, the example
`products/adapter/examples/odk-central-job/job.yaml`, and the example
`products/adapter/examples/odk-central-job/runtime.example.yaml`.
