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
documentation names feature versions (`$orderby` since v2024.1, which
this pack needs) but pins no server version this pack was run
against. The pack is unproved until a controlled deployment answers
the probe questions below.

## What the routes read

Two source routes over one `odk-odata` HTTP endpoint, both with the
read order pinned rather than left to Central's default (newest
first), both `$top=100`, and neither following the reply's
`@odata.nextLink`: Central's `$skiptoken` pages in its default
newest-first order, so it cannot resume an ascending scan. No
`$expand`, no `$select`.

- `odk-submissions`: the Submissions entity set of one form's OData
  service, `GET /v1/projects/{projectId}/forms/{xmlFormId}.svc/Submissions`,
  one page per run (https://docs.getodk.org/central-api-odata-endpoints/).
  Every send carries `$orderby=__system/submissionDate asc`; past the
  first run it also carries
  `$filter=__system/submissionDate ge <cursor date>`. Both
  `__system/submissionDate` filtering and `$orderby` are documented
  for the Submissions entity set.
- `odk-repeats`: one repeat entity set. Central exposes each repeat as
  its own entity set (for example `Submissions.household.member`), so
  the deployment binds the endpoint base path to that set. Every send
  carries `$orderby=$root/Submissions/__system/submissionDate asc`
  (repeat rows in their parent submission's order, the `$root/`
  prefix the documentation gives for repeat filters) and `$skip` from
  the cursor's offset.

The `odk-submissions` cursor is `{submissionDate, seen}`: the date of
the last row read, as Central rendered it, and every id the reply
carried at that date. The filter's bound is inclusive (`ge`), so the
next reply starts with the rows at the cursor date again; those the
cursor lists as seen are dropped, the rest are new. The inclusive
bound with a seen list, instead of a strict `gt`, covers submissions
that share one rendered millisecond: Central stores the timestamp
more finely than it renders it, so a strict filter on the rendered
value could skip a row.

Both routes hold their place at the tail of the `ongoing` scan:

- a page with rows hands out the position after its last row
  (`{submissionDate, seen}` or `{offset}`);
- an empty page hands the incoming cursor back unchanged, so the next
  pass reads only what arrived since;
- a first run over a form with nothing to read hands out no cursor.

`odk-submissions` refuses a reply that is out of submission-date order
or reaches back before the cursor date (a server that ignored
`$orderby` or `$filter`), and refuses more than 40 ids at one rendered
date: the cursor would outgrow its 2 KiB bound (CONCEPT 17.2), and a
page of nothing but seen rows would never move on.

Deployment scoping: the project, form, and entity set a job reads are
deployment values. A source route carries no template parameters, so
the runtime config binds the `odk-odata` endpoint's `baseUrl` to the
entity-set URL of the deployment's own form, origin plus base path,
and the pack sends `path: /`. A job on the `odk-repeats` route binds
it to the repeat entity set's URL instead. See
`products/adapter/examples/odk-central-job/job-runtime.example.yaml`.

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
- `revision`: `__system/updatedAt`, or `__system/submissionDate`
  while the submission was never edited. Central leaves `updatedAt`
  null when a submission is first created
  (https://docs.getodk.org/central-api-submission-management/), so
  the fallback keeps an unedited submission's revision stable and an
  edit changes it. Probe-gated.
- `value`: the entity object exactly as the page returned it.
- `odk-repeats` keys: the repeat row's own `__id`. Central derives it
  from the parent instance and the row's place in it, and gives the
  parent's instance id under `__Submissions-id`
  (`__Submissions-<group>-id` for a repeat nested in a group); the
  route requires one such member, so a binding to the Submissions set
  fails instead of passing submissions off as repeat rows, and
  `value` carries it unchanged. A repeat row carries no `__system`,
  so its item carries no revision.

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
   maps Central's `updatedAt` to `__system/updatedAt`, and the
   submission-management documentation says it is null until the
   first edit. Probe: does it change on every edit on the deployment's
   Central version?
3. The submission-date keyset. The pack needs `$orderby` (documented
   since Central v2024.1) and a `ge` filter on
   `__system/submissionDate`. Probe: does the deployment's Central
   honour both, how many submissions share one rendered millisecond at
   its submission rate (the pack refuses more than 40), and does a
   submission's `submissionDate` stay fixed across edits?
4. Repeat read order and `$skip` stability. The repeat route orders by
   the parent submission's date and pages by offset. New submissions
   append at the end, but an edit that adds or removes a repeat row in
   an older submission shifts every later row by one: an added row
   re-reads one row (covered by `key-deduplicated`), a removed row
   skips one until the periodic rescan. Probe: does Central accept the
   `$root/Submissions/__system/submissionDate` ordering on a repeat
   set, is the order stable for rows of one parent, and do the
   `__id` and `__Submissions-id` members read as described above?
5. Session-token credential. The docs describe `POST /v1/sessions`
   and the bearer header (same auth page). Probe (engine side): what
   does a session-owning credential kind need, and does Central's
   default 24-hour expiry fit the deployment's job cadence?

## Fixtures

`fixtures/` carries six synthetic suites (`documented` provenance,
reference = the documentation URLs, upstreamVersion = unverified): a
first run reading the first 100 of 130 submissions (two of them
edited, the rest with a null `updatedAt`), the continuation, which
drops a boundary submission sharing its millisecond with the next one
and holds the tail, a later pass picking up two new submissions, the
empty pages (at the tail and on a first run), a 401 suite expecting
the `credential.rejected` class, and one repeat-table suite. Every
name and value in them is made up. The maintained `AdapterFixture`
artifact is facade-shaped (a profile operation per entry); a job route
has neither, so these files keep the stable envelope and carry a
provisional job entry shape, marked in each header.

`crates/registry-adapter/tests/job_pack_replay.rs` compiles this
pack's routes through the job compiler and replays every fixture
entry: it checks the exact request each route sends (path and query)
and the item page or problem class that comes back. The same file
holds the refusal cases (a reply reaching back before the cursor
date, a repeat route bound to the Submissions set). `adapterctl job
check` compiles the example job in
`products/adapter/examples/odk-central-job/`, and
`products/adapter/scripts/check-contracts.sh` runs it.
