# kobotoolbox pack

A reviewed job pack for the governed-ingestion mode
(`products/adapter/CONCEPT.md` sections 17.1 and 17.2): it acquires
KoboToolbox submissions, one page per route run, and returns the item
contract `{items: [{key, revision, value}], next}`. No compiled
knowledge, no writes, no delete or patch endpoint, no
`_validation_status` handling beyond read-only passthrough inside the
captured value.

Unproved state, stated plainly: no KoboToolbox server has been
reached. Every upstream shape here is synthesized from the published
documentation, every fixture under `fixtures/` is synthetic with
`documented` provenance, and `testedVersions` is empty: the hosted
KoboToolbox documentation carries no server version and nothing was
exercised. The pack is unproved until a controlled deployment answers
the probe questions below.

## What the route reads

The v2 submissions listing, `GET /api/v2/assets/{uid}/data/`, one
page per run. (The brief's familiar `/submissions/` spelling is the
v1 name; v2 renamed it to `data`, kobotoolbox/docs
`source/migrating_api.md`, published from
https://support.kobotoolbox.org/api.html.) The reply envelope is
`{count, next, previous, results}`; the route reads `results` only and
never follows the reply's `next` URL. The resumption cursor is this
pack's own `{offset}` object: `next` is present when the page was full
(fixed `limit=100`, the documented default page size) and absent when
short or empty. Offset pages shift under concurrent submissions, so
the route declares `scan: ongoing` and `nextRecovery:
key-deduplicated`: the consumer deduplicates by key.

Deployment scoping: the asset a job reads is a deployment value. A
source route carries no template parameters, so the runtime config
binds the `kobo-api` endpoint's `baseUrl` to the data URL of the
deployment's own asset, origin plus base path, and the pack sends
`path: /`, which lands on the documented trailing slash. See
`products/adapter/examples/kobotoolbox-job/runtime.example.yaml`.

## Authentication

KoboToolbox authenticates API requests with an API token over
`Authorization: Token <token>` or with Basic auth over TLS
(kobotoolbox/docs `source/migrating_api.md`; the token retrieval page
documents `curl -u username:password` against
`https://[server-url]/token/?format=json`,
https://support.kobotoolbox.org/api.html).

An endpoint declares one kind, so this pack declares `basic`. A
deployment that prefers the personal API token swaps the endpoint kind
to `static-authorization` with `scheme: Token` and binds `tokenRef` in
the runtime config; both sides of the kind match move together. The
endpoint declares no request or response header allowlists: the
documented read consumes no header the engine would copy.

A refused credential never reaches the route: the engine's
authentication plan raises the uncatchable `credential.rejected` on a
401 under a static kind.

## Item mapping

- `key`: the submission's `_id`, as text. Hypothesis, see probes.
- `revision`: the submission's `_uuid`. Hypothesis, see probes; the
  documented alternative key is `meta/rootUuid`, which the docs
  describe as stable across edits while `_uuid` changes.
- `value`: the submission object exactly as the page returned it,
  `_validation_status` included only as read-only passthrough.

A submission without `_id` or `_uuid` fails the page rather than
producing a weaker item.

## Probe questions

The pack is unproved until a controlled deployment confirms each of
these (CONCEPT 17.7: every behavior that rests on documentation rather
than a probe is listed as unproved):

1. `_id` as the item key. Hypothesis from community posts and the
   docs sentence that `_id` is unchanged by edits
   (https://community.kobotoolbox.org/t/submission-id-and-uuid/6370;
   https://support.kobotoolbox.org/editing_and_deleting_data.html).
   Probe: is `_id` unique and stable per submission within one asset,
   across edits, deduplication, and server upgrades?
2. `_uuid` as the item revision. Hypothesis from the docs sentence
   "the `_uuid` value changes each time the submission is edited"
   (https://support.kobotoolbox.org/editing_and_deleting_data.html).
   Probe: does every submission carry `_uuid`, and does an edit always
   change it on the deployment's server?
3. `meta/rootUuid` persistence as the alternative stable key. The
   docs describe `rootUuid` as staying the same for the original
   submission while `_uuid` changes
   (https://support.kobotoolbox.org/editing_and_deleting_data.html;
   https://support.kobotoolbox.org/viewing_validating_data.html;
   implementation discussion
   https://github.com/kobotoolbox/kpi/issues/3940). Probe: is
   `meta/rootUuid` present on all submissions, including legacy ones,
   and stable across edits? If confirmed, the pack should switch its
   key to it and keep `_id` as a secondary.
4. Edit discovery. KoboToolbox REST Services push data to external
   servers "only on creation. Nothing is sent when data is edited"
   (https://support.kobotoolbox.org/rest_services.html), so edits are
   invisible to push integration and this pack polls instead. Probe:
   does an edited submission reappear at a position the offset scan
   reaches again, and do deletions ever surface to a poll-only
   consumer?
5. The 30,000-record bulk-read cap. Hypothesis from community posts
   about bulk reads refusing above 30,000 records; the number appears
   in the KoBoCAT source as `ParsedInstance.DEFAULT_LIMIT = 30000`
   (https://github.com/kobotoolbox/kpi,
   kobo/apps/openrosa/apps/viewer/models/parsed_instance.py). The
   maintained v2 page maximum is a server setting
   (`MAX_API_PAGE_SIZE`, default 1000; `DEFAULT_API_PAGE_SIZE`, 100).
   Probe: does the deployment's server refuse or truncate reads above
   the bulk cap, and does the fixed `limit=100` offset paging never
   trip it at the deployment's form sizes?
6. Offset-page shifts under concurrency. Declared
   `key-deduplicated`; not probed. Probe: how far do pages shift
   between two runs at the deployment's submission rate, and does
   deduplication by key hold the consumer's invariant?

## Fixtures

`fixtures/` carries five synthetic suites (`documented` provenance,
reference = the documentation URLs, upstreamVersion = the documented
Kobo behavior): two full pages, one short page, one empty page, each
with the expected item page, and a 401 suite expecting the
`credential.rejected` class. The maintained `AdapterFixture` artifact
is facade-shaped (a profile operation per entry); a job route has
neither, so these files keep the stable envelope and carry a
provisional job entry shape, marked in each header. They become
runnable when the job compiler's fixture format lands; they are
reviewable documents today.

## What this pack waits on

The job compiler and `adapterctl job check` land in the parallel
engine stream. Until then nothing here can be checked beyond the pack
reader and the core test suite. The files the job check should read:
this `pack.yaml` with its `scripts/`, the example
`products/adapter/examples/kobotoolbox-job/job.yaml`, and the example
`products/adapter/examples/kobotoolbox-job/runtime.example.yaml`.
