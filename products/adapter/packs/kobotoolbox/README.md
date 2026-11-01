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
never follows the reply's `next` URL.

The read order is pinned rather than left to the server default.
Every send carries `sort={"_id":1}` and `limit=100` (the documented
default page size); past the first run it also carries the keyset
filter `query={"_id":{"$gt":<afterId>}}` built from the job cursor.
The `sort` and MongoDB-syntax `query` parameters are documented in the
kpi API documentation (`kpi/docs/api/v2/data/list.md`), and `_id` is
the integer submission id the kpi server sorts on by default. A
submission only ever gains a larger `_id` than every earlier one, so
the keyset neither skips nor repeats rows when submissions arrive
between runs, where a `start` offset would shift.

The resumption cursor is this pack's own `{afterId}` object:

- a page with submissions, full or short, hands out the `_id` of its
  last submission;
- an empty page hands the incoming cursor back unchanged, so the
  `ongoing` scan holds its place at the tail and the next pass reads
  only what arrived since;
- a first run over a form with no submissions hands out no cursor,
  since there is no position to keep.

A reply whose `_id`s do not climb past the cursor (a server that
ignored `sort` or `query`) fails the run rather than hand out a
position that would skip or repeat submissions. The route declares
`nextRecovery: key-deduplicated` as the documented fallback.

Deployment scoping: the asset a job reads is a deployment value. A
source route carries no template parameters, so the runtime config
binds the `kobo-api` endpoint's `baseUrl` to the data URL of the
deployment's own asset, origin plus base path, and the pack sends
`path: /`, which lands on the documented trailing slash. See
`products/adapter/examples/kobotoolbox-job/job-runtime.example.yaml`.

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
- `value`: the submission object with its slash-separated group and
  repeat names nested into objects. Kobo returns group answers as flat
  names such as `household/household_size`; the item value carries
  them as `household: {household_size: ...}`, so a job projection
  addresses them as `household.household_size` (the projection
  grammar has no escape for a slash inside a member name). Rows of a
  repeat group arrive with their full names
  (`household/member/member_name`); each row drops its repeat's own
  name before nesting. `_validation_status` passes through only inside
  `value`, read-only.

A submission without an integer `_id` or without `_uuid` fails the
page rather than producing a weaker item, and so does a name that is
both an answer and a group (`household` and `household/x` in one
submission), because nesting would have to drop one of them.

The route shapes one submission per script call (a `split` over
`results`), so a wide form never shares one script budget with the
whole page.

## Probe questions

The pack is unproved until a controlled deployment confirms each of
these (CONCEPT 17.7: every behavior that rests on documentation rather
than a probe is listed as unproved):

The source route declares `edits: rescan` with a one-hour
`rescanDelaySeconds`: the documentation does not say whether an edited
submission moves in the API's read order, so the safe declaration is
that an edit stays behind the position and a periodic rescan re-reads
from the first page. The probe below settles it; if an edit moves the
submission past the read position, the declaration changes to `ordered`
and the rescan cost disappears.

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
   invisible to push integration and this pack polls instead. An edit
   keeps its `_id`, so it stays behind the keyset position and only
   the periodic rescan sees it. Probe: does an edit ever change `_id`,
   and do deletions ever surface to a poll-only consumer?
5. The 30,000-record bulk-read cap. Hypothesis from community posts
   about bulk reads refusing above 30,000 records; the number appears
   in the KoBoCAT source as `ParsedInstance.DEFAULT_LIMIT = 30000`
   (https://github.com/kobotoolbox/kpi,
   kobo/apps/openrosa/apps/viewer/models/parsed_instance.py). The
   maintained v2 page maximum is a server setting
   (`MAX_API_PAGE_SIZE`, default 1000; `DEFAULT_API_PAGE_SIZE`, 100).
   Probe: does the deployment's server refuse or truncate reads above
   the bulk cap, and does the fixed `limit=100` keyset paging never
   trip it at the deployment's form sizes?
6. `sort` and `query` honoured. The keyset rests on the server
   applying `sort={"_id":1}` and `query={"_id":{"$gt":N}}` as the kpi
   source reads them (the `sort` parameter in `kpi/views/v2/data.py`;
   `$gt` in the query key allowlist of `kpi/utils/mongo_helper.py`).
   Probe: on the deployment's server, does a filtered, sorted read
   return exactly the submissions past `N` in ascending `_id` order,
   and is `_id` assigned in increasing order as submissions arrive?
7. Slash-separated names. Probe: do group and repeat answers arrive
   as slash-separated names in `results` on the deployment's server,
   and can one submission carry both `x` and `x/y` (which the pack
   refuses)?

## Fixtures

`fixtures/` carries five synthetic suites (`documented` provenance,
reference = the documentation URLs, upstreamVersion = unverified):
a first run reading the first 100 of 130 submissions, the
continuation reading the remaining 30 and holding the tail, a later
pass picking up two new submissions, the empty pages (at the tail and
on a first run), and a 401 suite expecting the `credential.rejected`
class. Every name and value in them is made up. The maintained
`AdapterFixture` artifact is facade-shaped (a profile operation per
entry); a job route has neither, so these files keep the stable
envelope and carry a provisional job entry shape, marked in each
header.

`crates/registry-adapter/tests/job_pack_replay.rs` compiles this
pack's route through the job compiler and replays every fixture
entry: it checks the exact request the route sends (path and query)
and the item page or problem class that comes back. The same file
holds the refusal cases (a reply reaching back past the cursor, a name
that is both an answer and a group). `adapterctl job check` compiles
the example job in
`products/adapter/examples/kobotoolbox-job/`, and
`products/adapter/scripts/check-contracts.sh` runs it.
