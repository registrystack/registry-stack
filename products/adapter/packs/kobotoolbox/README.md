# kobotoolbox pack

A reviewed job pack for the governed-ingestion mode
(`products/adapter/CONCEPT.md` sections 17.1 and 17.2): it acquires
KoboToolbox submissions, one page per route run, and returns the item
contract `{items: [{key, revision, value}], next}`. No compiled
knowledge, no writes, no delete or patch endpoint, no
`_validation_status` handling beyond read-only passthrough inside the
captured value.

The maintainers ran the pack with synthetic data on a real KoboToolbox
`2.026.37c` server, using its submissions and edit APIs. A separate direct job
journey reached a submitted BReg Proposal, distinct human Casework approval, and
one applied record. An unchanged rescan skipped the item; editing the same
submission held it with the prior Proposal reference instead of registering it
again. No run record is committed, so `testedVersions` is unverified until your
own pilot repeats the run. This is bounded local evidence, not a production or
server-upgrade compatibility claim. The committed replay fixtures remain
synthetic.

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

An endpoint declares one kind, so this pack declares
`static-authorization` with `scheme: Token`, and the runtime config
binds the personal API token through `tokenRef`. The token reads the
API only. A Kobo password also signs in to the web UI, so a leaked
password is a full account login. A deployment that must use Basic
swaps the endpoint kind to `basic` and binds `usernameRef` and
`passwordRef`; both sides of the kind match move together. The
endpoint declares no request or response header allowlists: the
documented read consumes no header the engine would copy.

A refused credential never reaches the route: the engine's
authentication plan raises the uncatchable `credential.rejected` on a
401 under a static kind.

## Item mapping

- `key`: the submission's `_id`, as text, scoped to one configured asset.
- `revision`: the submission's `_uuid`. Controlled edits kept `_id` and
  `meta/rootUuid` stable while changing `_uuid`. A job does not switch its
  identity selector after delivery; existing effects need reconciliation
  before an identity migration.
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

## Probe results and remaining limits

The probe server was a real KoboToolbox `2.026.37c` loaded with synthetic data.
These observations apply to that server and version:

1. **Submission identity:** all 101 submission `_id` values were unique.
   An authenticated edit kept the same `_id`. Deduplication and identity
   continuity across server upgrades remain unproved.
2. **Revision:** real submissions carried `_uuid`, and both controlled
   edits changed it. The pack still refuses a submission missing it.
3. **Root identity:** the edited submissions retained `meta/rootUuid`.
   Legacy submissions and every historical form version were not tested.
   The maintained asset-scoped key remains `_id`.
4. **Edit discovery:** a source edit stayed behind the saved keyset tail.
   A rescan found it; an ordinary tail read did not. Keep `edits: rescan`
   and the bounded reconciliation interval. Deletion history is not a
   poll-only change feed.
5. **Read cap:** fixed `limit=100` returned pages of 100 and 1, followed by
   an empty tail. A 30,000-item deployment and bulk-cap behavior were not
   exercised. Size the response bound and rescan cost for each form; [Wide
   forms](#wide-forms) says how to change them.
6. **Sorting and filtering:** `sort={"_id":1}` and the `$gt` keyset filter
   returned exactly the expected ascending continuation. This was not a
   concurrent-writer or server-upgrade test.
7. **Grouped answers:** genuine group answers used slash-separated names,
   including a numeric answer encoded as a string. Group/repeat nesting
   and ambiguous-name refusal also have synthetic replay coverage; not
   every repeat or legacy form shape was exercised against the server.
8. **Authentication:** the `Token` authentication the pack declares has
   synthetic replay coverage; it was not re-run against the probe server.

The direct registration drill does not establish the separate Coordinator
workflow, automatic corrections, or approval authority for the ingestion
service. A service-initiated Proposal also needs a review policy compatible
with that actor: a policy requiring a human initiator refused a separate
fixture before task creation. Do not relax a production review policy merely
to copy the synthetic drill.

## Wide forms

The pack fixes the page at `limit=100` and the endpoint at 1 MiB
(`maximumResponseBytes: 1048576`). A form whose submissions average more than
about 10 KB (many questions, repeat groups, attachments, geolocation) makes a
full page exceed that bound. The send then fails with the same page on every
pass, and the position never moves. Neither the runtime nor the job can change
the pack's page size, and the runtime may only lower the response bound. The fix
is a pack of your own for that form, pinned in place of the maintained one:

1. Copy `pack.yaml` and its `scripts/` to a directory you own. Give the copy a
   new `id` (or `version`) so nobody mistakes it for the maintained pack.
2. In the copy, lower `limit` (for example to `"25"`), or raise the endpoint's
   `maximumResponseBytes` (the ceiling is 16 MiB, 16777216), or both. A lower
   `limit` also lowers the rescan cost per page.
3. If you raised `maximumResponseBytes`, raise `profile.maximumResponseBytes`
   and `profile.maximumPageBytes` in the job to match. The profile is never
   tighter than the endpoint. If you lowered `limit` alone, nothing else needs
   to change.
4. Recompute the pack digest: `shasum -a 256 pack.yaml`. Put it in
   `source.pack.digest` of your job file and in `pack.digest` of
   `project.yaml`. Update `id` or `version` in both places if you changed them.
5. Run `adapterctl job check` with your pack, as in
   `products/adapter/scripts/check-contracts.sh`. The check refuses a stale
   digest and names the field.

The maintained pack and its digest stay unchanged, so you can still compare
your copy with it.

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
