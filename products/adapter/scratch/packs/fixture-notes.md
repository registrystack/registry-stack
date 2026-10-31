# PACKS stream scratch: fixture notes

Shapes the fixtures pin, and why each synthetic value looks the way it
does. All names, uids, hosts, and timestamps are synthetic.

## kobotoolbox fixtures (packs/kobotoolbox/fixtures/)

Five suites, one entry each:

- page-one: cursor absent (first run). Request GET / with
  `format=json&limit=100&start=0`. Reply a full page: 100 submissions,
  `count: 260`, `next` a synthetic URL string (the route never reads
  it). Expected page: 100 items, `next: {offset: 100}`.
- page-two: cursor `{offset: 100}`. Same request with `start=100`.
  Full page again, `count: 260`. Expected: 100 items, `next:
  {offset: 200}`.
- page-short: cursor `{offset: 200}`. 60 submissions. Expected: 60
  items, no `next`.
- page-empty: cursor `{offset: 200}` in its own deployment state, a
  form whose total (200) is a multiple of the page size, so the
  second full page ended the data exactly and this run reads offset
  200 into an empty page. Empty `results`. Expected: empty items, no
  `next`.
- unauthorized: cursor absent. Reply 401 with a synthetic JSON error
  body. Expected: the `credential.rejected` class (engine-raised by
  the auth plan; no route clause).

Submission objects carry the documented Kobo metadata members plus
synthetic household-survey answers: `_id` (integer), `_uuid`,
`meta/instanceID`, `meta/rootUuid`, `formhub/uuid`, `_submission_time`,
`_tags: []`, `_notes: []`, `_version_`, `_status`, `_submitted_by`,
`_geolocation: []`, and answers (`respondent_name` "Fixture One" style,
`household_size`, `has_water`). page-one includes one submission with
a `_validation_status` object to pin the passthrough rule: it may
appear only inside `value` and no step reads it.

## odk-central fixtures (packs/odk-central/fixtures/)

Six suites, one entry each:

- submissions-page-one: cursor absent. Request GET / with
  `%24count=true&%24top=100` (the engine percent-encodes query keys,
  so the recorded wire form carries `%24`). Reply a full OData page:
  100 entities under `value`, `@odata.count: 172`,
  `@odata.nextLink` carrying a synthetic `$skiptoken`. Expected: 100
  items, `next: {nextLink: ...}`.
- submissions-page-two: cursor `{nextLink: ...}`. Request made through
  the pinned link: GET, path the entity-set base path, query
  `%24skiptoken=fixture-skip-token`. Full page again. Expected: 100
  items, `next: {nextLink: ...}`.
- submissions-page-short: 22 entities, no `@odata.nextLink`. Expected:
  22 items, no `next`.
- submissions-empty: empty `value`, no `@odata.nextLink`. Expected:
  empty items, no `next`.
- submissions-unauthorized: reply 401 (Central answers 401 without a
  `WWW-Authenticate` challenge per its auth docs). Expected:
  `credential.rejected`.
- repeats-page: the `odk-repeats` sketch. Cursor `{offset: 0}` on a
  repeat entity set. Reply a short page of 3 repeat entities, each
  carrying `__id`, the hypothesized `__parent-id`, `__system/updatedAt`
  on one row (one row omits it to pin revision-optional), and synthetic
  repeat answers. Expected: 3 items keyed `<parent>/<index>`.

Submission entities carry `__id`, `meta` (ComplexType with
`instanceID`), `__system` (`submitterId`, `submissionDate`,
`updatedAt`, `reviewState`), and synthetic form answers.

## Why recorded bodies are full pages

The first three suites share one synthetic deployment (260
submissions, newest first, ids 260..1); the empty suite is its own
deployment state (total 200, an exact page-size multiple). The
fixtures carry full 100-object pages, generated deterministically by
`gen-kobo-fixtures.py` and `gen-odk-fixtures.py` in this directory;
regenerate only with a pack change, and keep the expected pages in
lockstep.
