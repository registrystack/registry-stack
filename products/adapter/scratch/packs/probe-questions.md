# PACKS stream scratch: probe questions

The working list while authoring the kobotoolbox and odk-central packs.
The reviewed lists live in the pack READMEs; this scratch records the
notes and sources behind each question. Per CONCEPT 17.7, the packs are
unproved until a controlled deployment answers these.

## KoboToolbox

1. `_id` as the item key. Hypothesis. The Kobo docs state `_id` stays
   unchanged when a submission is edited
   (https://support.kobotoolbox.org/editing_and_deleting_data.html,
   "All other metadata fields remain unchanged, including `_id`"), and
   community threads treat it as the server row id
   (https://community.kobotoolbox.org/t/submission-id-and-uuid/6370).
   Probe: is `_id` unique and stable per submission within one asset on
   the deployment's server, across edits, deduplications, and server
   upgrades?
2. `_uuid` as the item revision. Hypothesis from the docs sentence "the
   `_uuid` value changes each time the submission is edited"
   (https://support.kobotoolbox.org/editing_and_deleting_data.html).
   Probe: does every submission carry `_uuid`, and does an edit always
   change it, on the deployment's server?
3. `meta/rootUuid` as the stable key. Hypothesis that it is present on
   every submission and equals the original `meta/instanceID`
   (https://support.kobotoolbox.org/viewing_validating_data.html and
   https://support.kobotoolbox.org/editing_and_deleting_data.html; the
   implementation discussion is kobotoolbox/kpi issue 3940,
   https://github.com/kobotoolbox/kpi/issues/3940). If the probe
   confirms presence and persistence, the pack should switch its key to
   `meta/rootUuid` and keep `_id` as a secondary. Probe: is
   `meta/rootUuid` present on all submissions (including legacy ones
   from before the field existed) and stable across edits?
4. Edit discovery. The REST Services page says data is pushed to
   external servers "only on creation. Nothing is sent when data is
   edited" (https://support.kobotoolbox.org/rest_services.html), so
   push integration cannot see edits; the pack polls instead. Probe:
   does an edited submission reappear in the `/data/` pages at a
   position the offset scan reaches again (Kobo orders by `_id`
   descending by default per the community thread
   https://community.kobotoolbox.org/t/kobo-api-get-last-submission-descending-order/44196),
   and do deletions ever surface to a poll-only consumer?
5. The 30,000-record bulk-read cap. Hypothesis from community posts
   about bulk reads refusing above 30,000 records; the number appears
   in the KoBoCAT source as `ParsedInstance.DEFAULT_LIMIT = 30000`
   (https://github.com/kobotoolbox/kpi shows the constant in
   kobo/apps/openrosa/apps/viewer/models/parsed_instance.py). The
   maintained v2 page maximum is a server setting
   (`MAX_API_PAGE_SIZE`, default 1000; `DEFAULT_API_PAGE_SIZE`, 100).
   Probe: does the deployment's server refuse or truncate reads above
   the bulk cap, and does the pack's fixed `limit=100` offset paging
   never trip it on real form sizes?
6. Offset-page shifts under concurrent submissions. Declared
   `key-deduplicated` recovery; not probed. Probe: how far do pages
   shift between two runs at the deployment's submission rate, and does
   the consumer's by-key deduplication hold the actual invariant?

## ODK Central

7. `__id` as the OData item key. Documented as the entity's key
   (`PropertyRef Name="__id"`), equal to the submission `instanceId`
   per the field-mapping table
   (https://docs.getodk.org/central-api-odata-endpoints/). Probe:
   confirm `__id` is the submission instance UUID, unique and stable,
   on the deployment's Central version.
8. `__system/updatedAt` as the item revision. The field table maps
   Central's `updatedAt` to `__system/updatedAt` (same page). Probe:
   does it change on every edit, and is it present on all entities?
9. `@odata.nextLink` and `$skiptoken` stability. Since Central v2023.4
   the nextLink carries a `$skiptoken` opaque cursor (same page).
   Probe: does replaying a nextLink after upstream inserts or edits
   re-read or skip rows in a way the key-deduplicated declaration
   covers, and does a skiptoken expire?
10. Repeat-table parent reference and ordinal. The OData page does not
    name the member by which a repeat entity references its parent
    submission; the pack sketch reads `__parent-id` and composes the
    key as parent plus row position, both flagged hypotheses. Probe:
    what is the actual parent-reference member of a repeat entity, is
    there a stable within-parent ordinal ("repeat index"), and if not,
    should the key fall back to the repeat row's own `__id`?
