# OpenCRVS event-search source recipe

This recipe represents the sanitized OpenCRVS v2 Event Search contract already
exercised by Registry Stack's reference adapter. It prepares an exact registered
birth-event search by tracking ID, limits the result to two records so ambiguity
is observable, validates the returned event type and status, and extracts the
configured complete parent-reference set plus the returned record identity.

The checked pack route receives only the minimized authorized `tracking_id` and
uses it to prepare the fixed search. A unique response becomes a match only when
its `trackingId` has the same scalar type and exact value. Missing, wrongly
typed, or different returned identity is a source protocol error before facts,
assertion derivation, or signing. Business derivations do not need to repeat
this reusable source-identity check.

It assumes the selected OpenCRVS deployment supports:

- `POST /events/search` with the pinned `and` query, exact status and tracking-ID
  clauses, limit, and offset;
- the pinned EventIndex result shape with `total`, `results`, `type`, `status`,
  `trackingId`, and the configured declaration fields;
- a deployment agreement that the configured parent-reference fields form a
  complete set for this assertion and that an absent configured field means no
  registered parent in that position.

OpenCRVS event declarations are deployment-configured. These assumptions are
therefore narrower than OpenCRVS compatibility in general. Review the exact
deployment and version, its configured fields, and the source authority before
use. The export contains no server origin, token endpoint, client ID, or client
secret. Bind them in the target-owned `connections` entry.

The `fixture-validation/` project is the seed used by the maintained integration
gate. The gate imports the exact pack closure, then adds the separately reviewed
synthetic assertion definition and checks the assembled project, because a source
export must never supply assertion meaning. Its sealed replay cases cover success, no match,
ambiguity, an event-type protocol mismatch, and returned tracking-ID value and
scalar-type mismatches.
Run it from the Registry Stack source tree or the downloaded catalog with
matching installed binaries:

```sh
bash ../run-fixtures.sh
```
