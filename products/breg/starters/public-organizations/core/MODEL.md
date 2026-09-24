# Fixed model and policy

This is a synthetic local learning profile. All access is authenticated and
restricted to the declared profiles. Browser previews never authorize local
requests. The registry-wide permissions and historical reads are explicit policy:
there are no hidden jurisdiction or ownership row filters. An institution must
review these boundaries before production deployment.

## Actors and operations

| Actor | Ordinary records | Correction requests |
| --- | --- | --- |
| Reader | Get and list accepted records, including references | No access |
| Editor | Create, get, list and inspect history; PATCH only where the entity is not controlled | Create and edit own drafts; submit, revise or cancel own requests |
| Maintainer | Get, list and inspect history | Read proposed fields and external review status; apply an exactly approved proposal |

Every operation absent from the authored permissions is denied, including deletion.
The full PATCH operation on PublicOrganization and InstitutionalRelationship is controlled. The correction changes
only `name`; it cannot change identity or holder/link endpoints. A maintainer is
the authorized source applier. Registry Casework independently owns reviewer
eligibility and separation from the submitter. External approval leaves the target unchanged.
Application uses the native frozen effect and expected target revision. A stale
target requires the native revision/rebase and review path.

Reasons and supporting references live in correction records, restricted to
maintainers. They are bounded synthetic text, not uploaded evidence or proof of
legal authority. Historical access includes old values of readable fields.

## References, identity and dates

BReg assigns the record UUID. `localIdentifier` is a unique, bounded local key
within each concrete entity, not a national identifier. It is this profile's
minimal representation of an Identifier, not the complete PublicSchema
multivalued `identifiers` structure. Class concept IRIs describe types; they are
never used as instance IDs. Importers must map external instance IRIs to the
correct concrete entity and returned UUID before writing references. Name
matching is not identity resolution.

Every endpoint is a native reference to one declared entity, with restricted
reference deletion. Missing and wrong-type targets are refused. No independently
editable inverse list duplicates the forward endpoints. All supplied dates are
native calendar dates. Both-known date pairs enforce start <= end, including
an equal-date assertion. Missing dates remain unknown; dates do not establish
currentness, exclusivity or non-overlap. Examples use the fixed date 2026-01-01.

The sample identifiers start `SYNTHETIC-`; `MY-FIRST-001` belongs only to the
independent first-record exercise. That exercise requires no sample references.
Edit `examples/inputs/first-record.json` before its first run. Native retained
state binds exact input bytes and captured UUIDs to each attempt.

## Semantic scope

PublicOrganization inherits Organization, without asserting separate legal
personality. The optional `description` field is a bounded free-text summary,
aligned to `description`; PublicSchema's coded `public_functions` has no field
in this starter. InstitutionalRelationship has typed source and
target organizations. Its profile code `reports-to` belongs to the declared
`https://public-organizations.example.org/relationship-types` scheme, directed
from a district office to its department. It is not a universal PublicSchema
enum and imposes neither one parent nor graph-cycle checking.

Relationship updates use the distinct `relationship-correction` request, which
reviews endpoint, classification and start-date changes while preserving the
existing optional end date. This fixed correction does not expose end-date
edits; those require another explicitly reviewed request definition. Creating or
correcting directory records does not create, merge, abolish or legally
reorganize an institution. The samples are the fictional Department of
Community Services and River and Hill District Offices.

## Attribution and adoption

The model maps selected fields and native references to PublicSchema draft
concepts at commit `e5cfbbc0161e4d2c802d1acd752ec193253f7820`, under CC BY 4.0.
See `PUBLICSCHEMA-LICENSE.txt` and the pinned source in `starter-template.json`.
The local key representation, permissions, review policy, reference target
narrowing and validation rules are Registry Stack starter decisions. Local
institutional and domain review remains necessary before adopting this profile.
