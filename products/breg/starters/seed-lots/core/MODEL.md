# Seed lots: fixed model and policy

This is a small authenticated register of physical seed lots maintained by a
fictional custodian. It is a single-variety teaching profile of the draft
PublicSchema SeedLot concept. A lot's physical identity differs from its number,
its variety and any accession. Recording or correcting a lot does not certify
material, establish varietal purity, grant marketing permission or prove stock
availability.

## Fixed records and quantities

| Record | Fixed fields and meaning |
| --- | --- |
| Seed lot | Required stable `localIdentifier`, required `lotNumber`, required `quantityKg`; optional `producedOn`, typed `variety` and typed `sourceLot` |
| Plant variety | A minimal synthetic local identity with `localIdentifier` and `varietyDenomination` |
| Lot-number correction | Lot reference, proposed `lotNumber`, reason and supporting reference; a fixed reviewed effect changes only the lot number |

BReg returns a UUID for each record. The custodian's `localIdentifier` is unique
and remains unchanged by the supplied correction. `lotNumber` is separately
unique in the fixed custodian namespace
`https://seed-lots.example.org/lot-number-scheme`. It is a bounded single local
representation of PublicSchema `seed_lot_identifiers`, not an implementation of
all multivalued Identifier fields or an internationally unique lot number.

`quantityKg` is an exact decimal with at most 12 digits and three fractional
digits, always in kilograms, from 0 through 999999999.999. This profile is a
single-unit representation of `seed_lot_quantity`, whose PublicSchema range is
QuantityValue. A quantity describes the lot at recording time; it is not an
inventory balance, present availability, conservation equation or evidence of
certification. Zero is allowed without inferring disposal or other status.
Numbers are JSON decimal strings; the native schema rejects negative and
out-of-range values. `producedOn` is an optional complete native calendar date.
Unknown production dates stay absent. Samples use January 2026 dates.

## References and reuse

`variety` is a native reference to exactly PlantVariety. This profile narrows
the draft's multivalued `seed_lot_varieties` to one optional known variety.
Absence does not imply varietal purity. `sourceLot` is a native reference to
another SeedLot and narrows `source_seed_lots` to one optional source. It says
nothing about mixture proportions, certified blend status or quantity balance.
The source records remain distinct from the derived lot. Native references
refuse missing and wrong-type targets; deletion is restricted. This small model
does not validate a provenance graph or prevent cycles.

The two local variety records are explicitly synthetic identities used to make
the example portable and its reference checks executable. They are not a new
authoritative variety register or copies of a national catalogue. Before using
real varieties, choose the owning authority and preserve registry-qualified
source identity. Map that identity explicitly to a locally held reference record
or adopt an external-reference profile. Do not resolve varieties by denomination
alone, fabricate external IDs or silently duplicate another registry's master.
The minimal records here carry no breeder rights or listing approvals.

The earlier research included producer/operator, seed classes, certifications,
mixtures and test reports. These are excluded from this core. In particular,
the pinned PublicSchema SeedLot declares no producer/operator property, so this
starter does not invent one. Broader blends, multiple varieties/accessions,
quantities with other units, certification schemes and laboratory results need
a separately reviewed profile. No certificate, test-report or regulatory status
is manufactured by registration.

## Actors and reviewed correction

| Actor | Seed lots | Synthetic variety identities | Correction requests |
| --- | --- | --- | --- |
| Reader | Get and list | Get and list | No access |
| Editor | Create, get, list and inspect history; no direct PATCH | Create, get, list, PATCH and inspect history | Create/edit own drafts; submit, revise and cancel own requests |
| Reviewer | Get, list and inspect history | Get, list and inspect history | Read proposals and target fields; approve, reject, request revision and apply |

All records are restricted to authenticated callers. Grants cover this local
registry, with no hidden jurisdiction/ownership filter. Every omitted operation
is denied, including deletion. History exposes previous values of fields the
maintainer can read. Reasons and supporting references remain in correction
records, unavailable to readers. Portable metadata describes the selected model
and grants no runtime record access.

The complete SeedLot PATCH operation requires review. The teaching request
corrects a transcribed lot number while preserving UUID, local identifier,
quantity, dates and references. A reviewer distinct from the submitting
principal approves or rejects it. Approval alone changes no lot. The reviewer
also has the explicit application grant and applies the native frozen effect
against the captured target revision. Stale state requires the native
revise/rebase and review path, never an implicit overwrite.

## Synthetic exercises and adoption

Explicit sample population creates two fictional varieties, an original lot,
a derived lot with both variety and source references, and a lot of another
variety. Sample IDs begin `SYNTHETIC-`. The first-record exercise instead creates
`MY-FIRST-LOT-001` with no references and works with an empty registry. Its lot
number changes from `LOT-2026-010` to `LOT-2026-100` after the separate review
and application steps. That is a transcription correction under example policy,
not a claim that real lot identifiers may always be reassigned.

Ordinary schema-test journeys exercise approval, application, rejection,
nonnegative quantity and date rules. The separate security journey additionally
checks missing scopes and a foreign reviewer action precondition. Native HTTP
regressions prove typed-reference refusals and independently authorized review.
Presence of these artifacts is not an execution receipt for an edited project.

The vocabulary is pinned to PublicSchema draft commit
`1ea9ce333918693b29aec31068fac412e02cb8dc`. See `ATTRIBUTION.md` and
`PUBLICSCHEMA-LICENSE.txt`. These cardinalities, permissions, local numbering and
unit decisions are starter policy, not universal PublicSchema requirements.
