# Acceptance journeys

Registry Server proves that the same binary and compiler profile serve five
configuration projects. Their contract identifiers and delivery state are in
`contracts/acceptance-scenario-matrix.yaml`.

| Project | Example | Coverage |
| --- | --- | --- |
| `business-establishments` | Businesses, establishments, and operating assignments | Dated relationships, exact selectors, related reads, derived counts, claim-bound access, and the local webhook demo |
| `business` | Legal entities, filings, and officer appointments | Registration identifiers, public and protected projections, create-only filings, and effective time |
| `facility` | Environmental facilities, permits, installations, and discharge reports | Coordinates, quantities and units, administrative row boundaries, and resumable imports |
| `inspection` | Public authorities, facility inspections, observations, and permit records | Protected structured metadata, bounded finding grades, create-only records, and corrections retaining the original effective period |
| `asset-site-placement` | Equipment assigned to sites | Non-overlapping placements and an additive signed upgrade with unchanged server bytes |

All five pass the Production compiler and the same real-PostgreSQL pilot test.
The test loads their module source, rederives the package, and executes configured
behavior without domain-specific runtime concepts.

The business-establishments demo creates North Quay Engineering, Central
Fabrication, and South Harbour Logistics, with eight establishments in total.
Central has a suspended depot; South Harbour supplies separate control records
for row and relationship isolation. The live summary counts establishments by
role, kind, and operating status using only currently effective assignments.
An operator can query the whole registry. A separate viewer is bound by verified
claims to one business and cannot list businesses or traverse their establishments.

Permit records reference their issuing public authority. A correction appends a new
record for the original effective period and retains the prior record unchanged. The
application chooses the applicable correction; the example does not mark old records
inactive automatically.

The local concept URIs are synthetic mappings, not an external-standard conformance
claim. These fixtures record registration and permit facts; they do not implement
incorporation, inspection case management, or permit approval workflows.

The asset project also passes the public-binary adopter workflow.
That workflow builds the two executables once, tests a candidate in an isolated
database, packages it for external signing, proves that an author without the
migration secret cannot initialize production state, applies it with the
operator role, and performs authenticated data access through a static JWKS.
It then adds one optional restricted field by configuration, tests and signs
the successor in a second isolated database, records a deliberately blocked
migration as durable failed maintenance, applies the exact fix-forward package,
and restarts the byte-identical server binary. The original data survives and
the restricted field remains outside the selected response projection.

The machine-readable matrix binds each journey to its exact executable proof.
Compiler-only evidence is not used to claim the unchanged-binary upgrade or
the author-versus-production authority boundary.
