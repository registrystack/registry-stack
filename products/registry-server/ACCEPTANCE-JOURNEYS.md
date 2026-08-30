# Acceptance journeys

Registry Server must prove the same binary and compiler profile can serve five
configuration-defined domains: a non-person asset registry, household,
disability, farmer, and business registries. Their contract identifiers and
delivery state are in `contracts/acceptance-scenario-matrix.yaml`.

All five configuration projects pass the Production compiler and the same
real-PostgreSQL pilot test. That test loads their module source, rederives the
package, and executes configured behavior without domain-specific runtime
concepts.

The PublicSchema household project is intentionally richer than a single
stored-record smoke test. Its authored configuration adds person sex and a
local household number, declares selector profiles, exposes household-to-person
reads through group membership, and derives live demographic facts from a
reviewed module-relative SQL file. The demo seed includes a single-headed
household with a child under five, a woman-headed household with a child and
elderly member, and a separate control household to prove row/path isolation.

The non-person asset project also passes the public-binary adopter workflow.
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
