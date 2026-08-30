# Acceptance journeys

Registry Server must prove the same binary and compiler profile can serve five
configuration-defined domains: a non-person asset registry, household,
disability, farmer, and business registries. Their contract identifiers and
delivery state are in `contracts/acceptance-scenario-matrix.yaml`.

All five configuration projects pass the Production compiler and the same
real-PostgreSQL pilot test. That test loads their locked module digests and
executes configured behavior without domain-specific runtime concepts.

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
