# Registry Document Store product

This directory owns the Document Store deployment contract, generated schemas
and API description, authored examples, product contracts, and product-local
verification scripts. Read the workspace `AGENTS.md`, this file, and
`README.md` before changing the product.

The Document Store holds document bytes in custody for an owning system and
releases an exact, verified document version to a recipient a document grant
names. It owns its custody records, document grants, stored bytes, content
verification state, and audit journal. Why a document exists, who it concerns,
and whether a recipient is entitled to it stay with the owning system.

The product is held out of releases. The document routes (reserve, upload,
read, download) are compiled only into test builds, behind a synthetic actor;
the served runtime answers only `GET /health` until authentication lands. Do
not serve a document route without the authorization,
verification, and audit rules that govern it and the invariant rows in
`contracts/` that prove them.

- No Document Store crate reaches a BReg, Casework, Coordinator, Evidence,
  Messaging, or Scheduling crate, and no product crate or the
  `registry-stack-client` facade reaches the Document Store runtime or
  `documentsctl`. Products reach the Document Store over its public HTTP
  contract like any external caller.
- `registry-documents-core` depends on no other Document Store crate, and
  `registry-documents-client` never reaches the runtime. The client has no
  Node.js or Python binding yet and is not part of the unified packages; follow
  `crates/CLIENTS.md` before changing its surface.
- `scripts/check_dependency_direction.py` enforces both directions on the
  whole forward closure with every feature enabled. Run the gate and its tests
  after any dependency change.
- PostgreSQL suites are opt-in behind the `postgres-test` feature, and
  `scripts/check_database_test_isolation.py` refuses a suite that would run
  under default Cargo resolution. A suite skipped for a missing database URL
  is not database verification; the suites fail instead of skipping.
- Treat everything under `generated/` as generated output. The schemas and
  the OpenAPI document come from the generators `README.md` names, and the
  `schema` feature's drift test, run by `scripts/check-checkpoint.sh`, fails
  when any of them drifts.
- `contracts/` is the security review baseline. A change that weakens an
  invariant row rewrites it in the same commit, and `scripts/check-contracts.sh`
  holds every cited test to its runner.
- Changes to authentication, authorization, content verification, audit, data
  minimization, retention, or erasure are security-sensitive and need explicit
  review notes in `SECURITY-REVIEW-NOTES.md`.
