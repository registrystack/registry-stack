# Registry Casework product

This directory owns the Casework product contract, generated API description,
canonical examples, and product-local verification scripts. Read the workspace
`AGENTS.md`, this file, and `README.md` before changing the product.

- Treat `generated/registry-casework.openapi.json` as generated output. Change
  `scripts/generate_openapi.py`, then run it and its `--check` mode.
- Keep `contracts/security-invariant-matrix.yaml` and
  `contracts/security-test-traceability.yaml` scoped to implemented Casework
  behavior. A mapped test is not evidence that the test ran.
- Preserve the source-neutral boundary: the core and generic client do not
  depend on a source product, and BReg packages do not depend on Casework. Run
  `scripts/check_dependency_direction.py` after dependency changes.
  Only `registry-caseworkctl` adopter tests may reach the Coordinator client
  through the unified client facade. Normal and build dependencies retain the
  independent product boundary; this exception permits no Coordinator runtime.
- Use explicitly disposable PostgreSQL databases. Current review, activation,
  and assignment suites accept `CASEWORK_REVIEW_TEST_DATABASE_URL`,
  `CASEWORK_ACTIVATION_TEST_DATABASE_URL`, and
  `CASEWORK_ASSIGNMENT_TEST_DATABASE_URL`; fixtures isolate themselves in
  unique schemas. The native BReg journey also uses `BREG_TEST_DATABASE_URL`.
  The separate `caseworkctl` split-role session test uses
  `CASEWORK_TEST_DATABASE_URL`.
  Never point test URLs at retained operator data.
- Keep the submitted and current-source examples small and executable. Preserve
  exact policy and provider bindings, reviewer disclosure, independent producer
  apply authority, and meaningful review and staffing proof when editing them.
