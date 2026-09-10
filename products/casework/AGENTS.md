# Registry Casework product

This directory owns the Casework product contract, generated API description,
checkpoint examples, and product-local verification scripts. Read the workspace
`AGENTS.md`, this file, and `README.md` before changing the product.

- Treat `generated/registry-casework.openapi.json` as generated output. Change
  `scripts/generate_openapi.py`, then run it and its `--check` mode.
- Keep `contracts/security-invariant-matrix.yaml` and
  `contracts/security-test-traceability.yaml` scoped to implemented Casework
  behavior. A mapped test is not evidence that the test ran.
- Preserve the source-neutral boundary: the core and generic client do not
  depend on a source product, and BReg packages do not depend on Casework. Run
  `scripts/check_dependency_direction.py` after dependency changes.
- PostgreSQL verification requires the two separate disposable databases named
  in `README.md`. Never point either variable at retained operator data.
- Keep authored examples and the checkpoint demo small. Do not add later-wave
  clocks, automation, or a second source to close a documentation obligation.
