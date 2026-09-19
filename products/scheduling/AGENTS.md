# Registry Scheduling product

This directory owns the Scheduling product contract, generated API
description, checkpoint examples, and product-local verification scripts.
Read the workspace `AGENTS.md`, this file, and `README.md` before changing the
product.

- Treat `generated/registry-scheduling.openapi.json` as generated output.
  Change `scripts/generate_openapi.py`, then run it and its `--check` mode.
- Treat `generated/runtime/runtime.schema.json` the same way: it is derived
  from the strict `RuntimeConfig` types, and the regeneration command is in
  `RUNTIME-CONFIG.md`.
- Keep `contracts/security-invariant-matrix.yaml` and
  `contracts/security-test-traceability.yaml` scoped to implemented Scheduling
  behavior. A mapped test is not evidence that the test ran.
- Preserve the source-neutral boundary: no scheduling crate, directly or
  through any shared dependency, reaches a Base Registry Engine, Casework, or
  Evidence crate, and none of those products reach a scheduling crate. Run
  `scripts/check_dependency_direction.py` after dependency changes.
- Each directory under `examples/` is exactly what `schedulingctl init` writes
  for the template with the same name, and the checkpoint fails if either pair
  drifts apart. When `schedulingctl init` starts emitting or changing a file,
  copy that output into both applicable committed examples in the same commit.
- Keep authored examples and the checkpoint demo small. Do not add a
  later-wave surface to close a documentation obligation; record the exclusion
  instead.
- PostgreSQL verification requires a separate disposable database and the
  `postgres-test` feature. A test binary that skips because its database URL
  is absent is not database verification.
