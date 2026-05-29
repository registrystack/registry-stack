# registry-lab Guidance

This repository owns the registry-lab demo orchestration only:
Compose, fixtures, static metadata config, walkthrough scripts, smoke checks,
and demo-owned Dockerfiles.

- Keep Registry Relay and Registry Notary product code in their source
  repositories and update the `vendor/` submodule pins after those changes are
  committed.
- Use `REGISTRY_RELAY_SOURCE_DIR` and `REGISTRY_NOTARY_SOURCE_DIR` to verify
  against sibling checkouts while source changes are still local.
- Do not commit `.env`, `output/*`, or generated `static-metadata/*` files.
- Use `uv` for Python script dependency workflows.
- Before calling the demo complete, run fixture generation, secret generation,
  static metadata publication, Compose build, smoke, and the narrated demo
  client, or run `scripts/release-check.sh`.
