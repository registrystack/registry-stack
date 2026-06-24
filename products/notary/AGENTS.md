# registry-notary Agent Notes

Follow the workspace guidance in `../AGENTS.md` first. These notes add
repo-specific CI discipline for Registry Notary.

## CI Preflight

Before opening or updating a PR that changes Rust code, Cargo features,
`Cargo.toml`, `Cargo.lock`, Dockerfiles, GitHub workflows, perf config, or
companion repository refs:

- Run `just ci-preflight`.
- Do not rely on ambient local sibling checkouts. CI uses the pinned
  `REGISTRY_PLATFORM_REF` and `CROSSWALK_REF` values from the workflows.
- If changing `REGISTRY_PLATFORM_REF`, `CROSSWALK_REF`, path dependencies, or
  feature flags, regenerate and commit `Cargo.lock` against those exact refs.
- If the preflight cannot be run, say exactly why in the handoff or PR notes.

This preflight exists to catch lockfile drift and companion-repo pin skew before
the heavyweight Docker, perf, and security jobs fail on first push.
