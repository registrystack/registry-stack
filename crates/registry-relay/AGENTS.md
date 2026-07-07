# registry-relay Agent Notes

Follow the workspace guidance in `../AGENTS.md` first. These notes add
repo-specific CI discipline for Registry Relay.

## CI Preflight

Before opening or updating a PR that changes Rust code, Cargo features,
`Cargo.toml`, `Cargo.lock`, Dockerfiles, root GitHub workflows, or perf config:

- Run `just ci-preflight`.
- The preflight runs from the registry-stack monorepo root and uses the root
  workspace lockfile.
- If changing path dependencies or feature flags, regenerate and commit
  `Cargo.lock` when the locked graph changes.
- If the preflight cannot be run, say exactly why in the handoff or PR notes.

This preflight exists to catch lockfile drift before the heavyweight Docker,
perf, and security jobs fail on first push.
