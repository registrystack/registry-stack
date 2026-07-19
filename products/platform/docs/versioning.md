# Platform versioning in the Registry Stack monorepo

The `registry-platform-*` crates and `registry-config-report` are workspace
members of Registry Stack. They share the version in the root `Cargo.toml`, are
verified from the root, and are released with the Registry Stack source tree.
There is no separate platform workspace tag or consumer pin to coordinate
inside this repository.

## Release policy

- Workspace release tags use the Registry Stack release version.
- All published platform crates use the root `[workspace.package]` version.
- A release candidate is not promoted until the active root workflows are
  green for formatting, normal workspace checks, platform all-feature checks,
  platform line coverage, dependency policy, secret scanning, hygiene
  alignment, and the relevant fuzz smoke.
- Before 1.0, minor releases may include documented breaking API or config
  changes. Patch releases remain compatible with the latest minor line.
- Backports to an older minor line require an explicitly opened backport lane.

Platform-owned signing and verification supports the algorithms documented in
the public Registry Stack security and compatibility specifications. OIDC JWT
verification remains a separate caller-configurable trust surface, and callers
must use an explicit algorithm allowlist.

## Release checks

Run from the monorepo root:

```sh
cargo fmt --check
cargo build --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features
cargo clippy --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features -- -D warnings
cargo test --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features
cargo llvm-cov --locked -p registry-config-report -p 'registry-platform-*' --all-features --fail-under-lines 80
cargo deny check
products/platform/scripts/check-hygiene-alignment.sh
products/platform/scripts/audit-configs.sh --check --format paths
gitleaks dir --config .gitleaks.toml --no-banner --redact --timeout 120 .
```

CI pins the non-Rust tools and verifies the same commands. The nightly workflow
runs the longer fuzz campaign; pull requests that affect the platform surface
run a bounded 60-second smoke for each platform fuzz target.
