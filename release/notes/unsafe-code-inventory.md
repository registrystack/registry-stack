# Unsafe-Code Inventory

Issue: [#202](https://github.com/registrystack/registry-stack/issues/202)

Generated: 2026-07-09

This is the release-readiness inventory for first-party unsafe Rust in the
Registry Stack workspace. It records where first-party release crates do not
inherit the workspace `unsafe_code = "forbid"` lint, what unsafe surface remains,
and the review status for 1.0.

## Method

- Reviewed the workspace root lint policy:
  `Cargo.toml` sets `[workspace.lints.rust] unsafe_code = "forbid"`.
- Scanned workspace member manifests under `crates/` plus
  `products/notary/xtask` for `[lints] workspace = true` and explicit
  `not opted into [workspace.lints]` annotations.
- Scanned the opt-out crates with `rg -n "unsafe\\s*\\{|unsafe fn|unsafe extern"`.
- Ran `cargo geiger` 0.13.0 as a cross-check. The tool cannot report directly
  from the virtual workspace manifest, so direct package scans were used to
  confirm the source-level findings below.

The excluded fuzz harness manifests under `products/*/fuzz` are separate
`cargo-fuzz` workspaces and are not release crates.

## Current Inventory

Current scan result: four first-party workspace crates are intentionally not
opted into `[workspace.lints]`. The older issue comment that mentioned five
opt-out crates is stale for the current tree; `crates/registry-relay/Cargo.toml`
now opts into workspace lints.

### `registry-manifest-cli`

Reason: local libyaml FFI for the YAML alias and anchor prepass.

Unsafe surface:

- `crates/registry-manifest-cli/src/lib.rs:27`
  initializes and drives the libyaml parser over an input string.
- `crates/registry-manifest-cli/src/lib.rs:92` releases parser state through
  `ParserGuard`.
- `crates/registry-manifest-cli/src/lib.rs:98` reads libyaml parser error
  details through raw pointers.

Review notes:

- The unsafe code is isolated to the CLI YAML prepass.
- The parser input borrows the original `raw` string for the lifetime of the
  parser guard.
- The guard owns libyaml teardown after successful parser initialization.
- This remains an FFI boundary and should stay localized.

1.0 status: accepted with the existing safety comments and tests that exercise
alias and anchor rejection.

### `registry-notary`

Reason: unsafe `std::env::set_var` and `std::env::remove_var` calls in
`#[cfg(test)]` code.

Unsafe surface:

- `crates/registry-notary/src/doctor/tests.rs:403`
- `crates/registry-notary/src/doctor/tests.rs:424`
- `crates/registry-notary/src/doctor/tests.rs:435`
- `crates/registry-notary/src/doctor/tests.rs:455`
- `crates/registry-notary/src/doctor/tests.rs:466`
- `crates/registry-notary/src/doctor/tests.rs:488`

Review notes:

- The unsafe calls are test-only environment mutation for JWK diagnostics.
- No runtime unsafe surface was found in this crate outside test code.
- Future cleanup should move these tests behind a serialized environment helper
  or a config injection path so the crate can inherit workspace lints.

1.0 status: accepted as test-only unsafe.

### `registry-notary-server`

Reason: unsafe `std::env::set_var` and `std::env::remove_var` calls in
`#[cfg(test)]` code.

Unsafe surface:

- `crates/registry-notary-server/src/standalone/tests/signing.inc:455`
- `crates/registry-notary-server/src/standalone/tests/signing.inc:546`
- `crates/registry-notary-server/src/standalone/tests/signing.inc:581`
- `crates/registry-notary-server/src/standalone/tests/signing.inc:658`
- `crates/registry-notary-server/src/standalone/tests/signing.inc:767`
- `crates/registry-notary-server/tests/deployment_gates_test.rs:34`
- `crates/registry-notary-server/tests/deployment_gates_test.rs:365`
- `crates/registry-notary-server/tests/deployment_gates_test.rs:383`
- `crates/registry-notary-server/tests/demo_config.rs:29`
- `crates/registry-notary-server/tests/demo_config.rs:66`
- `crates/registry-notary-server/tests/demo_config.rs:125`
- `crates/registry-notary-server/tests/demo_config.rs:183`
- `crates/registry-notary-server/tests/demo_config.rs:306`
- `crates/registry-notary-server/tests/demo_config.rs:408`
- `crates/registry-notary-server/tests/demo_config.rs:475`
- `crates/registry-notary-server/tests/decentralized_cross_source_cel.rs:248`
- `crates/registry-notary-server/tests/decentralized_cross_source_cel.rs:391`

Review notes:

- The unsafe calls are test-only environment mutation for deployment gates,
  demo config loading, CEL worker setup, and PKCS#11 or key diagnostics.
- No runtime unsafe surface was found in this crate outside test code.
- Future cleanup should reduce process-wide environment mutation in tests.

1.0 status: accepted as test-only unsafe.

### `registry-notary-worker-harness`

Reason: Unix process isolation uses `pre_exec`, `setrlimit`, process-group kill,
and a minimal `kill(2)` FFI declaration.

Unsafe surface:

- `crates/registry-notary-worker-harness/src/lib.rs:742` installs the Unix
  `pre_exec` hook.
- `crates/registry-notary-worker-harness/src/lib.rs:981` calls
  `libc::setrlimit`.
- `crates/registry-notary-worker-harness/src/lib.rs:1001` kills the worker
  process group on shutdown.
- `crates/registry-notary-worker-harness/src/lib.rs:1017` declares the Unix
  `kill(2)` FFI.

Review notes:

- This unsafe code is runtime code, but it is the intended isolation boundary
  for the hardened worker process pool.
- The worker command runs with a minimal environment and optional memory limits.
- The unsafe surface is Unix-specific and localized to the harness crate.

1.0 status: accepted for the worker isolation boundary.

## Review Decision

No new unsafe code is introduced by this inventory. For 1.0, the accepted
first-party unsafe surface is:

- localized libyaml FFI in `registry-manifest-cli`;
- test-only environment mutation in `registry-notary`;
- test-only environment mutation in `registry-notary-server`;
- Unix process-control FFI in `registry-notary-worker-harness`.

Any new first-party unsafe code must either inherit the workspace lint and fail
review, or update this inventory with maintainer rationale before release.
