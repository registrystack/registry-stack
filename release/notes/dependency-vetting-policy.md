# Dependency Vetting Policy

Issue: [#202](https://github.com/registrystack/registry-stack/issues/202)

This policy applies to new and changed first-party release dependencies in
Registry Stack, including Rust crates, npm packages used by the docs site, Git
dependencies, release tooling, and pinned external source inputs.

## Review Requirements

Before adding or materially changing a dependency, reviewers should record:

- the product or crate that needs it;
- the feature or bug that cannot reasonably be handled with existing code;
- whether the dependency is runtime, build-time, test-only, docs-only, or
  release-tooling only;
- the source, such as crates.io, npm, GitHub release, or a pinned Git commit;
- license compatibility with the repository license and release artifacts;
- maintenance health, including recent releases, issue activity, ownership, and
  whether the project is archived;
- default features and optional features enabled by Registry Stack;
- transitive dependency impact from the lockfile or package lockfile;
- security posture, including `cargo deny check`, npm audit output where
  applicable, Dependabot, CodeQL, and OpenSSF Scorecard signals;
- any accepted risk with a scoped rationale and review trigger.

Security-sensitive dependencies include auth, crypto, signing, credential
issuance, policy evaluation, audit integrity, release provenance, source
connectors, and parsers that process untrusted input. Prefer maintained
libraries with clear ownership and no unresolved unsoundness or memory-safety
advisory in the code path used by Registry Stack.

## Advisory Handling

New advisories should be handled by upgrading, replacing, feature-gating, or
removing the dependency. If no fix exists and release risk is accepted, the
ignore must be scoped in the relevant `deny.toml` file with:

- the advisory ID;
- the affected dependency and reachable product area;
- the reason the current release accepts the risk;
- the trigger for removing or re-reviewing the ignore.

The repository currently carries five `deny.toml` files:

- `deny.toml`;
- `crates/registry-relay/deny.toml`;
- `products/platform/deny.toml`;
- `products/platform/templates/deny.toml`;
- `products/manifest/deny.toml`.

Keep duplicated policy entries synchronized unless the divergence is deliberate
and documented in the changed file.

## Git Dependencies

Git dependencies are allowed only when a registry release is not adequate for
the required surface. They must be pinned to an immutable commit, allowed in
`deny.toml`, and documented with:

- upstream repository;
- pinned commit;
- product surface that uses it;
- reason a registry release is not used;
- review trigger;
- files that must be updated together when the pin changes.

Do not bump a Git pin casually. Bumps require a coordinated pull request that
updates the workspace dependency declaration, lockfile, release manifests where
applicable, release notes, and any source allow-list rationale.

## Verification

For dependency changes, run the narrowest relevant command set and report any
skipped command:

```bash
cargo metadata --locked --format-version 1
cargo deny check
cargo test --locked --workspace
```

For release-tooling or docs-site dependency changes, also run the relevant
Python or npm checks documented in `CONTRIBUTING.md`.

## Release Review

Before a 1.0 or stable release, maintainers should review:

- every advisory ignore;
- every `[sources]` Git allow-list entry;
- every first-party crate that does not inherit workspace lints;
- the Crosswalk pin rationale in `external/README.md`;
- release workflow pins for Syft, Grype, cosign, checkout, upload/download
  actions, and the Rust builder image.

## Automated Update And Release Windows

Routine Dependabot version updates enter the repository during a fixed weekly
maintenance window on Wednesday from 04:00 through 12:00 UTC. Ecosystems are
staggered within that window so their pull requests do not all compete for the
shared Linux runners at once. The schedule controls when Dependabot starts its
checks; it does not guarantee when pull-request CI will finish.

An active release window is lifecycle-based, not calendar-based. It opens when
a maintainer designates a release candidate for preparation or promotion and
closes after clean-environment publication verification succeeds or the
release is put on a recorded hold. During that window, maintainers should not
rebase, merge, manually trigger, or retry routine version-update pull requests.
Queued or running routine version-update CI may be canceled when it competes
with the active release, after confirming that the pull request is not linked
to a security update. Keep viable pull requests open and rerun them after the
window closes.

This policy never pauses Dependabot alerts or security updates, nightly
security checks, CodeQL, secret scanning, or OpenSSF Scorecard. Security work
may preempt routine updates and may hold a release. The configured
`open-pull-requests-limit` applies to routine version updates; GitHub manages
security-update pull requests separately. Do not add a `target-branch`, ignore
rule, or committed zero-limit pause as a release shortcut.

The machine-readable schedule contract is checked with the same command
locally and in CI:

```bash
python3 release/scripts/check-dependabot-release-window.py
```
