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

These files govern different resolved product graphs. Keep common license,
registry, and ban policy aligned where the product contract is the same, but
scope advisory exceptions and Git source allowances to dependencies actually
present in the graph governed by that file. Do not copy an exception or trusted
source into a product or template pre-emptively. Deliberate differences must be
documented in the changed file. The platform product policy and its published
template are byte-aligned by `products/platform/scripts/check-hygiene-alignment.sh`.

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

## Automated Update Window

Routine Dependabot updates are staggered on Wednesday between 04:00 and 11:30
UTC, with at most one open version-update pull request per ecosystem. This
keeps the dependency-update tool active without starting every update workflow
at once.

During an active release window, maintainers may cancel routine update runs
that compete with the release. Routine pull requests may be closed when they
are superseded or deliberately deferred. Reopen or recreate a deferred pull
request if it is later accepted; Dependabot may propose newer versions on later
runs. Do not pause security alerts, nightly security checks, CodeQL, secret
scanning, or OpenSSF Scorecard. Automated security-update pull requests are a
separate repository setting; when disabled, maintainers still triage visible
alerts through the normal security workflow.
