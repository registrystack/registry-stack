# Versioning

`registry-platform` is released as one workspace tag and consumed by Registry Relay and Registry Witness through that tag.

## Tag Policy

- Tags use `vMAJOR.MINOR.PATCH`.
- Initial release target: `v0.1.0`.
- Consumers pin git tags, not branches.
- All crates in this workspace share the same version in `[workspace.package]`.
- A tag is not cut until CI is green for format, clippy, build, tests, dependency policy, and hygiene checks.

## Semver Before 1.0

Before `v1.0.0`, minor bumps may contain breaking API or config changes. Patch bumps must be backward compatible for the latest minor line.

Examples:

- `v0.1.1` can fix `FetchUrlPolicy` behavior without changing public signatures.
- `v0.2.0` can change a public type or consumer config migration requirement.
- Backports to an older minor line happen only when Jeremi explicitly opens a backport lane.

## v0.1.0 Algorithm Scope

Platform-owned signing and verification supports EdDSA with Ed25519 JWKs. ES256,
RS256, PS256, and other JWK algorithms are intentionally rejected as unsupported
until a production consumer needs them. This keeps the first tag narrow while
making unsupported algorithms fail closed instead of silently falling back.

## Consumer Alignment

Relay and Witness must pin the same `registry-platform` tag during coordinated migrations. CI in each consumer should fail when:

- The pinned platform tag differs from the approved migration tag.
- `clippy.toml`, `rustfmt.toml`, or `deny.toml` differs from `registry-platform/templates/`.
- A consumer keeps duplicate in-tree security primitives that the migration DoD says should be removed.

## Release Checklist

1. Update `CHANGELOG.md` with breaking changes, migration notes, and security fixes.
2. Regenerate the config drift inventory with `scripts/audit-configs.sh --base ..`.
3. Run the Track 0 verification commands from the spec:
   - `cargo build --workspace --all-targets --all-features`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo install cargo-deny --version 0.19.7 --locked`
   - `cargo deny check`
   - `cargo test --workspace --all-features`
4. Confirm `scripts/check-hygiene-alignment.sh . .` is green.
5. Confirm consumer PRs are ready to pin the new tag.
6. Create and push the signed tag.
7. Land consumer tag bumps and publish operator-facing migration notes.
