# `chacha20poly1305` Dependency Vetting Review

Reviewed: 2026-08-10

Decision: accept the locked `chacha20poly1305` 0.11.0 release for Relay V2
opaque cursor encryption, subject to the controls and review triggers in this
note. The workspace dependency disables default features and enables only
`alloc`.

## Scope and Need

`registry-relay-v2` uses `XChaCha20Poly1305` to keep continuation-cursor state
confidential and tamper evident. The protected state binds filters, ordering,
authorization request context, and the selected access profile. Relay derives
a separate cursor key with an HMAC domain-separation label, holds it in a
zeroizing allocation, generates a fresh 24-byte nonce with the operating
system random source, and authenticates the cursor version as associated data.

The existing platform crypto crates do not provide a symmetric XChaCha20-Poly1305
cursor primitive. Implementing one locally or composing encryption and
authentication primitives in Relay would create a larger, less maintainable
cryptographic surface.

## Package and Dependency Graph

- Package: `chacha20poly1305` 0.11.0.
- Source: <https://crates.io/crates/chacha20poly1305/0.11.0>.
- Cargo checksum:
  `9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb`.
- Upstream: <https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305>.
- License: `Apache-2.0 OR MIT`.
- Features: default features disabled; only `alloc` enabled. Relay obtains
  nonces from its existing direct `getrandom` dependency, so the dependency's
  `getrandom`, `rand_core`, and `std` features are not enabled.
- Direct runtime consumer: `registry-relay-v2` only.
- New normal dependency nodes relative to `main`: `aead` 0.6.1,
  `chacha20poly1305` 0.11.0, `cipher` 0.5.2, `inout` 0.2.2, `poly1305` 0.9.1,
  and `universal-hash` 0.6.1. The graph reuses the workspace's existing
  `chacha20` 0.10.1 resolution.

This review upgrades the earlier branch resolution from 0.10.1 because the
upstream security policy supports only the latest release. The upgrade also
removes the older duplicate `chacha20` 0.9.1 resolution and `opaque-debug`
0.3.1 from the lockfile.

## Maintenance and Security Signals

The RustCrypto AEADs repository was active and not archived at review time.
The upstream security policy directs vulnerability reports to the RustCrypto
security contact and states that security updates are applied only to the
latest release. Version 0.11.0 was the latest `chacha20poly1305` release and
supports a Rust version below this workspace's MSRV.

The upstream project documents an NCC Group review of the Rust implementation
with no significant findings. It also documents a constant-time execution
caveat for processors where integer multiplication is variable time. Registry
Stack's supported server platforms are not known to include those processors;
adding such a target requires a new review.

The [OpenSSF Scorecard API][scorecard] reported active maintenance and strong
security-policy, binary-artifact, dangerous-workflow, and packaging signals at
review time. It also reported weaker code-review, token-permission,
pinned-dependency, fuzzing, license, branch-protection, and SAST signals. These
are supply-chain risk indicators, not evidence of a vulnerability.

`cargo deny check` completed successfully against the updated lockfile with
advisories, bans, licenses, and sources accepted. The workspace's existing
yanked `spin` 0.9.8 warning remains unrelated to this dependency graph.

## Accepted Risk and Controls

The residual risk is accepted for this narrow, bounded use of the crate's safe
AEAD API under these controls:

- use only `XChaCha20Poly1305` through the `Aead` and `KeyInit` safe APIs;
- generate a fresh 24-byte nonce for every encryption and never derive a nonce
  from cursor contents;
- retain the HMAC domain-separated, zeroized key derivation and versioned
  associated data;
- enforce cursor plaintext and encoded-token size limits before source access;
- reject all decode, authentication, version, context, and expiry failures
  closed with value-free errors;
- never log cursor keys, plaintext, bearer tokens, or rejected cursor values;
- keep cursor-bearing responses private and non-cacheable; and
- do not add another runtime consumer without re-reviewing the dependency and
  its feature graph.

## Review Triggers

Repeat this review when any of the following occurs:

- the version, checksum, source, enabled features, or dependency graph changes;
- an advisory, upstream report, audit, compiler, or sanitizer result identifies
  a risk in the reachable AEAD path;
- nonce generation, key derivation, associated data, cursor bounds, or failure
  handling changes;
- the dependency gains another runtime consumer;
- Registry Stack adds a processor target affected by the documented
  variable-time multiplication caveat;
- upstream archives the repository, changes its security-support posture, or
  ships a replacement release considered for adoption; or
- Registry Stack enters its next stable-release dependency review.

## Required Gates

The dependency and cursor changes must not merge until these checks pass
against the same locked tree:

```bash
cargo metadata --locked --format-version 1
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked -p registry-relay-v2
cargo test --locked --workspace
cargo deny check
git diff --check
```

Passing these gates supplies regression and repository-policy evidence. It is
not an independent cryptographic certification.

[scorecard]: https://api.securityscorecards.dev/projects/github.com/RustCrypto/AEADs
