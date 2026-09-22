# `aws-lc-rs` FIPS Backend Dependency Vetting Review

Reviewed: 2026-09-19

Issue: [#1108](https://github.com/registrystack/registry-stack/issues/1108)

Decision: accept the locked `aws-lc-rs` 1.18.1 release with the `fips`
feature enabled on the workspace dependency, linking `aws-lc-fips-sys`
0.14.2, subject to the controls and review triggers in this note. The FIPS
backend is always on: no build of Registry Stack selects the non-FIPS
module, and there is no runtime detection.

## Scope and Need

`registry-platform-crypto` provides field-level encryption for BReg
restricted fields (issue 1108): AES-256-GCM envelopes sealed under
per-value keys derived with HKDF-SHA-256 from a registry data key, plus an
HMAC-SHA-256 blind index. The ticket requires FIPS-validated cryptography
for these operations.

`aws-lc-rs` already sat in the graph as the default crypto backend of
`jsonwebtoken` 10.4.0, linked against the non-FIPS `aws-lc-sys`. Enabling
the `fips` feature on the workspace dependency declaration turns that
feature on for every `aws-lc-rs` consumer in the unified build, and
`aws-lc-rs` selects its backend module by that feature, so every runtime
path through `aws-lc-rs` (the field-encryption AEAD, HKDF, and HMAC, and
the JWT verification in `jsonwebtoken`) binds `aws-lc-fips-sys`; no
runtime path selects the non-validated module. The non-FIPS `aws-lc-sys`
0.45.0 nevertheless remains activated in the build graph, because
`jsonwebtoken`'s dependency edge enables `aws-lc-rs` default features and
this workspace cannot disable another crate's feature request. It is
compiled but unreferenced by `aws-lc-rs` code paths, and it stays
supply-chain relevant: advisories against it still apply to review.

The seal path uses `aead::RandomizedNonceKey`, the API the binding
documents for FIPS operation; the open path supplies the envelope nonce
explicitly because the nonce is a stored part of the envelope.

## Package and Dependency Graph

- Package: `aws-lc-rs` 1.18.1.
  - Source: <https://crates.io/crates/aws-lc-rs/1.18.1>.
  - Cargo checksum:
    `b281d307588d634de920874890732659e2e7672f72b5e10e81badc1a8a83621e`.
  - Upstream: <https://github.com/aws/aws-lc-rs>, maintained by the AWS
    Cryptography team.
- Native module: `aws-lc-fips-sys` 0.14.2 binds AWS-LC-FIPS 3.0.x.
  - Source: <https://crates.io/crates/aws-lc-fips-sys/0.14.2>.
  - Cargo checksum:
    `03367707e92796b190a4207d4d39b0a4271d574503d2969c2b0cfbf5c87658ee`.
  - Upstream module sources: the `fips-2024-09-27` branch of
    <https://github.com/aws/aws-lc>.
- License: `aws-lc-rs` is `ISC AND (Apache-2.0 OR ISC)`;
  `aws-lc-fips-sys` is `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`. The
  `OpenSSL` term covers OpenSSL-derived code vendored inside the FIPS
  module, which the non-FIPS `aws-lc-sys` 0.45.0 does not carry.
- New dependency nodes relative to `main`: `aws-lc-fips-sys` 0.14.2 and
  `bindgen` 0.72.1 with its supporting crates (a second `bindgen`
  resolution beside pg_query's 0.66.1). `aws-lc-sys` 0.45.0 remains in the
  lockfile from the pre-existing `jsonwebtoken` graph.
- Direct workspace consumers of `aws-lc-rs`: `jsonwebtoken` 10.4.0
  (pre-existing) and `registry-platform-crypto` (new).

## Build Impact

Building `aws-lc-fips-sys` from its bundled source requires CMake and Go and,
on targets without pre-generated bindings, bindgen with libclang. Bindings are
pre-generated for the workspace's server targets, including
`aarch64-apple-darwin` and the `x86_64`/`aarch64` `unknown-linux-gnu` and
`musl` targets. Hosted artifact and macOS verification workflows install Go
1.24.4 explicitly, and the release builder installs snapshot-pinned CMake and
Go packages; the review accompanies those build-input changes.

Linux packages continue to compile and link through the pinned Zig adapter so
the AWS-LC-FIPS objects share the artifact's documented glibc floor. The
adapter separates AWS-LC's textual-assembly and dependency-file passes to
accommodate Zig 0.12.1, and the existing symbol audit retains the published ABI
boundary.

On macOS arm64, `aws-lc-fips-sys` builds its shared libraries. Starting with
v0.33.0, each native executable asset is an archive that keeps the executable,
the exact shared libraries it loads, and the applicable notices together.
Installers for macOS-supported toolsets extract each archive into a private
installation directory and expose the command without separating it from that
library closure. Node.js and Python
client packages embed the same required libraries inside their existing package
formats, so their install commands do not change.

## Maintenance and Security Signals

At review time the crate showed active maintenance: 57 published versions
since April 2023, five releases between 2026-07-17 and 2026-09-01
(including the locked 1.18.1), and roughly 228 million crates.io downloads.
The AWS Cryptography team maintains the module and the binding in the same
repository. The OpenSSF Scorecard endpoint returned no report for the
repository at review time, so no Scorecard claim is made here.

`cargo deny check` completed successfully against the locked tree with
advisories, bans, and sources accepted; the licenses check passes with the
`OpenSSL` allowance this review adds to `deny.toml`.

## FIPS Posture Claims

Upstream documents that the bound AWS-LC-FIPS 3.0.x module has completed
FIPS validation testing by an accredited lab and directs consumers to the
NIST Cryptographic Module Validation Program for certification status.
Registry Stack does not independently certify the module; the claim made
elsewhere in this repository is that the cryptography backing field
encryption is the FIPS build of AWS-LC, always on, with no non-FIPS
fallback path. Documentation must not strengthen this into a certification
claim about Registry Stack itself.

## License Obligations

The `OpenSSL` license term imposes attribution and notice conditions on
redistribution of the vendored OpenSSL-derived code. Binary release artifacts
therefore need the OpenSSL attribution and disclaimer in their accompanying
documentation. Images carry `THIRD_PARTY_NOTICES` inside the artifact. Client
packages embed the applicable notices with their native libraries. From
v0.33.0, each macOS arm64 native executable archive also carries the notices
beside its executable and shared AWS-LC-FIPS libraries. The full archive is
checksum-covered by the release. Release notes need not duplicate the full
notice.

## Accepted Risk and Controls

The residual risk is accepted under these controls:

- keep the `fips` feature on the workspace-wide declaration so no consumer
  can resolve the non-FIPS backend;
- use only the `aead`, `hkdf`, and `hmac` safe APIs, with
  `RandomizedNonceKey` on the seal path;
- derive per-value keys with the HKDF domain-separation labels defined in
  `registry-platform-crypto`; never reuse a data key across registries;
- hold the returned data keys, their extracted base64 form, and the decoded
  intermediates in zeroizing allocations; the Transit HTTP response buffer
  and the rest of the parsed response tree are parser allocations the
  client does not control, and no zeroizing-only claim is made about them;
- fail closed on every envelope defect with value-free errors; and
- do not add another direct runtime consumer without re-reviewing the
  dependency and its feature graph.

## Review Triggers

Repeat this review when any of the following occurs:

- the locked version, checksum, enabled features, or dependency graph
  changes, including a `jsonwebtoken` upgrade that alters its crypto
  backend;
- upstream binds a new AWS-LC-FIPS module version, which the crate may do
  on minor bumps;
- the NIST CMVP status of the bound module version changes;
- an advisory, upstream report, or audit identifies a risk in the reachable
  AEAD, HKDF, or HMAC paths;
- the seal or open API usage changes away from `RandomizedNonceKey` or the
  explicit-nonce open path;
- the builder image changes how CMake or bindgen reach the build; or
- Registry Stack enters its next stable-release dependency review.

## Required Gates

```bash
cargo metadata --locked --format-version 1
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
git diff --check
```

Passing these gates supplies regression and repository-policy evidence. It
is not an independent cryptographic certification.
