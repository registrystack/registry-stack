# `aws-lc-rs` FIPS Backend Dependency Vetting Review

Reviewed: 2026-10-17 (first reviewed 2026-09-19)

Issue: [#1108](https://github.com/registrystack/registry-stack/issues/1108)

Decision: accept the locked `aws-lc-rs` 1.18.2 release with the `fips`
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
0.46.0 nevertheless remains activated in the build graph, because
`jsonwebtoken`'s dependency edge enables `aws-lc-rs` default features and
this workspace cannot disable another crate's feature request. It is
compiled but unreferenced by `aws-lc-rs` code paths, and it stays
supply-chain relevant: advisories against it still apply to review.

The seal path uses `aead::RandomizedNonceKey`, the API the binding
documents for FIPS operation; the open path supplies the envelope nonce
explicitly because the nonce is a stored part of the envelope.

## Package and Dependency Graph

- Package: `aws-lc-rs` 1.18.2.
  - Source: <https://crates.io/crates/aws-lc-rs/1.18.2>.
  - Cargo checksum:
    `faac5829c2b74c28f830747e7818ccfb684261b5f48a1118b1e2a13d36dfab13`.
  - Upstream: <https://github.com/aws/aws-lc-rs>, maintained by the AWS
    Cryptography team.
- Native module: `aws-lc-fips-sys` 0.14.2 binds AWS-LC-FIPS 4.x.
  - Source: <https://crates.io/crates/aws-lc-fips-sys/0.14.2>.
  - Cargo checksum:
    `03367707e92796b190a4207d4d39b0a4271d574503d2969c2b0cfbf5c87658ee`.
  - Upstream module sources: the `fips-2025-09-12-lts` branch of
    <https://github.com/aws/aws-lc>, which the `aws-lc-rs` 1.18.x README
    names for every `aws-lc-rs` release from 1.18.0. The bundled
    `include/openssl/base.h` in the published crate declares
    `AWSLC_VERSION_NUMBER_STRING` 4.2.0. The crate's own README still says
    3.0.x and `fips-2024-09-27`; the first review of this note repeated that
    stale text, and the bundled source is the authority.
- Non-FIPS module: `aws-lc-sys` 0.46.0, compiled but unreferenced (see
  Scope and Need).
  - Source: <https://crates.io/crates/aws-lc-sys/0.46.0>.
  - Cargo checksum:
    `f1622d8446a2d4b2ce0c7eefc73dd43a99779028d5ee5c2dd8073a658ba8a2bc`.
  - Bundles AWS-LC 5.11.0 (previously 5.7.0 in 0.45.0).
- License: `aws-lc-rs` is `ISC AND (Apache-2.0 OR ISC)`;
  `aws-lc-fips-sys` is `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`. The
  `OpenSSL` term covers OpenSSL-derived code vendored inside the FIPS
  module, which the non-FIPS `aws-lc-sys` 0.46.0 does not carry.
  `aws-lc-sys` 0.46.0 keeps the license expression of 0.45.0 unchanged.
- New dependency nodes relative to `main`: `aws-lc-fips-sys` 0.14.2 and
  `bindgen` 0.72.1 with its supporting crates (a second `bindgen`
  resolution beside pg_query's 0.66.1). `aws-lc-sys` remains in the
  lockfile from the pre-existing `jsonwebtoken` graph.
- Direct workspace consumers of `aws-lc-rs`: `jsonwebtoken` 10.4.0
  (pre-existing), `registry-platform-crypto` (runtime), the
  `registry-messagingctl` operator CLI (development key and random-secret
  generation, not a runtime), and `registry-messaging` as a dev-dependency
  only.

### Changes Since the First Review

The 2026-10-17 re-review covers the move from `aws-lc-rs` 1.18.1 to 1.18.2,
which carries `aws-lc-sys` 0.45.0 to 0.46.0:

- `aws-lc-fips-sys` is unchanged: 1.18.2 still requires `^0.14.2`, the lock
  keeps 0.14.2 with the checksum above, and the FIPS module sources are the
  ones the first review accepted. Upstream released `aws-lc-fips-sys` 0.14.3
  (a refreshed FIPS 4.x snapshot) alongside 1.18.2; it is not adopted here,
  and adopting it is a review trigger.
- The `aws-lc-rs` source change between the two releases is limited to `Eq`
  and `PartialEq` on the RSA and EdDSA parameter types and a rustdoc
  correction to `RandomizedNonceKey::open_in_place`, which now states that
  `in_out` may be overwritten on failure. The field-encryption open path
  already discards that buffer on failure, inside a zeroizing allocation, and
  returns a value-free error, so no usage change follows. The `aead`, `hkdf`,
  and `hmac` sources are unchanged.
- Upstream build changes in this release fix static FIPS system-library
  linking and Cranelift link names, which Registry Stack does not use (it
  builds the bundled sources with the default code generator), and adjust
  how the bundled `aws-lc-sys` build applies jitterentropy compiler flags,
  `AWS_LC_SYS_CC`, and archive member paths. Those change how the non-FIPS
  module compiles, not what it compiles. `aws-lc-sys` 0.46.0 raises its `cc`
  floor to 1.2.41, already satisfied by the locked `cc` 1.4.2, and moves its
  optional `bindgen` to 0.73, which no workspace feature activates, so it
  does not enter the lockfile.
- Upstream AWS-LC 5.8.0 to 5.11.0 changes reach only the non-FIPS module,
  which no runtime path references.
- The resolved `aws-lc-rs` feature set (`alloc`, `aws-lc-sys`, `default`,
  `fips`, `ring-io`, `ring-sig-verify`) and the normal and build dependency
  tree below it are identical to the first review except for the two
  version numbers (`cargo tree -e normal,build -p aws-lc-rs` on
  `aarch64-apple-darwin`, before and after). The direct consumers above are
  unchanged by the bump.

## Build Impact

Building `aws-lc-fips-sys` from its bundled source requires CMake and Go and,
on targets without pre-generated bindings, bindgen with libclang. Bindings are
pre-generated for the workspace's server targets, including
`aarch64-apple-darwin` and the `x86_64`/`aarch64` `unknown-linux-gnu` and
`musl` targets. Hosted artifact and macOS verification workflows install Go
1.27.2 explicitly, and the release builder installs snapshot-pinned CMake and
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

At the first review the crate showed active maintenance: 57 published
versions since April 2023, five releases between 2026-07-17 and 2026-09-01,
and roughly 228 million crates.io downloads. At the 2026-10-17 re-review it
showed 58 published versions, 1.18.2 released 2026-10-12 and not yanked, and
roughly 264 million downloads.
The AWS Cryptography team maintains the module and the binding in the same
repository. The OpenSSF Scorecard endpoint returned no report for the
repository at review time, so no Scorecard claim is made here.

`cargo deny check` completed successfully against the locked tree with
advisories, bans, and sources accepted; the licenses check passes with the
`OpenSSL` allowance the first review added to `deny.toml`. The 2026-10-17
re-review repeated it against the 1.18.2 lock with the same result and no
advisory against `aws-lc-rs`, `aws-lc-sys`, or `aws-lc-fips-sys`.

## FIPS Posture Claims

Upstream documents that the bound AWS-LC-FIPS 4.x module has completed
FIPS validation testing by an accredited lab and directs consumers to the
NIST Cryptographic Module Validation Program for certification status. At
the 2026-10-17 re-review, AWS-LC's `FIPS.md` lists AWS-LC-FIPS v4.0 (static
and dynamic) under modules in process, not under awarded certificates.
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
