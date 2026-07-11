# `ryu-js` Dependency Vetting Review

Reviewed: 2026-07-11

Decision: accept the locked `ryu-js` 1.0.2 release for the narrow runtime use
described below, subject to the controls and review triggers in this note. This
decision is not a certification of RFC 8785 conformance, memory safety, or
upstream supply-chain security.

## Scope and Need

`registry-platform-canonical-json` uses `ryu-js` to serialize finite IEEE 754
binary64 numbers with ECMAScript number-to-string semantics. The small shared
crate supplies canonical bytes to `registry-platform-crypto`,
`registry-manifest-core`, and their hash, signature, JWK thumbprint, policy,
manifest, and configuration-artifact consumers.

The existing `serde_json::Number::to_string()` path preserves Rust integer
representations and does not provide the ECMAScript formatting rules required
by RFC 8785. Plain `ryu` and `serde_json`'s normal number serializer are also
not substitutes for the ECMAScript fixed-versus-exponent thresholds. Rewriting
the conversion algorithm locally would add a larger and harder-to-verify
security-sensitive implementation.

## Package and Dependency Graph

- Package: `ryu-js` 1.0.2.
- Source: <https://crates.io/crates/ryu-js/1.0.2>.
- Cargo checksum:
  `dd29631678d6fb0903b69223673e122c32e9ae559d0960a38d574695ebc0ea15`.
- Upstream: <https://github.com/boa-dev/ryu-js>.
- License: `Apache-2.0 OR BSL-1.0`. Both choices are allowed by all five
  repository `deny.toml` license policies.
- Features: no optional feature is enabled; the crate's default feature set is
  empty.
- Normal transitive dependencies: none.
- Lockfile impact: version 1.0.2 was already present through the `oxjsonld`
  development dependency path. The product change promotes the same locked
  package to a direct runtime dependency of
  `registry-platform-canonical-json`; it does not add another external package
  version or checksum.

## Maintenance and Security Signals

At review time, the upstream repository was not archived and reported a most
recent push on 2026-07-10. Its latest crates.io/GitHub release was 1.0.2 on
2025-02-16. The repository includes fuzzing and Dependabot configuration.

The [OpenSSF Scorecard API][scorecard] reported an overall score of 5.0 on
2026-07-06. The report assigned zero scores to Token-Permissions,
Pinned-Dependencies, Security-Policy, and SAST. These are risk signals, not
proof of a vulnerability or a compliance result, but they limit the assurance
available from upstream automation.

The repository has no cargo-vet audit or import configuration. Registry Stack
therefore relies on its documented manual review, locked resolution, `cargo deny`,
Dependabot, CodeQL, Scorecard signals, and conformance regression tests. The
reviewed `cargo deny check` completed successfully with no new advisory, license,
source, or ban failure attributable to `ryu-js`.

The first-party crate inherits `unsafe_code = "forbid"`, but that lint does not
apply to dependencies. `ryu-js` exposes the safe `Buffer` API used by Registry
Stack and implements it over third-party unsafe code. A source scan found 43
lines matching unsafe constructs across 12 Rust source files, including raw
buffer writes and unchecked UTF-8 conversion in the formatting path. The
release unsafe-code inventory is explicitly first-party-only, so this note
records the new runtime third-party unsafe surface without changing that
inventory's scope.

## Accepted Risk and Controls

The residual third-party unsafe and weak upstream supply-chain signals are
accepted for this locked, narrow use because the crate has no normal
dependencies, provides the needed ECMAScript behavior through a safe API, was
already resolved in the workspace, and passed the RFC 8785 Appendix B finite
number vectors used during review.

The following controls are required:

- call only the safe `ryu_js::Buffer` API;
- reject values that are not finite binary64 numbers before calling
  `format_finite`;
- enable correctly rounded JSON-to-binary64 parsing with
  `serde_json/float_roundtrip` in every build graph that canonicalizes parsed
  JSON;
- keep the exact version and checksum in `Cargo.lock`, and use locked build and
  test commands;
- retain exact RFC 8785 number, string, UTF-16 property-order, nesting, and
  negative-zero regression vectors;
- treat changes to canonical bytes as signature and digest compatibility
  changes, not formatting-only changes;
- keep raw I-JSON validation, including duplicate-property rejection and input
  size or depth limits, at the calling trust boundary.

## Review Triggers

Repeat this review when any of the following occurs:

- the `ryu-js` version, checksum, source, features, or dependency graph changes;
- a RustSec, GitHub, compiler, Miri, fuzzing, or upstream report identifies
  unsoundness or memory-safety risk in the reachable formatting path;
- upstream archives the repository, materially reduces maintenance, or ships a
  replacement release considered for adoption;
- ECMAScript number serialization, RFC 8785 guidance or errata, or
  `serde_json` number parsing changes;
- any RFC vector, differential test, signature fixture, or digest fixture
  changes or fails;
- the dependency is used outside finite JSON number serialization; or
- Registry Stack enters its next stable-release dependency review.

## Required Gates

The dependency and canonicalization change must not merge or release until the
following commands and evidence pass against the same locked tree:

```bash
cargo metadata --locked --format-version 1
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked -p registry-platform-canonical-json
cargo test --locked -p registry-platform-crypto
cargo test --locked -p registry-platform-config --test config_bundle_canonicalization
cargo test --locked --workspace
cargo deny check
git diff --check
```

The committed crypto tests must include all 24 finite RFC 8785 Appendix B
bit-pattern vectors and explicit rejection coverage for non-finite values.
Passing these gates provides regression and policy evidence only; it does not
establish independent standards certification.

[scorecard]: https://api.securityscorecards.dev/projects/github.com/boa-dev/ryu-js
