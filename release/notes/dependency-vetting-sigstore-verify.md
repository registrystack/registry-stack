# `sigstore-verify` dependency vetting

Date: 2026-07-30

Registryctl uses `sigstore-verify` only at the offline release-lock boundary.
The direct dependency is pinned exactly to `0.11.0` with default features
disabled. Registryctl does not expose options which skip certificate-chain,
SCT, transparency-log, checkpoint, inclusion-proof, signed-entry-timestamp, or
artifact-signature verification.

The verifier receives only:

- the exact canonical release-lock payload bytes;
- the inline Sigstore protobuf bundle;
- the compiled-in production trusted root whose reviewed JSON SHA-256 is
  `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`;
- the exact Registry Stack release workflow identity and GitHub Actions issuer.

It performs no trust-root or bundle download. Although the pinned Sigstore
crate graph retains HTTP client crates internally, the Registryctl verification
path constructs `TrustedRoot` and `Bundle` directly from local bytes and calls
the synchronous offline verifier.

## Review evidence

- Source repository declared by the crate:
  <https://github.com/sigstore/sigstore-rust>
- License: Apache-2.0.
- Exact Cosign 3.0.4 release bundle verifies offline in the Registryctl test.
- Negative tests reject altered artifact bytes, wrong certificate identity,
  wrong trusted root, invalid signing time, and a corrupted Rekor inclusion
  proof.
- `cargo deny check` completed with advisories, bans, licenses, and sources
  accepted. Its existing duplicate, unmatched-license, and yanked warnings
  remain warnings.
- `cargo audit` reported zero vulnerabilities and the repository's three
  existing allowed warnings.

## Dependency and binary impact

The exact pin adds 37 unique nodes to Registryctl's resolved normal dependency
graph, from 713 to 750. A same-profile cached debug comparison grew from
151,620,176 bytes to 170,328,928 bytes, an increase of 18,708,752 bytes
(12.34%). Release-profile size remains a release-gate measurement because this
shared development worktree did not have a comparable pre-change release
binary.
