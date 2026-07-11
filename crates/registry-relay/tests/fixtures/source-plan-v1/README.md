# Relay source-plan v1 hash vectors

These are the exact portable integration-pack, public-contract, and private-binding inputs used by the Rust source-plan compiler tests.

Run the dependency-free verifier from the repository root:

```sh
node crates/registry-relay/tests/fixtures/source-plan-v1/verify-vectors.mjs
```

The domain labels in `manifest.json` exclude the separator. Hashing appends exactly one NUL byte to the UTF-8 domain label, followed by the RFC 8785 canonical JSON bytes. The declared `finite-safe-integers-only` vector domain is deliberately narrower than general RFC 8785 number handling. The verifier strictly decodes UTF-8 without stripping a leading BOM. It rejects malformed UTF-8, a leading BOM, duplicate JSON members, invalid Unicode strings, negative zero, fractional or exponent-form number tokens, and integers outside JavaScript's safe interoperable range.
