# Relay source-plan v1 hash vectors

These are the exact portable integration-pack, compiler-generated consultation-policy preimage, public-contract, and private-binding inputs used by the Rust source-plan compiler tests.

`snapshot-exact-compiler-vectors.json` freezes the domain-separated predicate-plan and physical-projection preimages for the reviewed UTF-8 binary-equality snapshot key and its fixed logical-to-physical projection. The Rust test independently canonicalizes and hashes both preimages before comparing them with the compiled runtime digests.

`runtime-chain-vectors.json` separately freezes three synthetic end-to-end runtime chains: bounded HTTP without consent, sandboxed Rhai without consent, and bounded HTTP with required consent. Each case records the exact keyed subject, input, predicate, and optional consent preimages and commitments, the exact authorization, execution-plan, and authorized-request preimages and digests, and the exact 16-member completion seed, canonical byte count, and plain SHA-256 digest. The synthetic 32-byte `0x42` master key is first processed by the production HKDF-Expand-only label before the HMAC commitments are computed. The Node verifier independently derives that sub-key and validates every link in all three chains.

Run the dependency-free verifier from the repository root:

```sh
node crates/registry-relay/tests/fixtures/source-plan-v1/verify-vectors.mjs
```

The domain labels in `manifest.json` exclude the separator. Hashing appends exactly one NUL byte to the UTF-8 domain label, followed by the RFC 8785 canonical JSON bytes. Policy vectors are not authored fourth artifacts. They are the exact typed preimages Relay generates from normalized public contracts, and each contract's declared policy hash must match before the contract hash is verified. The dedicated ordering pair uses U+E000 followed by U+10000. That is UTF-8 byte order and the reverse of UTF-16 code-unit order, so both Rust and Node must implement the frozen purpose-set ordering rather than inherit a language default. The declared `finite-safe-integers-only` vector domain is deliberately narrower than general RFC 8785 number handling. The verifier strictly decodes UTF-8 without stripping a leading BOM. It rejects malformed UTF-8, a leading BOM, duplicate JSON members, invalid Unicode strings, negative zero, fractional or exponent-form number tokens, and integers outside JavaScript's safe interoperable range.
