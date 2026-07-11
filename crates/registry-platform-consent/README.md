# registry-platform-consent

Shared, offline verification for Registry Stack consent evidence.

The first implementation slice accepts one compact Ed25519 JWS per evaluation.
It validates the closed `ConsentEvidenceV1` payload, verifies the signature
against deployment-pinned JWKs, and enforces exact subject, recipient,
assurance, purpose, time, and optional profile bindings. It intentionally has
no source-status adapter, resolver, network access, or consent collection UI.

Raw compact artifacts are bounded at 8 KiB and deliberately do not implement
`Debug` or `Serialize`. Callers should retain only `VerifiedConsent`, and put
only the domain-separated keyed commitment in audit data.

The portable fixtures under `tests/fixtures/` publish the exact payload,
public JWK, compact JWS, and keyed-commitment result used by the verification
tests. The maximum-field test separately proves that the largest valid Ed25519
artifact remains below the 8 KiB wire limit.
