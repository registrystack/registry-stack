# Evidence OID4VCI adapter guidance

This crate delivers holder-bound Evidence credentials through the closed
OID4VCI 1.0 Final pre-authorized-code profile. Read the relevant sections of
[oid4vci-profile.yaml](../../products/evidence/contracts/oid4vci-profile.yaml)
and [holder-bound-profile.yaml](../../products/evidence/contracts/holder-bound-profile.yaml).
[Evidence guidance](../../products/evidence/AGENTS.md) also applies to shared
semantics and source/domain neutrality.

The adapter signs no credential, holds no Evidence signing key or holder
private key, and creates no Evidence requirement, derivation, or authority.
Evidence signs the credential for the unchanged public holder keys. Production
dependencies run toward Evidence's client; Evidence does not depend on this
adapter.

- Protect adopter-facing `/offers` as its own OIDC resource server. Keep that
  identity distinct from the outbound private-key-JWT client calling Evidence.
  Metadata and offer configuration come from authenticated Evidence discovery,
  and only holder-bound configurations may be delivered.
- Validate closed wallet proofs before Evidence access. Accept only inline
  public JWK or locally decoded `did:jwk#0`; never resolve a remote key,
  certificate, or DID. Preserve signature-first parsing, duplicate-member
  rejection, and exact audience, nonce, time, and claim rules.
- Codes and tokens are single use. Store only bounded process-local keyed-tag
  state, zeroize claimed values, retain transaction-code lockout, and fail
  closed on saturation. Nonces are stateless freshness challenges. A failure
  after token claim is terminal for that exchange; retry is only for the
  profile's pre-claim transient failures.
- One replica owns this state. Restart invalidates outstanding exchanges.
  Backing Evidence bundle changes require the profile's coordinated stop,
  discard, update, and restart cutover so cached catalog generations do not
  silently disagree. Do not add persistence or replicas as a local refactor.
- Metrics are absent unless configured on a separate private listener with
  only `GET /metrics`. Preserve the closed label vocabulary and value-free
  diagnostics; codes, tokens, nonces, proofs, selectors, keys, credentials, and
  deployment identifiers do not become telemetry.

Keep the adapter interoperable with conforming wallets without introducing
wallet-specific Evidence semantics or a general issuer platform.
Run focused tests and `cargo test --locked -p registry-evidence-oid4vci` from
the monorepo root. Protocol, metadata, or contract changes also use
`products/evidence/scripts/check-contracts.sh` and
`products/evidence/scripts/check-source-neutrality.sh`. Generated OpenAPI is
owned by the contract gate, not hand editing. Real integration proofs live in
`tests/offer_authorization.rs`, `tests/state_machine_recovery.rs`, and
`tests/inji_interoperability.rs`; select the journey crossing the changed
authorization, state, or wallet boundary.
