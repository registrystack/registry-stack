# Registry Notary Specs

Design specifications and implementation traces live here. Current operator
guides, tutorials, SDK docs, and release notes stay in `docs/`.

Status tags: `[implemented]` ships in code, `[archived: ...]` is a kept design
record that no longer drives the code, and `[active: ...]` is a living document
that still tracks open work.

- [`adr-audit-pseudonym-redesign.md`](adr-audit-pseudonym-redesign.md):
  accepted design record for versioned audit pseudonym domains, canonical
  identifier inputs, no-match behavior, retention, key rotation, erasure, and
  federation pairwise alignment. **[archived: reconciled design record]**
- [`citizen-self-attestation-spec.md`](citizen-self-attestation-spec.md):
  citizen self-attestation behavior, guard order, privacy controls, rate
  limits, credential issuance, and implementation status.
  **[archived: reconciled design record]**
- [`federated-evaluation-mvp-spec.md`](federated-evaluation-mvp-spec.md):
  static-peer delegated evaluation MVP. **[implemented]**
- [`federated-notary-manifest-spec.md`](federated-notary-manifest-spec.md):
  manifest-backed federation, trust, delegated evaluation, credential issuance,
  and audit checkpoint design. **[archived: diverges from code]**
- [`evidence-request-subject-model-spec.md`](evidence-request-subject-model-spec.md):
  breaking evaluation request model for requester, target, relationship,
  provider-side matching, and non-person evidence subjects.
  **[archived: diverges from code]**
- [`notary-api-v1-route-cleanup-proposal.md`](notary-api-v1-route-cleanup-proposal.md):
  implemented route cleanup design record for the stable `/v1` REST API
  surface. **[implemented]**
- [`openid4vci-wallet-facade-spec.md`](openid4vci-wallet-facade-spec.md):
  OpenID4VCI wallet facade design and current compatibility profile.
  **[implemented]**
- [`openfn-sidecar-source-spec.md`](openfn-sidecar-source-spec.md):
  OpenFn sidecar source integration contract. **[implemented]**
- [`scalability-spec.md`](scalability-spec.md):
  scalability goals, constraints, and performance work plan. **[implemented]**
- [`notary-capability-gaps.md`](notary-capability-gaps.md):
  maintainer roadmap of the per-scenario gaps and the rollup of capability gaps
  surfaced by the Notary scenario catalog. **[active: gap register]**
