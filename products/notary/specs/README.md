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
- [`bounded-batch-evaluation-v1.md`](bounded-batch-evaluation-v1.md):
  hard limits, two-phase processing, per-member audit, cancellation, replay,
  and issuance boundaries for the synchronous batch evaluation surface.
  **[implemented]**
- [`citizen-self-attestation-spec.md`](citizen-self-attestation-spec.md):
  citizen self-attestation behavior, guard order, privacy controls, rate
  limits, and historical source-free credential issuance design. Current
  source-free claims are evaluation-only; current credential issuance requires
  exact registry-backed Relay execution provenance.
  **[archived: reconciled design record]**
- [`federated-evaluation-mvp-spec.md`](federated-evaluation-mvp-spec.md):
  static-peer delegated evaluation MVP. **[implemented]**
- [`gitb-conformance-suite.md`](gitb-conformance-suite.md):
  target GITB runtime scenario suite and first runnable slice for Notary
  interoperability evidence. **[active: suite design]**
- [`notary-api-v1-route-cleanup-proposal.md`](notary-api-v1-route-cleanup-proposal.md):
  implemented route cleanup design record for the stable `/v1` REST API
  surface. **[implemented]**
- [`openid4vci-wallet-facade-spec.md`](openid4vci-wallet-facade-spec.md):
  OpenID4VCI wallet facade design and current compatibility profile.
  **[implemented]**
- [`source-adapter-sidecar-source-spec.md`](../archive/specs/source-adapter-sidecar-source-spec.md):
  historical source-adapter sidecar integration contract.
  **[archived: removed before 1.0]**
- [`scalability-spec.md`](../archive/specs/scalability-spec.md):
  historical direct-source scalability goals and performance work plan.
  **[archived: superseded by Relay-backed execution]**
- [`notary-capability-gaps.md`](notary-capability-gaps.md):
  maintainer roadmap of the per-scenario gaps and the rollup of capability gaps
  surfaced by the Notary scenario catalog. **[active: gap register]**

Archived specs that diverge from the current code moved to `../archive/specs/`:

- [`federated-notary-manifest-spec.md`](../archive/specs/federated-notary-manifest-spec.md)
- [`evidence-request-subject-model-spec.md`](../archive/specs/evidence-request-subject-model-spec.md)
