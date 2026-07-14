# Registry Notary Capability Gaps

> **Page type:** Design record · **Product:** Registry Notary · **Layer:** all · **Audience:** maintainer

> **Status: active gap register (2026-05-31).** This is the maintainer roadmap of
> named product gaps surfaced by the scenario catalog. The scenario stories and
> diagrams live in `../docs/notary-scenario-patterns.md`; the status-labeled
> scenario matrix lives in `../docs/notary-capability-matrix.md`.

## Per-Scenario Gaps

The "Missing" bullets below are collected from each scenario in
`../docs/notary-scenario-patterns.md`. Each group keeps its scenario name so the
gap can be traced back to its flow.

### 1. Civil Alive Predicate

- No product gap for a compiler-pinned Relay consultation.

### 2. Age Or Date-Of-Birth Evidence

- No product gap for a compiler-pinned Relay consultation.

### 3. Program Enrollment Active

- No product gap for a compiler-pinned Relay consultation.

### 4. Health Facility Service Available

- No product gap for a compiler-pinned Relay consultation.

### 5. Agriculture Voucher Eligibility

- No product gap for a compiler-pinned Relay consultation.

### 6. Livestock Movement Permit Eligibility

- No product gap for a compiler-pinned Relay consultation.

### 7. Benefits Agency Asks Civil Notary For Alive Predicate

- Relay-backed federation with cross-service audit correlation.
- Product outbound Notary-to-Notary client.
- Lab client scenario that signs and verifies the full flow end to end.

### 8. Benefits Agency Asks Social Notary For Active Beneficiary

- Relay-backed federation with cross-service audit correlation.
- Product requester/runtime client.
- Demo fixture wiring for social federation profile metadata.

### 9. Health-Linked Child Support Across Three Authorities

- Outbound Notary federation client.
- Runtime mapping of signed peer responses into CEL inputs.
- Deterministic failure mapping for peer denial, stale claim result, and timeout.

### 10. Municipality Verifies Residency With A National Steward

- Relay-backed federation with cross-service audit correlation.
- Residency profile fixtures.
- Outbound requester support in Registry Notary if the municipal service is
  itself a Notary workflow.

### 11. Citizen Presents Civil-Status Proof To Benefits Service

- User-presented proof verifier profile.
- Mapping verified disclosures into local rule inputs.
- Presentation replay and status policy.

### 12. Farmer Presents Landholding Or Registration Proof

- Proof profile for accepted landholding or farmer-registration credentials.
- Freshness and revocation policy for agricultural proofs.

### 13. Health Worker Presents Professional Credential

- Notary runtime proof intake.
- Issuer trust policy and status policy for professional credentials.

### 14. Parent Or Guardian Requests A Service For A Child Or Dependent

- Actor and subject separation in request and audit models.
- Representation proof profiles for parentage, guardianship, power of attorney,
  case delegation, or social-worker assignment.
- Policy rules for whether Alice may request, receive, or hold evidence about
  Charlie.
- Redacted audit fields that record "Alice acted for Charlie" without exposing
  raw identifiers.

### 15. Household Or Group Representative Requests A Service

- Collective `subject_ref` model for households, groups, cooperatives, farms,
  and legal entities.
- Representation proof profiles for household head, group officer,
  cooperative representative, business officer, or delegated agent.
- Policy rules for whether the actor may request, receive, or hold evidence
  about the collective subject and its members.
- Audit fields that distinguish actor, collective subject, represented members
  when relevant, and representation proof without logging raw identifiers.

### 16. Civil Notary Issues Date-Of-Birth Or Alive Credential

- Production wallet interoperability hardening is outside this catalog.

### 17. Agriculture Notary Issues Voucher Eligibility Credential

- Full production wallet ceremony and status profile.

### 18. Shared Eligibility Notary Issues Combined-Support Credential

- Peer-result composition inside Notary runtime.
- Audit links from issued credential to remote evaluation response ids.

### 19. Service Helps Holder Obtain Credential From Remote Notary

- Holder-binding ceremony for federated issuance.
- Nonce ownership, transparent relay rules, substitution defenses, and tests.

### 20. Replay And Emergency Peer Or Key Denial

- Shared replay store for active-active production deployments.

### 21. Auditor Verifies Minimized Decision Evidence

- Signed audit checkpoints and inclusion proofs.
- Standard audit report shape for cross-organization review.

### 22. Peer Audit Checkpoint Monitoring

- Merkle checkpoint builder.
- Checkpoint publisher.
- Peer monitor and historical checkpoint semantics.

## Capability Gaps Surfaced

- Outbound Notary federation client.
- Mapping verified peer responses into local claim rule inputs.
- User-presented proof verifier profiles.
- Representation authority profiles, actor/subject separation, and collective
  subject support.
- Credential status and freshness policy for remote proofs.
- Federated credential issuance holder-binding ceremony.
- Shared replay store for active-active deployments.
- Signed audit checkpoints and peer monitoring.
- Registry Lab federation scenario scripts and fixture metadata.
