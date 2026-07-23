# Registry Notary capability matrix

> **Page type:** Concept · **Product:** Registry Notary · **Layer:** all · **Audience:** integrator, operator

Use this page to decide what Registry Notary can do today: read the status
labels, the personas and systems vocabulary, then scan the scenario matrix for
the support level and main gap of each flow.

This catalog describes practical places where Registry Notary can help. It is
not a protocol spec. It is a product and demo guide for deciding which flows are
already supported, which are demo-only, and which need more runtime work.

The scenarios use five status labels:

| Status | Meaning |
| --- | --- |
| Supported | Works in Registry Notary runtime and has focused tests or existing product coverage |
| Lab-supported | Can be shown with demo scripts or config, but is not a complete runtime feature |
| Partial | Important pieces exist, but named product gaps remain |
| Planned | Not yet implemented |
| Out of scope | Not a Registry Notary responsibility |

## Personas

The worked scenarios and their recurring example cast live in [Notary
scenario patterns](notary-scenario-patterns.md).

| Persona | What they need | Examples |
| --- | --- | --- |
| Citizen or resident | Share only the proof needed to access a service | Parent applying for child support, farmer applying for a voucher |
| Case worker | Make an evidence-backed decision without seeing unnecessary registry data | Benefits officer, enrollment officer |
| Programme administrator | Define eligibility policy, evidence requirements, and acceptable issuers | Social protection ministry, agriculture programme team |
| Registry steward | Protect source registry data while answering authorized evidence questions | Civil registry, farmer registry, health facility registry |
| Auditor or oversight body | Verify evidence evaluations and data exchanges were lawful, minimized, and replay-protected | Internal audit, data protection authority |
| Wallet or client app operator | Help users present proofs or receive credentials | Mobile wallet, service portal, case-management app |

## Systems

| System | Role |
| --- | --- |
| Source registry | Operational system of record. It is not exposed directly to consumers |
| Registry Relay | Read-only gateway and metadata publisher for source registry data |
| Registry Notary | Evaluates reusable Relay-backed or source-free evidence claims, signs results, issues credentials only from exact Relay-backed evaluation provenance, enforces evidence policy, and emits audit. Source-free results cannot authorize issuance |
| Registry Manifest | Public metadata and discovery artifact for capabilities, profiles, and evidence offerings |
| Registry Platform | Shared crypto, HTTP, OIDC, SD-JWT, DID/JWK, replay, and audit primitives |
| Service portal or case system | Consumes evidence and owns eligibility, prioritization, workflow, and action decisions |
| Holder wallet or client app | Stores credentials, presents proofs, and receives issued credentials |
| Trust bundle or trust registry | Signed trust metadata; not yet supported. Peer trust today is a static allowlist |
| Audit store | Local audit trail for evaluations, issuance, denials, and federation exchanges |

## Scenario matrix

The supported scenarios return evidence. The consuming programme makes any
eligibility, entitlement, payment, referral, or workflow decision. A Notary
claim may attest a source-owned decision, but Notary does not recompute that
decision as programme policy.

| # | Scenario | Pattern | Status | Main gap |
| --- | --- | --- | --- | --- |
| 1 | Civil alive predicate | Relay-backed evaluation | Supported | None for a compiler-pinned Relay consultation |
| 2 | Age or date-of-birth evidence | Relay-backed evaluation | Supported | None for a compiler-pinned Relay consultation |
| 3 | Programme enrollment active | Relay-backed evaluation | Supported | None for a compiler-pinned Relay consultation |
| 4 | Health facility service available | Relay-backed evaluation | Supported | None for a compiler-pinned Relay consultation |
| 5 | Farmer registration and landholding evidence | Relay-backed evaluation | Supported | None for a compiler-pinned Relay consultation |
| 6 | Livestock identity and movement-status evidence | Relay-backed evaluation | Supported | None for a compiler-pinned Relay consultation |
| 7 | Benefits agency asks Civil Notary for alive predicate | Delegated evaluation | Planned | Inbound federation is source-free in this version, and no outbound Notary client ships |
| 8 | Benefits agency asks Social Notary for active beneficiary predicate | Delegated evaluation | Planned | Inbound federation is source-free in this version, and no outbound Notary client ships |
| 9 | Health-linked child support across civil, social, and health | Outbound composition | Planned | No outbound Notary client or peer-result composition runtime ships yet; you cannot compose signed peer results across authorities in one flow |
| 10 | Municipality verifies residency with a national registry steward | Delegated evaluation | Planned | Inbound federation is source-free in this version, and no outbound client or demo wiring ships |
| 11 | Citizen presents civil-status proof to a benefits service | User-presented proof | Planned | No proof profiles or verifier runtime ship yet; you cannot accept this user-presented civil-status proof |
| 12 | Farmer presents landholding or farmer-registration proof | User-presented proof | Planned | No proof profiles or status/freshness policy ship yet; you cannot accept a user-presented landholding or farmer-registration proof |
| 13 | Health worker presents professional credential for workforce assignment | User-presented proof | Planned | No proof profiles or issuer trust policy ship yet; you cannot accept the presented professional evidence |
| 14 | Parent or guardian requests a service for a child or dependent | Delegated self-attestation plus proof | Supported | Evaluation and rendering require the configured Relay-backed relationship proof; delegated credential issuance is intentionally unavailable in 1.0 |
| 15 | Household or group representative requests a service | Representation plus proof | Planned | No collective subject model or representative authority policy ships yet; you cannot let a household or group representative request this service |
| 16 | Civil Notary issues date-of-birth or alive credential | Credential issuance | Supported | Full EdDSA and ES256 source-tested pre-authorized flow exists; external wallet evidence remains candidate-only |
| 17 | Agriculture Notary issues farmer-registration or landholding credential | Credential issuance | Supported | Full EdDSA and ES256 source-tested pre-authorized flow exists; external wallet evidence remains candidate-only |
| 18 | Shared evidence service issues combined-support evidence credential | Credential issuance plus composition | Partial | Relay-backed credential issuance exists, but peer-result composition is missing |
| 19 | Consuming service helps holder obtain credential from remote Notary | Federated credential issuance | Planned | No holder-binding ceremony, nonce ownership, or relay rules ship yet; you cannot help a holder obtain a credential from a remote Notary through this service |
| 20 | Replay and emergency peer/key denial | Governance | Supported | Active-active deployments require the typed Notary-owned PostgreSQL state schema |
| 21 | Auditor verifies minimized evidence exchange | Governance | Partial | Signed results and audit exist, checkpoints are planned |
| 22 | Peer audit checkpoint monitoring | Governance | Planned | No checkpoint publisher, Merkle builder, or peer monitor ships yet; you cannot independently verify peer audit checkpoints |

Each Relay authority uses one Notary authority, with Notary-owned PostgreSQL
correctness state for production and multi-instance deployment. Wallet-facing
issuance supports only issuer-initiated pre-authorized code, EdDSA `did:jwk`
holder proof, and EdDSA or ES256 issuer signing. This matrix makes no EUDI,
HAIP, PAR, DPoP, wallet-attestation, ES256-holder, or external wallet/verifier
conformance claim. Those claims require frozen candidate artifacts and recorded
external evidence.
