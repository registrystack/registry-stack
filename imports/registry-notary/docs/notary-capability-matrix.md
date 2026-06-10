# Registry Notary Capability Matrix

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
| Planned | Captured in design records, not yet implemented |
| Out of scope | Not a Registry Notary responsibility |

## Personas

Scenario stories use the same small cast so examples stay easy to follow:
Alice is usually the citizen, resident, farmer, household representative, or
holder; Bob is the case worker or service operator; Carol is the registry
steward; Dave is the auditor or security operator; Erin is the program
administrator; Charlie is a child or dependent person Alice may be authorized
to represent; the Rivera household is a collective subject Alice may represent.

| Persona | What They Need | Examples |
| --- | --- | --- |
| Citizen or resident | Share only the proof needed to access a service | Parent applying for child support, farmer applying for a voucher |
| Case worker | Make an evidence-backed decision without seeing unnecessary registry data | Benefits officer, enrollment officer |
| Program administrator | Define eligibility policy, evidence requirements, and acceptable issuers | Social protection ministry, agriculture program team |
| Registry steward | Protect source registry data while answering authorized evidence questions | Civil registry, farmer registry, health facility registry |
| Auditor or oversight body | Verify decisions and data exchanges were lawful, minimized, and replay-protected | Internal audit, data protection authority |
| Wallet or client app operator | Help users present proofs or receive credentials | Mobile wallet, service portal, case-management app |

## Systems

| System | Role |
| --- | --- |
| Source registry | Operational system of record. It is not exposed directly to consumers |
| Registry Relay | Read-only gateway and metadata publisher for source registry data |
| Registry Notary | Evaluates claims, signs results, issues credentials, enforces evidence policy, and emits audit |
| Registry Manifest | Public metadata and discovery artifact for capabilities, profiles, and evidence offerings |
| Registry Platform | Shared crypto, HTTP, OIDC, SD-JWT, DID/JWK, replay, and audit primitives |
| Service portal or case system | Starts a service workflow and consumes evidence or decisions |
| Holder wallet or client app | Stores credentials, presents proofs, and receives issued credentials |
| Trust bundle or trust registry | Later-stage signed trust metadata. It is not an MVP allowlist |
| Audit store | Local audit trail for evaluations, issuance, denials, and federation exchanges |

## Scenario Matrix

| # | Scenario | Pattern | Status | Main Gap |
| --- | --- | --- | --- | --- |
| 1 | Civil alive predicate | Local evaluation | Supported | None for configured local sources |
| 2 | Age or date-of-birth evidence | Local evaluation | Supported | None for configured local sources |
| 3 | Program enrollment active | Local evaluation | Supported | None for configured local sources |
| 4 | Health facility service available | Local evaluation | Supported | None for configured local sources |
| 5 | Agriculture voucher eligibility | Local evaluation | Supported | None for configured local sources |
| 6 | Livestock movement permit eligibility | Local evaluation | Supported | None for configured local sources |
| 7 | Benefits agency asks Civil Notary for alive predicate | Delegated evaluation | Partial | Product can serve inbound, but has no outbound Notary connector |
| 8 | Benefits agency asks Social Notary for active beneficiary predicate | Delegated evaluation | Partial | Product can serve inbound, but has no outbound Notary connector |
| 9 | Health-linked child support across civil, social, and health | Outbound composition | Planned | Needs outbound connector and runtime composition |
| 10 | Municipality verifies residency with a national registry steward | Delegated evaluation | Partial | Needs demo/client wiring and metadata publication |
| 11 | Citizen presents civil-status proof to a benefits service | User-presented proof | Planned | Needs proof profiles and verifier runtime |
| 12 | Farmer presents landholding or farmer-registration proof | User-presented proof | Planned | Needs proof profiles and status/freshness policy |
| 13 | Health worker presents professional credential for service eligibility | User-presented proof | Planned | Needs proof profiles and issuer trust policy |
| 14 | Parent or guardian requests a service for a child or dependent | Representation plus proof | Planned | Needs actor/subject separation and representation authority policy |
| 15 | Household or group representative requests a service | Representation plus proof | Planned | Needs collective subject model and representative authority policy |
| 16 | Civil Notary issues date-of-birth or alive credential | Credential issuance | Supported | Local wallet ceremony is still demo-grade |
| 17 | Agriculture Notary issues voucher eligibility credential | Credential issuance | Supported | Local wallet ceremony is still demo-grade |
| 18 | Shared Eligibility Notary issues combined-support credential | Credential issuance plus composition | Partial | Credential issuance exists, but peer-result composition is missing |
| 19 | Consuming service helps holder obtain credential from remote Notary | Federated credential issuance | Planned | Needs holder-binding ceremony, nonce ownership, and relay rules |
| 20 | Replay and emergency peer/key denial | Governance | Supported | Shared replay store is still needed for active-active production |
| 21 | Auditor verifies minimized decision evidence | Governance | Partial | Signed results and audit exist, checkpoints are planned |
| 22 | Peer audit checkpoint monitoring | Governance | Planned | Needs checkpoint publisher, Merkle builder, and peer monitor |
