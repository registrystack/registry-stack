# Registry Notary Scenario Catalog

This catalog describes practical places where Registry Notary can help. It is
not a protocol spec. It is a product and demo guide for deciding which flows are
already supported, which are demo-only, and which need more runtime work.

The scenarios use five status labels:

| Status | Meaning |
| --- | --- |
| Supported | Works in Registry Notary runtime and has focused tests or existing product coverage |
| Lab-supported | Can be shown with demo scripts or config, but is not a complete runtime feature |
| Partial | Important pieces exist, but named product gaps remain |
| Planned | Captured in specs or roadmap, not implemented yet |
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

## Reusable Patterns

### Local Evaluation

```mermaid
sequenceDiagram
  participant Portal as Service Portal
  participant Notary as Registry Notary
  participant Relay as Registry Relay
  participant Source as Source Registry

  Portal->>Notary: Evaluate local claim
  Notary->>Relay: Authorized source lookup
  Relay->>Source: Read source fact
  Source-->>Relay: Source fact
  Relay-->>Notary: Filtered row or value
  Notary->>Notary: Apply claim rule and disclosure policy
  Notary-->>Portal: Evaluation result
```

### Delegated Evaluation

```mermaid
sequenceDiagram
  participant Consumer as Consuming Actor
  participant Peer as Serving Notary
  participant Relay as Peer Registry Relay

  Consumer->>Peer: Signed federation evaluation request
  Peer->>Peer: Verify peer, purpose, profile, replay
  Peer->>Relay: Source read after policy passes
  Relay-->>Peer: Source facts
  Peer-->>Consumer: Signed evaluation response
```

### Outbound Composition

```mermaid
sequenceDiagram
  participant Shared as Shared Eligibility Notary
  participant Civil as Civil Notary
  participant Social as Social Notary
  participant Health as Health Notary

  Shared->>Civil: Signed request for alive predicate
  Civil-->>Shared: Signed alive result
  Shared->>Social: Signed request for beneficiary predicate
  Social-->>Shared: Signed beneficiary result
  Shared->>Health: Signed request for service predicate
  Health-->>Shared: Signed health result
  Shared->>Shared: Verify and compose final claim
```

### User-Presented Proof

```mermaid
sequenceDiagram
  participant H as Holder Wallet
  participant P as Service Portal
  participant W as Consuming Notary
  participant I as Issuing Notary

  H->>P: Share credential or proof
  P->>W: Submit presentation
  W->>W: Verify signature, holder binding, audience, nonce, status
  W->>I: Optional status or trust-material fetch
  I-->>W: Verification material
  W->>W: Map verified claims into rule inputs
  W-->>P: Evaluation result
```

### Credential Issuance

```mermaid
sequenceDiagram
  participant Holder as Holder Wallet
  participant Notary as Registry Notary
  participant Relay as Registry Relay

  Holder->>Notary: Request credential after local workflow
  Notary->>Relay: Authorized source lookup or evaluation input
  Relay-->>Notary: Source facts
  Notary->>Notary: Evaluate claim and verify holder proof
  Notary-->>Holder: SD-JWT VC credential
```

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

## Scenarios

### 1. Civil Alive Predicate

Pattern: Local evaluation  
Status: Supported  
Priority: High

Story: Bob is reviewing Alice's application and only needs to know whether the
civil registry still records her as alive. The Civil Notary checks the source
through the Civil Relay and returns a signed predicate, so Bob gets the answer
without receiving Alice's full civil record.

Personas: case worker, registry steward, auditor  
Systems: service portal, civil Notary, civil Relay, civil registry, audit store

```mermaid
sequenceDiagram
  participant Portal as Service Portal
  participant Notary as Civil Notary
  participant Relay as Civil Relay

  Portal->>Notary: Evaluate person-is-alive
  Notary->>Relay: Lookup civil person by national id
  Relay-->>Notary: Deceased flag
  Notary-->>Portal: Predicate result
```

Supported today:

- Claim configuration with Registry Data API or DCI source connectors.
- Predicate disclosure.
- Redacted audit event.

Missing:

- No product gap for configured local sources.

### 2. Age Or Date-Of-Birth Evidence

Pattern: Local evaluation  
Status: Supported  
Priority: High

Story: Alice needs to prove that she meets an age requirement, but she should
not have to expose more civil data than necessary. Bob asks the Civil Notary
for a date-of-birth value or an age predicate, and the Notary applies the
configured disclosure policy before returning the result.

Personas: citizen, case worker, registry steward  
Systems: service portal, civil Notary, civil Relay, civil registry

```mermaid
sequenceDiagram
  participant Portal as Service Portal
  participant Notary as Civil Notary
  participant Relay as Civil Relay

  Portal->>Notary: Evaluate date-of-birth or age predicate
  Notary->>Relay: Lookup birth date
  Relay-->>Notary: Birth date
  Notary->>Notary: Extract value or derive age predicate
  Notary-->>Portal: Value or predicate result
```

Supported today:

- Value and predicate disclosure modes.
- SD-JWT VC issuance for configured credential profiles.

Missing:

- No product gap for configured local sources.

### 3. Program Enrollment Active

Pattern: Local evaluation  
Status: Supported  
Priority: High

Story: Bob wants to confirm that Alice is actively enrolled in a social
program before approving a linked benefit. The Social Protection Notary checks
the program enrollment record and returns only the active-beneficiary evidence
that the workflow needs.

Personas: case worker, program administrator, registry steward  
Systems: social protection Notary, social protection Relay, source registry

```mermaid
sequenceDiagram
  participant Portal as Benefits Portal
  participant Notary as Social Protection Notary
  participant Relay as Social Protection Relay

  Portal->>Notary: Evaluate beneficiary-active
  Notary->>Relay: Lookup program enrollment
  Relay-->>Notary: Enrollment status
  Notary-->>Portal: Active beneficiary predicate
```

Supported today:

- Local claim dependencies and CEL rules.
- Predicate or value result formats.

Missing:

- No product gap for configured local sources.

### 4. Health Facility Service Available

Pattern: Local evaluation  
Status: Supported  
Priority: Medium

Story: Bob is processing a service request that depends on whether a nearby
facility is licensed and ready to provide care. The Health Notary evaluates
the facility facts behind the Health Relay and gives Bob a service-availability
predicate instead of raw facility rows.

Personas: case worker, program administrator, registry steward  
Systems: health Notary, health Relay, health facility registry

```mermaid
sequenceDiagram
  participant Portal as Service Portal
  participant Notary as Health Notary
  participant Relay as Health Relay

  Portal->>Notary: Evaluate service availability
  Notary->>Relay: Lookup facility facts
  Relay-->>Notary: License, service, practitioner status
  Notary-->>Portal: Service availability predicate
```

Supported today:

- Multi-field source bindings.
- CEL rules over filtered source facts.

Missing:

- No product gap for configured local sources.

### 5. Agriculture Voucher Eligibility

Pattern: Local evaluation  
Status: Supported  
Priority: High

Story: Alice is a farmer applying for a climate-smart input voucher. The
Agriculture Notary checks the farmer, parcel, and redemption facts needed for
Erin's program rules, then returns an eligibility result and reason without
handing the portal all of Alice's registry records.

Personas: farmer, case worker, agriculture program administrator  
Systems: agriculture Notary, agriculture Relay, farmer and parcel registries

```mermaid
sequenceDiagram
  participant Portal as Agriculture Portal
  participant Notary as Agriculture Notary
  participant Relay as Agriculture Relay

  Portal->>Notary: Evaluate voucher eligibility
  Notary->>Relay: Lookup farmer and parcel facts
  Relay-->>Notary: Registration, parcel, redemption facts
  Notary-->>Portal: Eligibility predicate and reason
```

Supported today:

- Demo configuration can evaluate voucher eligibility.
- Reason-code style companion claims can explain denials.
- Local SD-JWT VC issuance can represent successful eligibility.

Missing:

- No product gap for configured local sources.

### 6. Livestock Movement Permit Eligibility

Pattern: Local evaluation  
Status: Supported  
Priority: Medium

Story: Alice needs permission to move livestock between districts. The
Agriculture Notary evaluates herd, vaccination, and quarantine facts and gives
Bob a permit predicate plus a reason code when the movement should be denied.

Personas: farmer, case worker, veterinary registry steward  
Systems: agriculture Notary, agriculture Relay, livestock registry

```mermaid
sequenceDiagram
  participant Portal as Permit Portal
  participant Notary as Agriculture Notary
  participant Relay as Agriculture Relay

  Portal->>Notary: Evaluate livestock movement permit
  Notary->>Relay: Lookup herd, vaccination, quarantine facts
  Relay-->>Notary: Herd facts
  Notary-->>Portal: Permit eligibility predicate and reason
```

Supported today:

- Local multi-claim evaluation.
- Predicate results and reason-code claims.

Missing:

- No product gap for configured local sources.

### 7. Benefits Agency Asks Civil Notary For Alive Predicate

Pattern: Delegated evaluation  
Status: Partial  
Priority: High

Story: Bob works for the benefits agency, while Carol's civil registry owns the
source facts. Instead of giving Bob direct read access to the civil registry,
the benefits actor sends a signed request to Carol's Civil Notary and receives
a signed alive predicate back.

Personas: case worker, registry steward, auditor  
Systems: benefits portal or peer Notary, civil Notary, civil Relay

```mermaid
sequenceDiagram
  participant Benefits as Benefits Actor
  participant Civil as Civil Notary
  participant Relay as Civil Relay

  Benefits->>Civil: Signed federation request for alive predicate
  Civil->>Civil: Verify peer, purpose, profile, replay
  Civil->>Relay: Source read after policy passes
  Relay-->>Civil: Civil facts
  Civil-->>Benefits: Signed predicate response
```

Supported today:

- Inbound `POST /federation/v1/evaluations`.
- Static peer policy, request verification, replay rejection, signed response.

Missing:

- Product outbound Notary-to-Notary connector.
- Lab client scenario that signs and verifies the full flow end to end.

### 8. Benefits Agency Asks Social Notary For Active Beneficiary

Pattern: Delegated evaluation  
Status: Partial  
Priority: High

Story: Bob needs to know whether Alice is an active beneficiary in another
agency's program. The benefits actor asks the Social Protection Notary for a
signed active-beneficiary predicate under a specific purpose, keeping the
social registry steward in control of the source data.

Personas: case worker, program administrator, auditor  
Systems: benefits portal or peer Notary, social protection Notary, social Relay

```mermaid
sequenceDiagram
  participant Benefits as Benefits Actor
  participant Social as Social Protection Notary
  participant Relay as Social Protection Relay

  Benefits->>Social: Signed request for beneficiary-active
  Social->>Social: Verify purpose and profile
  Social->>Relay: Lookup enrollment
  Relay-->>Social: Enrollment facts
  Social-->>Benefits: Signed active-beneficiary response
```

Supported today:

- Serving Notary side of delegated evaluation.
- Purpose and profile policy checks.

Missing:

- Product requester/runtime connector.
- Demo fixture wiring for social federation profile metadata.

### 9. Health-Linked Child Support Across Three Authorities

Pattern: Outbound composition  
Status: Planned  
Priority: High

Story: Alice applies for health-linked child support, and no single agency owns
all the facts. A Shared Eligibility Notary would ask Civil, Social, and Health
Notaries for signed predicates, verify them, and compose one final eligibility
claim for Bob to review.

Personas: citizen, case worker, registry stewards, auditor  
Systems: shared eligibility Notary, civil Notary, social Notary, health Notary

```mermaid
sequenceDiagram
  participant Shared as Shared Eligibility Notary
  participant Civil as Civil Notary
  participant Social as Social Notary
  participant Health as Health Notary

  Shared->>Civil: Signed request for person-is-alive
  Civil-->>Shared: Signed alive predicate
  Shared->>Social: Signed request for beneficiary-active
  Social-->>Shared: Signed beneficiary predicate
  Shared->>Health: Signed request for health-service-available
  Health-->>Shared: Signed health predicate
  Shared->>Shared: Compose final eligibility claim
```

Supported today:

- Each domain claim can be evaluated locally.
- Inbound delegated evaluation exists.

Missing:

- `registry_notary_federation` source connector.
- Runtime mapping of signed peer responses into CEL inputs.
- Deterministic failure mapping for peer denial, stale source, and timeout.

### 10. Municipality Verifies Residency With A National Steward

Pattern: Delegated evaluation  
Status: Partial  
Priority: Medium

Story: Bob works at a municipality and needs to confirm Alice's residency
without receiving a national population record. The municipal service asks the
national Notary for a residency predicate, and Carol's national registry keeps
control of what can be answered and audited.

Personas: citizen, municipal case worker, national registry steward  
Systems: municipal portal, national civil or population Notary

```mermaid
sequenceDiagram
  participant City as Municipal Service
  participant National as National Registry Notary

  City->>National: Signed request for residency predicate
  National->>National: Verify municipal peer and purpose
  National-->>City: Signed residency predicate
```

Supported today:

- Inbound serving pattern is supported.
- Static peer policy can restrict profile and purpose.

Missing:

- Residency profile fixtures.
- Outbound requester support in Registry Notary if the municipal service is
  itself a Notary workflow.

### 11. Citizen Presents Civil-Status Proof To Benefits Service

Pattern: User-presented proof  
Status: Planned  
Priority: High

Story: Alice already has a civil-status credential in her wallet and wants to
share it with a benefits service. Bob's Benefits Notary verifies the
presentation, holder binding, audience, freshness, and status policy before
using the disclosed claims as evidence.

Personas: citizen, case worker, registry steward  
Systems: holder wallet, benefits portal, benefits Notary, civil Notary

```mermaid
sequenceDiagram
  participant Wallet as Citizen Wallet
  participant Portal as Benefits Portal
  participant Notary as Benefits Notary
  participant Civil as Civil Notary

  Wallet->>Portal: Share civil-status proof
  Portal->>Notary: Submit presentation
  Notary->>Notary: Verify holder binding, audience, nonce, expiry
  Notary->>Civil: Optional status or metadata fetch
  Civil-->>Notary: Status or trust material
  Notary-->>Portal: Evaluation result using verified claims
```

Supported today:

- SD-JWT VC issuance primitives exist.

Missing:

- User-presented proof verifier profile.
- Mapping verified disclosures into local rule inputs.
- Presentation replay and status policy.

### 12. Farmer Presents Landholding Or Registration Proof

Pattern: User-presented proof  
Status: Planned  
Priority: Medium

Story: Alice has a farmer-registration or landholding credential from a
trusted authority. Rather than asking a service portal to read the underlying
farm registry, Alice presents the proof and the Agriculture Notary maps the
verified claims into the voucher eligibility workflow.

Personas: farmer, agriculture case worker, registry steward  
Systems: farmer wallet, agriculture portal, agriculture Notary

```mermaid
sequenceDiagram
  participant Wallet as Farmer Wallet
  participant Portal as Agriculture Portal
  participant Notary as Agriculture Notary

  Wallet->>Portal: Present landholding or farmer-registration proof
  Portal->>Notary: Submit proof presentation
  Notary->>Notary: Verify issuer, status, holder binding
  Notary->>Notary: Map acreage and registration claims
  Notary-->>Portal: Voucher eligibility input result
```

Supported today:

- Local agriculture eligibility can be evaluated against Relay sources.

Missing:

- Proof profile for accepted landholding or farmer-registration credentials.
- Freshness and revocation policy for agricultural proofs.

### 13. Health Worker Presents Professional Credential

Pattern: User-presented proof  
Status: Planned  
Priority: Medium

Story: Alice is a health worker whose professional status affects whether a
facility can satisfy a service rule. She presents her professional credential,
and the consuming Notary verifies issuer trust and holder binding before using
that status in the local decision.

Personas: health worker, program administrator, auditor  
Systems: holder wallet, service portal, benefits or health Notary

```mermaid
sequenceDiagram
  participant Wallet as Health Worker Wallet
  participant Portal as Service Portal
  participant Notary as Consuming Notary

  Wallet->>Portal: Present professional credential proof
  Portal->>Notary: Submit presentation
  Notary->>Notary: Verify issuer trust and holder binding
  Notary->>Notary: Map professional status into service rule
  Notary-->>Portal: Accepted or rejected evidence input
```

Supported today:

- Credential issuance and verification primitives exist in platform-adjacent
  crates.

Missing:

- Notary runtime proof intake.
- Issuer trust policy and status policy for professional credentials.

### 14. Parent Or Guardian Requests A Service For A Child Or Dependent

Pattern: Representation plus proof  
Status: Planned  
Priority: High

Story: Alice is applying for a child benefit on behalf of Charlie. Bob needs
evidence about Charlie, but Alice is the person interacting with the portal, so
the Benefits Notary must verify both Charlie's eligibility evidence and
Alice's authority to act for Charlie.

Personas: citizen or resident, case worker, registry steward, auditor  
Systems: holder wallet, service portal, benefits Notary, civil Notary, social Notary

```mermaid
sequenceDiagram
  participant Alice as Parent or Guardian
  participant Portal as Service Portal
  participant Notary as Benefits Notary
  participant Civil as Civil Notary
  participant Social as Social Notary

  Alice->>Portal: Apply for Charlie
  Portal->>Notary: Submit Alice identity and representation proof
  Notary->>Notary: Verify Alice can act for Charlie
  Notary->>Civil: Request Charlie birth or alive predicate
  Civil-->>Notary: Signed child predicate
  Notary->>Social: Request household or benefit predicate
  Social-->>Notary: Signed household predicate
  Notary->>Notary: Evaluate child benefit eligibility
  Notary-->>Portal: Decision or evidence result
```

Supported today:

- Local and delegated claim evaluation can represent some child-related facts.
- User-presented proof is planned as the mechanism for representation evidence.

Missing:

- Actor and subject separation in request and audit models.
- Representation proof profiles for parentage, guardianship, power of attorney,
  case delegation, or social-worker assignment.
- Policy rules for whether Alice may request, receive, or hold evidence about
  Charlie.
- Redacted audit fields that record "Alice acted for Charlie" without exposing
  raw identifiers.

### 15. Household Or Group Representative Requests A Service

Pattern: Representation plus proof  
Status: Planned  
Priority: High

Story: Alice is the registered representative for the Rivera household, a farm
group, or a cooperative. Bob needs to evaluate a service for that collective
subject, so the Notary must verify Alice's authority to act for the household
or group before it evaluates household, member, parcel, or program facts.

Personas: citizen or resident, case worker, program administrator, auditor  
Systems: holder wallet, service portal, benefits Notary, social Notary, agriculture Notary

```mermaid
sequenceDiagram
  participant Alice as Household Representative
  participant Portal as Service Portal
  participant Notary as Benefits Notary
  participant Social as Social Notary
  participant Agriculture as Agriculture Notary

  Alice->>Portal: Apply for Rivera household or group
  Portal->>Notary: Submit representative authority proof
  Notary->>Notary: Verify Alice can act for the group subject
  Notary->>Social: Request household eligibility predicate
  Social-->>Notary: Signed household predicate
  Notary->>Agriculture: Request farm group or parcel predicate
  Agriculture-->>Notary: Signed group predicate
  Notary->>Notary: Evaluate service eligibility
  Notary-->>Portal: Decision or evidence result
```

Supported today:

- Local claim evaluation can target non-person entities when configured.
- Delegated evaluation can request predicates about configured subject types.

Missing:

- Collective `subject_ref` model for households, groups, cooperatives, farms,
  and legal entities.
- Representation proof profiles for household head, group officer,
  cooperative representative, business officer, or delegated agent.
- Policy rules for whether the actor may request, receive, or hold evidence
  about the collective subject and its members.
- Audit fields that distinguish actor, collective subject, represented members
  when relevant, and representation proof without logging raw identifiers.

### 16. Civil Notary Issues Date-Of-Birth Or Alive Credential

Pattern: Credential issuance  
Status: Supported  
Priority: High

Story: Alice wants a reusable civil credential so she does not need a fresh
registry lookup for every service. The Civil Notary evaluates the configured
claim, verifies Alice's holder proof, and issues a holder-bound SD-JWT VC.

Personas: citizen, registry steward, wallet operator  
Systems: holder wallet, civil Notary, civil Relay

```mermaid
sequenceDiagram
  participant Wallet as Holder Wallet
  participant Notary as Civil Notary
  participant Relay as Civil Relay

  Wallet->>Notary: Request credential with holder proof
  Notary->>Relay: Evaluate configured civil claims
  Relay-->>Notary: Civil facts
  Notary->>Notary: Bind credential to holder DID
  Notary-->>Wallet: SD-JWT VC
```

Supported today:

- Local SD-JWT VC issuance for configured credential profiles.
- Holder binding with `did:jwk`.

Missing:

- Production wallet interoperability hardening is outside this catalog.

### 17. Agriculture Notary Issues Voucher Eligibility Credential

Pattern: Credential issuance  
Status: Supported  
Priority: High

Story: Alice qualifies for an agriculture voucher and wants portable proof of
that result. After the Agriculture Notary evaluates the voucher rules, it can
issue a holder-bound credential that Alice can present to a payment or voucher
system.

Personas: farmer, program administrator, wallet operator  
Systems: holder wallet, agriculture Notary, agriculture Relay

```mermaid
sequenceDiagram
  participant Wallet as Farmer Wallet
  participant Notary as Agriculture Notary
  participant Relay as Agriculture Relay

  Wallet->>Notary: Request voucher eligibility credential
  Notary->>Relay: Evaluate voucher eligibility
  Relay-->>Notary: Farmer and parcel facts
  Notary-->>Wallet: Holder-bound SD-JWT VC
```

Supported today:

- Lab agriculture flow can produce a demo credential after successful evaluation.
- Runtime credential profiles support SD-JWT VC issuance.

Missing:

- Full production wallet ceremony and status profile.

### 18. Shared Eligibility Notary Issues Combined-Support Credential

Pattern: Credential issuance plus composition  
Status: Partial  
Priority: High

Story: Alice's combined-support eligibility depends on facts held by multiple
authorities. The future Shared Eligibility Notary would verify peer-signed
predicates, compose a final claim, and issue Alice a credential that points
back to the remote evidence decisions without exposing raw source data.

Personas: citizen, case worker, auditor  
Systems: shared eligibility Notary, peer Notaries, holder wallet

```mermaid
sequenceDiagram
  participant Shared as Shared Eligibility Notary
  participant Civil as Civil Notary
  participant Social as Social Notary
  participant Wallet as Holder Wallet

  Shared->>Civil: Request signed civil predicate
  Civil-->>Shared: Signed civil result
  Shared->>Social: Request signed social predicate
  Social-->>Shared: Signed social result
  Shared->>Shared: Compose combined-support claim
  Shared-->>Wallet: Combined-support credential
```

Supported today:

- Local credential issuance exists.
- Local composed claims can depend on local claim results.

Missing:

- Peer-result composition inside Notary runtime.
- Audit links from issued credential to remote evaluation response ids.

### 19. Service Helps Holder Obtain Credential From Remote Notary

Pattern: Federated credential issuance  
Status: Planned  
Priority: Medium

Story: Alice needs a credential from Carol's issuing Notary while starting
from Bob's service journey. Bob can help Alice discover the issuer or relay
bytes transparently, but Carol's Notary must still own the nonce, audience,
holder-proof verification, and issued credential.

Personas: citizen, wallet operator, registry steward  
Systems: holder wallet, consuming Notary, issuing Notary

```mermaid
sequenceDiagram
  participant Wallet as Holder Wallet
  participant Consumer as Consuming Notary
  participant Issuer as Issuing Notary

  Consumer->>Issuer: Discover credential profile
  Consumer-->>Wallet: Return issuer offer
  Wallet->>Issuer: Present holder proof to issuer
  Issuer->>Issuer: Verify nonce, audience, holder key
  Issuer-->>Wallet: Credential response
```

Supported today:

- Local issuance exists.
- Broader spec defines discovery/handoff and transparent byte relay constraints.

Missing:

- Holder-binding ceremony for federated issuance.
- Nonce ownership, transparent relay rules, substitution defenses, and tests.

### 20. Replay And Emergency Peer Or Key Denial

Pattern: Governance  
Status: Supported  
Priority: High

Story: Dave sees suspicious activity from a peer key and needs the serving
Notary to fail closed immediately. Replay protection blocks reused requests,
and the emergency denylist lets the operator reject a compromised node or key
while the incident is investigated.

Personas: registry steward, auditor, security operator  
Systems: serving Notary, peer Notary, audit store

```mermaid
flowchart TD
  Request["Signed federation request"]
  Replay["Replay store"]
  Denylist["Emergency node/kid denylist"]
  Policy["Peer policy"]
  Result["Allow or deny"]
  Audit["Audit event"]

  Request --> Replay
  Request --> Denylist
  Replay --> Policy
  Denylist --> Policy
  Policy --> Result
  Result --> Audit
```

Supported today:

- Static peer policy.
- Replay protection for request ids.
- Emergency denylist configuration for peers and keys.

Missing:

- Shared replay store for active-active production deployments.

### 21. Auditor Verifies Minimized Decision Evidence

Pattern: Governance  
Status: Partial  
Priority: High

Story: Dave reviews Alice's benefit decision months later and wants confidence
that Bob used minimized evidence. The signed predicate result and redacted
audit event show which profile and purpose were used without disclosing raw
registry rows.

Personas: auditor, registry steward, program administrator  
Systems: service portal, Notary, audit store

```mermaid
flowchart TD
  Decision["Service decision"]
  Predicate["Signed predicate result"]
  Audit["Redacted audit event"]
  Policy["Profile and purpose policy"]
  Report["Audit report"]

  Decision --> Predicate
  Predicate --> Audit
  Policy --> Audit
  Audit --> Report
```

Supported today:

- Signed evaluation responses for federation.
- Redacted local audit events.
- Predicate disclosure avoids raw source rows by default.

Missing:

- Signed audit checkpoints and inclusion proofs.
- Standard audit report shape for cross-organization review.

### 22. Peer Audit Checkpoint Monitoring

Pattern: Governance  
Status: Planned  
Priority: Medium

Story: Dave monitors whether Carol's Notary audit trail is continuous over
time. Signed checkpoints let Dave detect root or sequence regressions without
asking Carol to share every underlying audit event.

Personas: auditor, security operator, registry steward  
Systems: publishing Notary, monitoring Notary, audit store

```mermaid
sequenceDiagram
  participant Publisher as Publishing Notary
  participant Monitor as Monitoring Notary
  participant Audit as Audit Store

  Publisher->>Audit: Append local audit events
  Publisher->>Publisher: Build Merkle checkpoint
  Monitor->>Publisher: Fetch latest checkpoint
  Publisher-->>Monitor: Signed checkpoint
  Monitor->>Monitor: Detect root or sequence regression
```

Supported today:

- Audit fields and spec direction exist.

Missing:

- Merkle checkpoint builder.
- Checkpoint publisher.
- Peer monitor and historical checkpoint semantics.

## Capability Gaps Surfaced

- Outbound `registry_notary_federation` source connector.
- Mapping verified peer responses into local claim rule inputs.
- User-presented proof verifier profiles.
- Representation authority profiles, actor/subject separation, and collective
  subject support.
- Credential status and freshness policy for remote proofs.
- Federated credential issuance holder-binding ceremony.
- Shared replay store for active-active deployments.
- Signed audit checkpoints and peer monitoring.
- Registry Lab federation scenario scripts and fixture metadata.
