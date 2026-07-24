# Registry Notary documentation

Registry Notary evaluates claims and issues evidence. For registry-backed
evidence, it consumes only authenticated, typed Registry Relay consultation
results. For Notary-only projects it can evaluate source-free self-attested
evidence, but it cannot issue credentials from those claims. Credential
issuance requires a newly executed, compiler-pinned Relay consultation for
every selected claim. It never connects directly to a registry source.

## Understand

- [Architecture overview](architecture-overview.md)
- [Capability matrix](notary-capability-matrix.md)
- [Consultation identity and outcomes](identity-and-record-matching.md)
- [Scenario patterns](notary-scenario-patterns.md)
- [Source and claim modeling](source-claim-modeling-guide.md)

## Integrate

- [Client SDK guide](client-sdk-guide.md)
- [API reference](api-reference.md)
- [Wallet interop with OID4VCI](oid4vci-wallet-interop.md)
- [SD-JWT VC conformance](sd-jwt-vc-conformance-profile.md)

## Operate

- [Operator configuration reference](operator-config-reference.md)
- [Self-attestation](self-attestation-operator-guide.md)
- [Federated evaluation](federated-evaluation-operator-guide.md)
- [Credential lifecycle and status](credential-lifecycle-status.md)
- [Credential issuance trust-boundary migration](credential-issuance-migration.md)
- [Signing key providers](signing-key-provider.md)
- [Configuration trust](configuration-trust-and-integrity.md)
- [Deployment hardening](deployment-hardening-runbook.md)
- [Security assurance](security-assurance.md)

## Maintain

- [Product layout](../README.md#layout)
- [Design records](../specs/README.md)
- [Release notes](release-notes.md)
- [Security policy](../../../SECURITY.md)

Registry source adaptation belongs to Relay and Registry Stack project
authoring. Rhai is Relay's reviewed `script` capability and CEL is Notary's
evidence-claim policy language. Product and version metadata never selects
either runtime. The evidence consumer determines how returned evidence is
used, and the decision owner remains accountable for requirements, decisions,
workflow, and actions. CEL is not a general-purpose consumer decision engine.
