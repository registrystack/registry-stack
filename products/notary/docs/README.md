# Registry Notary documentation

> **Page type:** Landing · **Product:** Registry Notary · **Layer:** all · **Audience:** integrator, operator, maintainer

Registry Notary answers configured claims about a person or entity by reading
the minimum data from a source registry, without becoming a copy of that
registry. Depending on the claim, it returns a claim result, renders a supported
format, or issues a short-lived SD-JWT VC credential.

Pick the path that matches what you are doing. New to Registry Notary? Start with the hosted walkthrough or a runnable local tutorial. If you are configuring or operating Notary, start with the [architecture overview](architecture-overview.md).

- [See it live](https://docs.registrystack.org/start/see-it-live/): watch Notary issue a privacy-preserving credential against a hosted lab, with zero install.
- [Verify a claim with Registry Notary](https://docs.registrystack.org/tutorials/verify-claim-registry-api/): add Notary to a local registry API project with `registryctl`.
- [Connect Notary to a Registry Data API source](https://docs.registrystack.org/tutorials/run-notary-standalone-for-api/): transitional migration tutorial for an existing direct Registry Data API-shaped source.
- [Relay-backed DHIS2 journey](../../../crates/registry-relay/profiles/dhis2-2.41.9-enrollment-status/README.md): start a new registry integration from the maintained, hash-pinned consultation profile.

- [Architecture overview](architecture-overview.md): what Registry Notary is, the request lifecycle, and how the layers relate.
- [Capability matrix](notary-capability-matrix.md): which flows Notary supports today, by persona and system.
- [Identity and record matching](identity-and-record-matching.md): how Notary resolves the target entity to a source record, the outcome model, and matching policy.

## Integrate

For application and wallet developers calling the API or the SDKs.

- [Client SDK guide](client-sdk-guide.md): evaluate claims and issue credentials from Rust, Python, and Node.js.
- [API reference](api-reference.md): the route-to-client-method matrix and the stable problem-code registry.
- [Wallet interop with OID4VCI](oid4vci-wallet-interop.md): the OpenID4VCI wallet facade contract and compatibility checklist.
- [SD-JWT VC conformance](sd-jwt-vc-conformance-profile.md): the supported credential wire contract and the explicit non-support list.
- [OpenCRVS tutorial](opencrvs-dci-standalone-tutorial.md): issue local demo SD-JWT VCs from OpenCRVS birth-record evidence.
- [OpenCRVS onboarding model](opencrvs-onboarding.md): understand the
  registryctl-generated project boundary, evidence question, demo signing
  posture, and lightweight policy decision point (PDP) model.
- [Scenario patterns](notary-scenario-patterns.md): reusable evaluation, federation, and issuance flows with sequence diagrams.

## Operate

For operators deploying, configuring, and running a Registry Notary.

- [Configuration reference](operator-config-reference.md): the config blocks for auth, evidence, sources, replay, status, self-attestation, OID4VCI, and federation.
- [Model sources and claims](source-claim-modeling-guide.md): design pinned Relay consultations, source-free claims, and temporary direct migration claims.
- [Relay-backed DHIS2 journey](../../../crates/registry-relay/profiles/dhis2-2.41.9-enrollment-status/README.md): configure and prove the maintained consultation profile end to end.
- [Integration patterns](https://docs.registrystack.org/explanation/integration-patterns/): historical direct/sidecar patterns retained only as migration references.
- [FHIR source adapter](fhir-source-adapter-guide.md): transitional migration reference for existing bounded FHIR projections.
- [Script (Rhai) source adapter](script-rhai-source-adapter-guide.md): transitional migration reference for existing sandboxed sidecar flows.
- [Signing key providers](signing-key-provider.md): SD-JWT VC signing-key configuration, rotation, and PKCS#11 setup.
- [Self-attestation](self-attestation-operator-guide.md): citizen OIDC subject binding, token policy, allow-lists, and rollout.
- [Federated evaluation](federated-evaluation-operator-guide.md): static-peer setup, environment variables, and the replay limitation.
- [Credential lifecycle and status](credential-lifecycle-status.md): short-lived credentials, optional live status, retention, and verifier caveats.
- [Sidecar trust and secret handling](sidecar-trust-and-secrets.md): how the source adapter sidecar verifies its configuration, how Notary pins the sidecar it trusts, how secrets are handled, and what that path does and does not protect against.
- [Deployment hardening runbook](deployment-hardening-runbook.md): production-readiness checklist for network boundaries, secrets, Redis, audit, and rollback.

## Build and maintain

For maintainers changing the code or reviewing design history.

- [Workspace layout](../README.md#layout): the crates and bindings and what each owns.
- [Command-line interface](../../../crates/registry-notary/README.md): the server binary and its subcommands.
- [Design records](../specs/README.md): specifications and implementation traces, kept as design history.
- [Security assurance](security-assurance.md): CI security gates, image publication and signing policy.
- [GITB conformance suite design](../specs/gitb-conformance-suite.md): target runtime scenarios and claim boundary for ITB/GITB (the EU Global Interoperability Test Bed) interoperability evidence.

## Related

- [Release notes](release-notes.md)
- [Security policy](../../../SECURITY.md)
