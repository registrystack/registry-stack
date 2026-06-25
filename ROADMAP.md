# Roadmap

Registry Stack is a pre-1.0 technical release for evaluation, integration
pilots, and public review. This roadmap describes the public direction through
June 2027. It is planning guidance, not a support commitment or hosted-service
SLA.

Public issues remain the source of truth for work selection:

- [enhancements](https://github.com/registrystack/registry-stack/issues?q=is%3Aissue%20is%3Aopen%20label%3Aenhancement)
- [post-1.0 candidates](https://github.com/registrystack/registry-stack/issues?q=is%3Aissue%20is%3Aopen%20label%3Apost-1.0)

## Now To September 2026

- Keep the root monorepo release train reproducible enough for public review:
  pinned release source refs, release capsules, checksums, keyless cosign
  signatures for GitHub Release assets, SBOMs, and Grype reports.
- Close documentation gaps needed by adopters: installation, verification,
  security posture, release verification, and support expectations.
- Tighten contribution hygiene around DCO sign-offs, test expectations, and
  review standards.
- Continue migrating product-local release evidence into the root monorepo
  release model.

## October 2026 To March 2027

- Harden Registry Relay and Registry Notary deployment profiles for pilot
  operators, especially configuration diagnostics, audit posture, and
  verification commands.
- Expand coverage for governed registry reads, evidence issuance, sidecar
  boundaries, and release tooling.
- Improve contributor onboarding with clearer public issue descriptions and
  scope labels.
- Keep dependency, container, and GitHub Actions update work routine through
  Dependabot and release security checks.

## April 2027 To June 2027

- Prepare a production-stability review plan for the surfaces that have enough
  adoption evidence.
- Decide which APIs and deployment contracts are stable enough for a 1.0
  compatibility policy.
- Revisit stronger supply-chain evidence such as OCI image signatures,
  provenance attestations, and reproducible-build verification.
- Review whether governance capacity supports stricter required-human-review
  rules without blocking maintenance.

## Non-Goals For This Roadmap

- Registry Stack will not become a hosted registry database.
- The hosted lab is not production infrastructure and does not carry an uptime
  or data-retention commitment.
- Runtime credentials, private deployment details, and internal release notes
  will not be copied into public repositories.
- Dynamic trust-chain discovery and federated credential issuance remain out of
  scope unless a future design explicitly promotes them.
- A two-maintainer governance model is not promised until there is real
  maintainer capacity to support it.
