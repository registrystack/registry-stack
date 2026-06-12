# Registry Relay Documentation

Registry Relay turns registry data you already hold, in spreadsheets or PostgreSQL, into protected, scoped, read-only HTTP APIs. Authorized callers read records over purpose-bound routes, and the gateway never widens reach at request time. Relay also publishes discovery metadata that points callers to a Registry Notary for claim and evidence verification.

New here? Start with the hosted walkthrough, then the first-run tutorials in Registry Docs:

- [See it live](https://docs.registrystack.org/start/see-it-live/): read a protected API and get a credential against a hosted lab, with zero install.
- [Publish a spreadsheet as a secured registry API](https://docs.registrystack.org/tutorials/publish-spreadsheet-secured-registry-api/)
- [Verify a claim from your registry API](https://docs.registrystack.org/tutorials/verify-claim-registry-api/)

The references describe supported behavior. Each fact has one home; pages link to the owning reference instead of restating it. Some links open the source repository on GitHub.

## Integrate

- [API guide](api.md): auth, scopes, filters, pagination, metadata caching, Problem Details, standards surfaces, and the admin route reference. The curated public OpenAPI surface lives in [openapi/registry-relay.openapi.json](../openapi/registry-relay.openapi.json) and the served `/docs` and `/openapi.json`.
- [Client integration guide](client-integration.md): caller behavior for auth, purpose headers, discovery, pagination, ETags, errors, retries, aggregates, signed response credentials, and the Registry Notary handoff.
- [Signed response credentials](provenance.md): VC-JWT response opt-in, issuer modes, schemas, contexts, DID Web, audit, and verification. The config key is `provenance` for compatibility.

## Operate

- [Configuration guide](configuration.md): YAML contract, auth, audit, source formats, Postgres, entities, OGC Features, SP DCI, PublicSchema, aggregates, and signed response credential issuer configuration (`provenance` key).
- [Operations runbook](ops.md): deployment, production hardening checklist, build and release, secret rotation, audit handling, reloads, probes, metrics, running with Registry Notary, and troubleshooting.
- [Portable metadata](metadata.md): manifest split, metadata CLI, static publication, ODRL policy metadata contract, Relay metadata routes, catalog validation, and boundary rules.
- [Standards adapter operator guide](standards-adapter-operator-guide.md): rollout checklist for OGC Features, OGC Records, OGC EDR, SP DCI sync, and PublicSchema mapping.
- [XLSX readiness contract](xlsx-readiness-contract.md): workbook rules for stable XLSX-backed registries.

## Understand

- [Relay scenario catalog](relay-scenario-catalog.md): personas, systems, reusable patterns, support status, and demo coverage.
- [Standards assumptions](../STANDARDS_ASSUMPTIONS.md): what Relay publishes versus what downstream tools may infer.
- [Release notes](release-notes.md): versioned adopter-facing changes and known limits.

## Build and maintain

- [Development guide](development.md): local setup, verification commands, local IdP setup, project layout, OpenAPI release policy, platform compatibility gate, and contribution rules.
- [Security assurance](security-assurance.md): CI security gates, image publication and signing policy, and advisory baselines.
- [perf/README.md](../perf/README.md): local k6 and Criterion performance workflow.

Historical design records and implementation plans are archived in the private
`registry-internal` repository and are not part of this documentation set.
