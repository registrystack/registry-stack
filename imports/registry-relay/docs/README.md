# Registry Relay Documentation

Registry Relay turns registry data you already hold, in spreadsheets or PostgreSQL, into protected, scoped, read-only HTTP APIs. Authorized callers read records over purpose-bound routes, and the gateway never widens reach at request time. Relay also publishes discovery metadata that points callers to a Registry Notary for claim and evidence verification.

New here? Start with the hosted walkthrough, then the first-run tutorials in Registry Docs:

- [See it live](https://docs.registrystack.org/start/see-it-live/): read a protected API and get a credential against a hosted lab, with zero install.
- [Publish a spreadsheet as a secured registry API](https://docs.registrystack.org/tutorials/publish-spreadsheet-secured-registry-api/)
- [Verify a claim from your registry API](https://docs.registrystack.org/tutorials/verify-claim-registry-api/)

The references below describe supported behavior. Historical design notes under [history/](history/) are context only; the current contract lives in these references. Some links below open the source repository on GitHub.

## Current References

- [API guide](api.md): auth, scopes, filters, pagination, metadata caching, Problem Details, standards adapters, provenance opt-in, and the dataset-scoped V1 route table.
- [Client integration guide](client-integration.md): caller behavior for auth, purpose headers, discovery, pagination, ETags, errors, retries, aggregates, provenance, and Registry Notary handoff.
- [Configuration guide](configuration.md): YAML contract, auth, audit, source formats, Postgres, entities, OGC Features, SP DCI, PublicSchema, aggregates, and provenance.
- [Deployment hardening](deployment-hardening.md): production checklist for network boundaries, auth, secrets, source data, audit, metadata, provenance, and readiness.
- [Operations runbook](ops.md): deployment, secret rotation, audit handling, reloads, probes, metrics, and troubleshooting.
- [Portable metadata](metadata.md): manifest split, static publication, ODRL policy metadata, Relay metadata routes, and boundary rules.
- [Registry Notary discovery](evidence-verification.md): evidence-offering discovery and the Relay to Registry Notary handoff.
- [Data provenance](provenance.md): VC-JWT response opt-in, issuer modes, schemas, contexts, DID Web, audit, and verification.
- [Relay scenario catalog](relay-scenario-catalog.md): personas, systems, reusable patterns, support status, and demo coverage.
- [Standards adapter operator guide](standards-adapter-operator-guide.md): rollout checklist for OGC Features, OGC Records, OGC EDR, SP DCI sync, and PublicSchema mapping.
- [OpenAPI release policy](openapi-release-policy.md): static vs runtime OpenAPI contract and refresh rules.
- [Use cases](use-cases.md): core product journeys.
- [Development guide](development.md): local setup, verification commands, project layout, and contribution rules.
- [XLSX readiness contract](xlsx-readiness-contract.md): workbook rules for stable XLSX-backed registries.
- [Performance and load testing spec](performance-load-testing-spec.md) and [perf/README.md](../perf/README.md): benchmark design and local k6 workflow.
- [Release notes](release-notes.md): versioned adopter-facing changes and known limits.

## Specs Still In Progress

- [ODRL policy metadata spec](odrl-policy-spec.md): implementation contract for descriptive policy metadata.
- [OGC API Features spec](ogc-api-features-spec.md): feature design notes for the optional OGC Features surface.

## Historical And Internal Notes

Historical files under [history/](history/) may mention removed routes such as `/datasets/{dataset_id}/{entity}` or pre-rename "Evidence Server" wording. Treat them as context only.

Local files under `docs/internal/` capture review findings and work planning. They can be useful during release prep, but they are not normative API, config, or operations documentation and should stay out of commits.
