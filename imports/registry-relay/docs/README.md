# Registry Relay Documentation

This directory has three kinds of documents:

- Current operator and adopter references. These describe supported behavior in the current worktree.
- Historical design notes under [history/](history/). These are useful context, but the current contract lives in the operator references.
- Local internal review notes may exist under `docs/internal/`. That directory is ignored and should not be committed.

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

## Missing Documentation Backlog

- A final REST route and static OpenAPI refresh after the active API design changes settle.
- Language-specific client examples or SDKs, if Relay grows a supported client package.
- Deeper feature-specific conformance notes for standards adapters once each adapter has external consumer feedback.
