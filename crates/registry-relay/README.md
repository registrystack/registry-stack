# Registry Relay

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Release label: pre-1.0 technical release for evaluation and integration pilots.

[Public test coverage dashboard](https://docs.registrystack.org/reference/test-coverage/) tracks the CI line-coverage signal for this repository.

Registry Relay is a config-driven Rust service that turns sensitive government tabular files and selected database tables into protected, read-only, domain-oriented APIs.

V1 is built around two layers:

- Storage tables read local CSV, XLSX, Parquet, or PostgreSQL sources into Arrow/DataFusion. Table ids are private implementation detail.
- Entities expose domain resources such as `household` or `individual`, with field projection, relationships, scopes, configured aggregates, semantic metadata, and audit records.

This is not an open-data portal and not a spreadsheet wrapper. It publishes restricted consultation APIs for authorized systems. For what ships today and the known limits, see [docs/release-notes.md](docs/release-notes.md) and the [scenario catalog](docs/relay-scenario-catalog.md).

## Background

Registry Relay is an experiment toward a redesigned [GovStack](https://govstack.global/) Digital Registries Building Block. The current BB spec defines a single uniform CRUD platform; this project explores the BB instead as a protected consultation gateway with optional capability families (evidence-offering discovery, aggregates, standards adapters) over a shared entity model. Provisioning and Write are intentionally out of scope for V1; conformance is by capability, not by a single mandatory interface.

Standards integrations such as DCAT-AP, OGC API Records, OGC API Features, Registry Notary evidence-offering discovery, and the optional [Social Protection Digital Convergence Initiative (SP DCI)](https://spdci.org/) sync adapter are layered on top of the core gateway. [STANDARDS_ASSUMPTIONS.md](STANDARDS_ASSUMPTIONS.md) states precisely what Relay publishes versus what downstream tools may infer.

## Get Started

Without cloning this repository, use the Registry Docs tutorials. They create a Relay project from a sample workbook with `registryctl`, start the protected API, and run smoke checks:

- [See it live](https://docs.registrystack.org/start/see-it-live/): hosted lab, zero install.
- [Publish a spreadsheet as a secured registry API](https://docs.registrystack.org/tutorials/publish-spreadsheet-secured-registry-api/)
- [Verify a claim from your registry API](https://docs.registrystack.org/tutorials/verify-claim-registry-api/)

From this repository, the demo pack is the fastest local run. It generates scoped demo API keys on first use and starts a server with five synthetic datasets and the standards adapters enabled:

```sh
just setup
just demo-run
```

Health endpoints are unauthenticated:

```sh
curl -i http://127.0.0.1:4242/healthz
```

Protected endpoints need one of the generated demo keys. List the personas and the operations each key unlocks:

```sh
just demo-keys-list
```

See [demo/README.md](demo/README.md) for the datasets, personas, Bruno collection, and worked scenarios, and [demo/decentralized/README.md](demo/decentralized/README.md) for the multi-service compose demo.

## Documentation

[docs/README.md](docs/README.md) is the documentation map. The main references:

- [API guide](docs/api.md): auth, scopes, filters, pagination, error contract, and standards surfaces. The curated public OpenAPI surface lives in [openapi/registry-relay.openapi.json](openapi/registry-relay.openapi.json) and at the served `/docs` and `/openapi.json`.
- [Client integration guide](docs/client-integration.md): caller behavior, discovery, retries, and the Registry Notary handoff.
- [Configuration guide](docs/configuration.md): the full YAML contract. The binary reads `--config <path>`, then `REGISTRY_RELAY_CONFIG`, then `./config/example.yaml`; [config/example.yaml](config/example.yaml) is the canonical example. API keys are never stored in YAML: configs reference environment-backed SHA-256 fingerprints, and `auth.mode: oidc` validates bearer JWTs against an external IdP.
- [Portable metadata](docs/metadata.md): `metadata.yaml` manifests, the metadata CLI, static publication, ODRL policy metadata, and DCAT-AP/SHACL validation. Manifests can outlive Relay itself and be published as static files.
- [Operations runbook](docs/ops.md): deployment, hardening checklist, key rotation, audit handling, reloads, probes, and troubleshooting.
- [Credential issuance migration](docs/provenance.md): notes for removing legacy Relay response-credential issuer config and using Registry Notary as the issuance surface.
- [Development guide](docs/development.md): local setup, verification commands, project layout, and the OpenAPI release policy.

## Build

Prerequisites: Rust stable toolchain and `just`.

```sh
just setup
just build
```

The release binary is written to `target/release/registry-relay`. The full local CI gate is `just ci`.
Before opening a PR that changes Rust, Cargo, Docker, root workflow, or perf
surfaces, run `just ci-preflight` to check locked Cargo resolution from the
registry-stack root.

## Container Image

```sh
scripts/build-image.sh registry-relay:local
```

The production image is distroless, non-root, and built with no optional Cargo features; standards-enabled images opt in through `REGISTRY_RELAY_FEATURES`. Build steps, sibling-checkout requirements, and promotion gates are in [docs/ops.md](docs/ops.md#build-and-release); image publication, tagging, and signing policy are in [docs/security-assurance.md](docs/security-assurance.md). Release images publish to `ghcr.io/registrystack/registry-relay` from stable `vX.Y.Z` tags and `registry-stack-technical-preview-<date-or-version>` tags; consume release tags or digests, not `latest`, for rollback guarantees. `Dockerfile.demo` is demo-only and is not release evidence.

## Operating With Registry Notary

Relay is the protected consultation API; [Registry Notary](https://github.com/jeremi/registry-notary) is the claim evaluation and credential issuance service. Relay publishes evidence offerings that point callers to Notary and never executes verification itself; Notary calls Relay as an HTTP source. Credential and port conventions for running both are in [docs/ops.md](docs/ops.md).

## Performance Testing

k6 scenarios, synthetic fixtures, and Criterion microbenchmarks live under [perf/](perf/) and [benches/](benches/); the local workflow is documented in [perf/README.md](perf/README.md).

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy and [docs/security-assurance.md](docs/security-assurance.md) for the CI security gates. To contribute, start with [CONTRIBUTING.md](CONTRIBUTING.md).
