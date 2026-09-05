# Registry Stack

[![CI](https://github.com/registrystack/registry-stack/actions/workflows/ci.yml/badge.svg)](https://github.com/registrystack/registry-stack/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/registrystack/registry-stack/badge)](https://scorecard.dev/viewer/?uri=github.com/registrystack/registry-stack)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13372/badge)](https://www.bestpractices.dev/projects/13372)
[![Release](https://img.shields.io/github/v/release/registrystack/registry-stack?include_prereleases&sort=semver)](https://github.com/registrystack/registry-stack/releases)
[![Docs](https://img.shields.io/badge/docs-docs.registrystack.org-blue)](https://docs.registrystack.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Registry Stack helps institutions run registry-facing services over the data
they already hold and the registries they do not hold yet: a
configuration-defined writable registry, protected read APIs, signed
minimum-disclosure assertions, a provider index, and audit records, without
turning the registry into a shared database.

This repository is the monorepo source of truth for Registry Stack product code,
release manifests, and docs.

> **Status:** Registry Stack is pre-1.0 Beta software for self-hosted
> institutional pilots. APIs and deployment contracts may still change.
> Adopters should use matching release artifacts and documentation for one
> version.

## Start Here

| Goal | Start here |
|---|---|
| Understand the product | [registrystack.org](https://registrystack.org/) |
| Read the technical docs | [docs.registrystack.org](https://docs.registrystack.org/) |
| Get a first minimum-disclosure assertion | [Evidence Gateway overview](https://docs.registrystack.org/dev/start/evidence-quickstart/) |
| Serve a governed read-only API over a registry you hold | [Publish a governed SQLite registry](https://docs.registrystack.org/dev/tutorials/publish-governed-sqlite-registry/) |
| Build a writable registry backed by PostgreSQL | [Create and query your first registry](https://docs.registrystack.org/dev/tutorials/first-breg/) |
| Publish an index of registry providers | [Publish and consume a Registry Discovery index](https://docs.registrystack.org/dev/tutorials/publish-and-consume-discovery-index/) |
| Install VS Code or Zed integration | [Editor integrations](editors/README.md) |
| Work on the monorepo | See [Development](#development) |
| Review the public roadmap | [ROADMAP.md](ROADMAP.md) |
| Review release evidence | See [Release And External Inputs](#release-and-external-inputs) |

## What It Includes

Registry Stack ships five installable products on one release train. Each has
its own deployment contract and adopter tooling, and each one is optional.

- **Base Registry Engine:** a configuration-defined writable registry backed by
  PostgreSQL. A registry project declares the entities, relationships,
  constraints, access profiles, and events; the compiler turns it into a
  PostgreSQL schema, a REST API, per-profile permissions, revision history, and
  an audit journal.
  Docs: [Base Registry Engine overview](https://docs.registrystack.org/dev/start/breg-quickstart/).
- **Registry Relay:** scoped, read-only HTTP APIs over an existing read-only
  SQLite source. One authored contract compiles and seals into the package the
  `relay` service verifies before it opens a listener.
  Docs: [Publish a governed SQLite registry](https://docs.registrystack.org/dev/tutorials/publish-governed-sqlite-registry/).
- **Evidence Gateway:** signed, minimum-disclosure assertions from fixed
  requests to authoritative sources. Version 1 excludes credential lifecycles,
  documents, federation, and a general policy engine.
  Docs: [Evidence Gateway overview](https://docs.registrystack.org/dev/start/evidence-quickstart/).
- **Registry Discovery:** one immutable index built offline from an
  operator-approved list of public provider descriptions. It is a catalog, not
  a trust broker, authorization service, protocol adapter, or data proxy.
  Docs: [Registry Discovery is an index](https://docs.registrystack.org/dev/explanation/discovery-as-an-index/).
- **Registry Manifest:** portable metadata that describes what a registry
  exposes, rendered without touching the production source.
  Docs: [Registry Manifest reference](https://docs.registrystack.org/dev/products/registry-manifest/reference/).

Evidence Gateway can use a Base Registry Engine or Registry Relay API as one of
its fixed sources, and keeps its own authorization either way. The stack also
includes Registry Mint for short-lived access tokens, Registry Platform shared
primitives, the `bregctl`, `relayctl`, `evidencectl`, and `discoveryctl` adopter
tools, unified Node.js and Python clients, and release tooling for validating
the public source model.

### Install a released build

```bash
# Base Registry Engine: breg and bregctl
curl -fsSL https://github.com/registrystack/registry-stack/releases/latest/download/breg-install.sh | bash

# Registry Relay: relay and relayctl
curl -fsSL https://github.com/registrystack/registry-stack/releases/latest/download/relay-install.sh | bash

# Evidence Gateway: evidence, evidencectl, mint, and evidence-oid4vci
curl -fsSL https://github.com/registrystack/registry-stack/releases/latest/download/evidencectl-install.sh | bash
```

Each installer verifies the binaries against the published `SHA256SUMS` before
writing them to `$HOME/.local/bin`, or to the directory `BREG_INSTALL_DIR`,
`RELAY_INSTALL_DIR`, or `EVIDENCECTL_INSTALL_DIR` names. Registry Discovery and
Registry Manifest publish a binary and no installer: download
`discovery-<tag>-linux-amd64` or `registry-manifest-<tag>-linux-amd64` from the
[release page](https://github.com/registrystack/registry-stack/releases) and
check it against the release checksum chain. Container images for `breg`,
`relay`, `evidence`, `mint`, and `discovery` are published as
`ghcr.io/registrystack/<name>:<tag>`. Which platforms each artifact supports,
and what is not supported, is recorded in
[known limitations](https://docs.registrystack.org/dev/explanation/known-limitations/#platform-support).

```mermaid
flowchart LR
    source["Existing registry source<br/>file, extract, database, platform"]
    manifest["Registry Manifest<br/>describe"]
    relay["Registry Relay<br/>expose protected reads"]
    breg["Base Registry Engine<br/>hold and update records"]
    evidence["Evidence Gateway<br/>minimum-disclosure assertions"]
    discovery["Registry Discovery<br/>index published providers"]
    mint["Registry Mint<br/>issue short-lived tokens"]
    caller["Approved service or verifier"]

    source --> relay
    manifest --> relay
    relay --> caller
    breg --> caller
    source -. fixed request .-> evidence
    relay -. protected fixed request .-> evidence
    breg -. protected fixed request .-> evidence
    evidence -. signed assertion .-> caller
    mint -. access token .-> caller
    relay -. advertisement .-> discovery
    evidence -. advertisement .-> discovery
    discovery -. index lookup .-> caller
```

## Repository Layout

- `crates/`: Rust crates and runnable binaries for Base Registry Engine,
  Registry Relay, Evidence Gateway, Registry Discovery, Registry Manifest,
  Registry Mint, Registry Platform, and the `bregctl`, `relayctl`,
  `evidencectl`, and `discoveryctl` adopter tools. Base Registry Engine lives in
  `crates/registry-breg` with one `breg` binary, and Evidence Gateway in
  `crates/registry-evidence` with one `evidence` binary.
- `products/`: product-owned docs, examples, Docker inputs, specs, security
  material, scripts, performance harnesses, and fixtures that are not normal
  workspace crates.
- `docs/site/`: the public Registry Stack docs site.
- `editors/`: source-installed VS Code and Zed semantic navigation integrations.
- `release/`: stack release manifests, schemas, import audit records, and public
  release and conformance tooling.
- `external/`: notes for external inputs that intentionally stay outside this
  source tree.

## Development

Prerequisites:

- Rust toolchain from `rust-toolchain.toml`.
- Python 3.11 or later for release helper tests and conformance tooling.
- Node.js 22.12.0 and npm for `docs/site`.

Useful first checks:

```bash
cargo metadata --locked --format-version 1
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo test --locked -p registry-evidence
```

Release source checks:

```bash
python3 -m unittest release/scripts/test_registry_release.py
release/scripts/registry-release validate release/manifests/registry-stack-beta-28.yaml
release/scripts/registry-release audit release/manifests/import-map-2026-06-24.yaml
REGISTRY_RELEASE_SOURCE_MODE=monorepo release/scripts/check-release-source-model.sh
python3 -m unittest release/scripts/test_check_release_source_model.py
```

Docs checks:

```bash
cd docs/site
npm ci
npm test
npm run check
```

The GitHub Actions workflow in `.github/workflows/ci.yml` is the reference for
the current pull request gate.

Major new functionality must include automated tests with the change proposal.
Release candidates are built from exact protected-main source and lockfiles.
Independent repeatability exercises run outside ordinary Beta publication. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the formal test and repeatability
policies.

## Release And External Inputs

Crosswalk remains an external pinned input and is not imported into this
repository. Release builds use the pinned Git dependency declared in the root
workspace manifest and record the exact ref in `release/manifests/*.yaml`.

Historical release manifests retain immutable Registry Atlas and eSignet relay
authenticator refs for releases that used them as lab-only external inputs.

Release evidence lives in:

- `release/manifests/`
- `release/notes/`
- `release/conformance/`
- `release/scripts/`

Release assets are published with an authenticated SHA256 checksum chain. The
exact candidate manifest and bundle are attested and verified before promotion.
See [release/VERIFY.md](release/VERIFY.md) for verification commands and
[release/REPEATABLE-BUILDS.md](release/REPEATABLE-BUILDS.md) for asynchronous
repeatable-build evidence.

## Support And Contribution

Use [GitHub issues](https://github.com/registrystack/registry-stack/issues) for
non-security bugs, questions, and feature discussion. See [SUPPORT.md](SUPPORT.md)
for support expectations and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution
workflow. Before opening a pull request, run the relevant checks from
[Development](#development) and keep changes scoped to the owning crate,
product, docs, or release area. Open issues are triaged with public labels
described in [CONTRIBUTING.md](CONTRIBUTING.md#issue-labels).

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md) before opening
a public issue for suspected minimum-disclosure failure, auth bypass, audit
redaction failure, source connector data leakage, or signing key handling bugs.

## License

Registry Stack is released under the [Apache License 2.0](LICENSE).
