# Registry Stack lab

The lab demonstrates the supported pre-1.0 Registry Stack topology and keeps
runtime examples aligned with Registry Stack project authoring.

The default Compose topology runs:

- four Relay-only registry deployments over synthetic local fixtures;
- one source-free, self-attested Notary-only deployment;
- Postgres, Redis, Zitadel, and static metadata support services.

Registry-backed Notary evidence is authored as one Registry Stack project.
Notary receives only the project's Relay connection and compiler-pinned
consultation contracts. It never receives a registry destination or source
credential.

## Executable project topologies

The committed workspaces under `projects/` prove the three supported
deployment shapes:

| Workspace | Products | Purpose |
| --- | --- | --- |
| `projects/combined` | Relay and Notary | One Relay integration supplies several Notary claims. |
| `projects/relay-only` | Relay | Materialization without a Notary deployment. |
| `projects/notary-only` | Notary | Source-free applicant declaration evidence. |
| `projects/openspp-exact` | Relay and Notary | Offline exact-lookup fixture using generic `http`. |

Run the project-authoring gate:

```bash
cd lab
just project-topologies
```

The gate copies each workspace to a temporary directory, runs the documented
`registryctl test`, `check --explain`, and `build` paths, verifies which
product configurations were emitted, and rejects superseded Notary source
paths. The OpenSPP workspace is offline synthetic fixture evidence only. Live
OpenSPP testing is deliberately deferred to the owner-held holdout.

## Quick start

Requirements:

- Docker with Compose v2
- Rust and Cargo
- `just`, `uv`, `jq`, and `rg`
- initialized submodules

```bash
cd lab
just setup
just quick
```

`just quick` performs fixture and secret generation, the project-topology
gate, image builds, startup, Relay access-control smoke checks, and the
source-free Notary evaluation.

Generated local credentials are written to the ignored `.env` file. Do not
commit it. Test output is written beneath ignored `output/`.

When finished:

```bash
just down
```

## Default runtime checks

```bash
just generate
just build
just up
just smoke
```

The smoke proves:

- Relay health and readiness for the civil, social-protection, and health
  deployments;
- evidence-only Relay credentials cannot read records;
- a row-reader credential can read the admitted synthetic records route;
- the Notary-only service evaluates a source-free applicant declaration;
- configured credentials and signing material do not appear in container logs.

The Notary-only configuration is
`config/notary/self-attested-notary.yaml`. Its always-true declaration is a
fictional demonstration of source-free evidence, not an identity or eligibility
proof.

## Relay-only exercises

The lab retains focused Relay infrastructure checks:

```bash
just relay-postgres
just relay-zitadel
just oidc-relay
```

The agricultural and social-protection hosted Compose files are Relay-only.
Their records and aggregate consumers remain available through the existing
`agri-*` recipes that do not require Notary evidence.

## Citizen self-attestation

The optional eSignet flow remains a Notary-only journey. Registry Relay is used
by eSignet as its account source, but the Notary evidence claim itself is
source-free and does not read Relay or another registry.
The negative control proves `NID-1001` is denied by token-to-subject binding
before evaluation.

```bash
just esignet-up
just citizen-login
# Complete the browser redirect, then:
just citizen-code
```

See
[`docs/citizen-self-attestation-esignet-use-case.md`](docs/citizen-self-attestation-esignet-use-case.md)
and [`docs/wallet-interop-testing.md`](docs/wallet-interop-testing.md).

## Hosted validation

Hosted Compose validation remains available:

```bash
just hosted-validate
just hosted-preflight
```

The monolithic hosted topology publishes civil and health Relays, a
source-free self-attested Notary, static metadata, Zitadel, and the mock citizen
portal. The per-track agriculture and social-protection deployments are
Relay-only.

## Verification

Fast lab-local gates:

```bash
bash -n scripts/*.sh
just --list
just config-vocabulary-check
just project-topologies
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Release-oriented gate:

```bash
just release-fast
```

The release wrapper uses the monorepo sources, runs the project topology and
offline fixture checks, builds the lab, runs the smoke suite, and then tears
down volumes.

## Security notes

- All committed data and integration fixtures are synthetic.
- Source credentials remain environment-only and are never passed to Notary.
- Do not print or retain bearer tokens, API keys, signing JWKs, live selectors,
  or unsanitized upstream responses.
- Relay authorization and purpose checks precede source access.
- The source-free Notary claim has no registry access path.
- Live OpenSPP is not part of this lab gate.
