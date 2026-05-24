# registry-lab

This demo runs three independent Registry Relay authorities, three independent
Registry Witness verifiers, a static metadata publisher, and a narrated client.
It uses functional domains only. The services simulate civil, social protection,
and health registry patterns, but they are not real OpenCRVS, OpenSPP, DHIS2,
OpenIMIS, MOSIP, or other product integrations.

## Topology

- `civil-registry-relay`: CSV-backed civil registry authority on host port `4311`.
- `social-protection-registry-relay`: XLSX-backed social protection authority on host port `4312`.
- `health-registry-relay`: Parquet-backed health authority on host port `4313`.
- `civil-witness`: civil evidence verifier on host port `4321`.
- `social-protection-witness`: social protection verifier on host port `4322`.
- `shared-eligibility-witness`: cross-authority civil, social, and health verifier on host port `4323`.
- `openfn-civil-witness`: optional OpenFn sidecar-backed civil verifier on host port `4324`.
- `openfn-civil-sidecar`: optional OpenFn adaptor sidecar on host port `4341`.
- `openfn-mock-registry`: optional registry-like HTTP API on host port `4340`.
- `static-metadata-publisher`: generated static metadata on host port `4331`.

Inside Compose, services use DNS names like
`http://civil-registry-relay:8080` and
`http://shared-eligibility-witness:8080`. Registry Witness containers do
not mount source data. They read registry facts over HTTP from Relay. The demo
client also has no `data/` mount.

## First Run

Clone with submodules:

```bash
git clone --recurse-submodules git@github.com:jeremi/registry-lab.git
cd registry-lab
```

For an existing checkout:

```bash
git submodule update --init --recursive
```

Then run:

```bash
uv run scripts/generate-fixtures.py
scripts/generate-demo-secrets.py
scripts/publish-static-metadata.sh
docker compose -f compose.yaml build
docker compose -f compose.yaml up -d
scripts/smoke.sh
docker compose -f compose.yaml --profile client run --rm demo-client
docker compose -f compose.yaml down -v
```

The same path is wrapped by:

```bash
scripts/release-check.sh
```

## Optional OpenFn Sidecar Demo

The OpenFn profile proves the Registry Witness `registry_data_api` connector can
source one-item civil lookups from an OpenFn HTTP adaptor sidecar:

```bash
uv run scripts/generate-fixtures.py
scripts/generate-demo-secrets.py

REGISTRY_WITNESS_SOURCE_DIR=../registry-witness \
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform \
docker compose -f compose.yaml --profile openfn build openfn-mock-registry openfn-civil-sidecar openfn-civil-witness

REGISTRY_WITNESS_SOURCE_DIR=../registry-witness \
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform \
scripts/smoke-openfn.sh
```

Use the sibling `../registry-witness` checkout until the vendored Witness pin
contains `crates/registry-witness-openfn-sidecar`.

The smoke writes `output/smoke-openfn-sidecar-rda.json` and
`output/smoke-openfn-witness-evaluation.json`. The direct Witness request is:

```bash
set -a
. ./.env
set +a

curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/openfn-sidecar-demo" \
  http://127.0.0.1:4324/claims/evaluate \
  --data '{"subject":{"id":"person-123","id_type":"national_id"},"claims":["date-of-birth"],"disclosure":"value","format":"application/vnd.registry-witness.claim-result+json"}' | jq
```

Generated artifacts are written to `output/`. Generated static publication
files are written under `static-metadata/`. Both directories keep only their
`.gitignore` files in git.

## Source Repositories

This demo keeps runtime orchestration, fixtures, static metadata config, and
walkthrough scripts in this repository. Registry Platform, Registry Relay, and
Registry Witness are submodules under `vendor/`:

- `vendor/registry-platform`: shared platform crates used by Relay and Witness.
- `vendor/registry-relay`: Relay source used by `Dockerfile.registry-relay`.
- `vendor/registry-witness`: Registry Witness source used by
  `Dockerfile.registry-witness`.

The Compose build uses Docker named contexts so local source checkouts can be
used without changing `compose.yaml`:

```bash
REGISTRY_RELAY_SOURCE_DIR=../registry-relay \
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform \
REGISTRY_WITNESS_SOURCE_DIR=../registry-witness \
docker compose -f compose.yaml build
```

Use the same variables with `scripts/generate-demo-secrets.py` and
`scripts/publish-static-metadata.sh` when you want those scripts to use a sibling
Relay checkout instead of the `vendor/registry-relay` submodule. For a release,
pin the submodules to commits that already include the Registry Platform,
Registry Relay, and Registry Witness behavior required by this demo.

## Fixture Data

`scripts/generate-fixtures.py` is the source of truth for the synthetic CSV,
XLSX, and Parquet extracts. It writes a small but non-trivial fixture set:

- civil registry CSV: children, caregivers, living adults, and deceased adults
  across five districts;
- social protection XLSX: households, household members, and enrollments with
  active, inactive, suspended, and review-required cases;
- health registry Parquet: active, suspended, pending-renewal, and
  partially-serviceable facilities.

The generator validates key coverage before writing files so the demo keeps a
successful subject, failed predicates, deceased-member cases, cross-source
subjects, and health-linked support cases.

## Credentials

`scripts/generate-demo-secrets.py` writes `.env` with local demo credentials and
matching Relay SHA-256 hashes. The committed `.env.example` contains inert
examples only.

Credential classes:

- metadata client tokens for each Relay;
- evidence source tokens used by Registry Witness instances when calling Relay;
- evidence-only Relay tokens used to prove verification scope does not imply
  row or aggregate access;
- row-reader tokens for the explicit positive row-read check;
- aggregate-reader tokens for the aggregate consultation;
- separate Registry Witness client API keys and bearer tokens;
- distinct shared Registry Witness source tokens for civil, social, and health.
- per-deployment audit hash secrets for Relay and Witness redaction.

The social protection Relay config keeps row and aggregate scopes on separate
credentials so the smoke flow can prove row-reader credentials cannot run the
aggregate endpoint. Civil and health aggregate credentials are generated for
future symmetry but are not used by the v1 walkthrough.

Relay and Registry Witness auth configs should reference only `*_HASH` env vars.
Registry Witness upstream source connections still reference raw `token_env`
names for outbound calls to Relay. No raw token should be committed.

## Static Metadata

`scripts/publish-static-metadata.sh` wraps
`vendor/registry-relay/scripts/run_registry_manifest_cli.sh publish` by default
and publishes the portable manifest at `config/static-metadata/metadata.yaml`
into `static-metadata/metadata/`. The publisher serves it at paths such as:

- `http://127.0.0.1:4331/metadata/index.json`
- `http://127.0.0.1:4331/metadata/catalog.json`
- `http://127.0.0.1:4331/metadata/evidence-offerings.json`
- `http://127.0.0.1:4331/metadata/policies.jsonld`

The static bundle is generated from portable metadata, not scraped from a
running Relay. It must not include source paths, table ids, scopes, cache paths,
or backend runtime details.

## Demo Flow

`scripts/demo-flow.py` narrates three scenarios:

1. Birth Registration To Child Support: Registry Witness verifies civil facts and
   issues a demo-grade credential without exposing raw civil rows.
2. Household Benefit Review From Registry Data: the client performs a protected
   Relay row read and aggregate consultation with `Data-Purpose`, then writes a
   demo household-benefit decision artifact without writing back to Relay.
3. Cross-Authority Conditional Support: static metadata leads the client to a
   shared Registry Witness claim that depends on civil, social protection, and
   health authorities.

Every client request sends `x-request-id` using
`decentralized-demo-correlation-001` by default and saves JSON artifacts.

## Notes

The Relay demo image is built by `Dockerfile.registry-relay` with
`spdci-api-standards,standards-cel-mapping` so DCI source routes are available.

Registry Witness exposes OpenAPI at `/openapi.json` under the same auth boundary
as the rest of the Registry Witness API. The demo client and smoke script fetch
that document from all three Registry Witness instances.
