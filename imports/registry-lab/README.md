# registry-lab

This demo runs three independent Registry Relay authorities, four Registry
Witness verifiers, a live Postgres source, a live Zitadel IdP, a default OpenFn
sidecar scenario, a static metadata publisher, and a narrated client. It uses
functional domains only. The services simulate civil, social protection, and
health registry patterns, but they are not real OpenCRVS, OpenSPP, DHIS2,
OpenIMIS, MOSIP, or other product integrations.

## Topology

- `civil-registry-relay`: CSV-backed civil registry authority on host port `4311`.
- `social-protection-registry-relay`: XLSX-backed social protection authority on host port `4312`.
- `health-registry-relay`: Parquet-backed health authority on host port `4313`.
- `postgres`: live Postgres service for Relay database-source scenarios on host port `54329`.
- `zitadel`: live Zitadel IdP for Relay OIDC scenarios on host port `4380`.
- `civil-witness`: civil evidence verifier on host port `4321`.
- `social-protection-witness`: social protection verifier on host port `4322`.
- `shared-eligibility-witness`: cross-authority civil, social, and health verifier on host port `4323`.
- `openfn-civil-witness`: OpenFn sidecar-backed civil verifier on host port `4324`.
- `openfn-civil-sidecar`: OpenFn adaptor sidecar on the private Compose network.
- `openfn-mock-registry`: registry-like HTTP API on the private OpenFn network.
- `static-metadata-publisher`: generated static metadata on host port `4331`.

Inside Compose, services use DNS names like
`http://civil-registry-relay:8080` and
`http://shared-eligibility-witness:8080`. Registry Witness containers do
not mount source data. They read registry facts over HTTP from Relay. The demo
client also has no `data/` mount.

## Quick Start

Clone with submodules:

```bash
git clone --recurse-submodules git@github.com:jeremi/registry-lab.git
cd registry-lab
```

For an existing checkout, or after pulling changes:

```bash
just setup
just generate
just build
just up
just smoke
just client
```

The service-first story uses sibling checkouts of `registry-manifest` and
`registry-atlas` by default. Override `REGISTRY_MANIFEST_REPO` and
`REGISTRY_ATLAS_SOURCE_DIR` if those projects are not next to this repo.
`just generate` fails early when `registry-manifest` is missing, while
`just smoke`, `just live-stories`, and `just release` fail early when either
service-first sibling checkout is missing.

`just generate` writes `.env`, fixture files, and static metadata. Run it before
`just up` the first time, and run it again after pulling demo changes that add
new credentials such as the default OpenFn sidecar tokens. It rewrites `.env`
with fresh local demo secrets, so do not use a hand-edited `.env` for anything
you need to keep.

When you are done:

```bash
just down
```

For a single command that generates, builds, starts, and runs the core checks:

```bash
just quick
```

## Demo Commands

List available recipes:

```bash
just
```

Core setup and lifecycle:

```bash
just setup       # initialize submodules
just generate    # write fixtures, .env secrets, and static metadata
just build       # build the default topology
just up          # start Relay, Witness, Postgres, Zitadel, OpenFn, metadata
just ps          # show service status
just logs        # follow all logs
just logs -- zitadel openfn-civil-witness
just down        # stop containers and remove demo volumes
```

Run the default API-key demo:

```bash
just smoke       # API-level smoke for Relay and Witness
just openfn      # OpenFn sidecar-backed Witness smoke
just client      # narrated default client flow
just quick       # generate, build, up, smoke, openfn, client
```

Run the live-service demos:

```bash
just relay-postgres  # Relay ignored Postgres integration test
just relay-zitadel   # Relay ignored Zitadel integration test
just oidc-relay      # separate OIDC-protected Relay node
just citizen-login  # print local eSignet login URL
just citizen-code   # exchange returned code and run flow
just citizen-token  # run flow with exported tokens
just citizen-oid4vci-token # optional OID4VCI endpoint probe with exported tokens
just live-stories    # print narrated discovery queries and write artifacts
```

Re-open explainability artifacts from `just live-stories`:

```bash
just story-page
just briefing
just case-file
just conformance
```

Run the broader checks:

```bash
just try          # standard demo sequence, leaves containers up
just release      # full release check, cleans up volumes on success
just release-fast # release check without slower live-service extras
```

The release wrapper ends with `docker compose -f compose.yaml down -v`, so it
removes demo volumes after a successful run. Use the individual checks above
when you want to keep the current Postgres, Zitadel, or OpenFn containers
running for inspection.

The `justfile` defaults `REGISTRY_RELAY_SOURCE_DIR`,
`REGISTRY_WITNESS_SOURCE_DIR`, `REGISTRY_OPENFN_WITNESS_SOURCE_DIR`, and
`REGISTRY_PLATFORM_SOURCE_DIR` to sibling checkouts when present. Override those
variables when you want to build from the pinned `vendor/` submodules or another
local path.

## Live Relay Scenarios

The lab includes live services by default so the same checkout can exercise
file-backed Relays, Postgres-backed Relay ingest, and OIDC bearer-JWT auth:

```bash
just relay-postgres
just relay-zitadel
just oidc-relay
```

`check-relay-postgres.sh` starts the lab Postgres service and runs Relay's
ignored `postgres_snapshot` integration test against
`postgres://postgres:postgres@127.0.0.1:54329/registry_lab?sslmode=disable`.

`check-relay-zitadel.sh` starts Zitadel, exports the generated credentials to
`output/zitadel.env`, and runs Relay's ignored `oidc_zitadel` integration test.

`smoke-oidc-relay.sh` starts a host-side OIDC-protected social protection Relay
on port `4314` using the same `output/zitadel.env`. This keeps the existing
API-key demo nodes intact while proving a separate Relay node can verify a real
Zitadel access token. Today the script accepts either a `200` row read or a
`403` scope denial: both prove JWT verification succeeded, while `403` means the
machine-user token did not emit the mapped Zitadel roles.

`smoke-citizen-self-attestation.sh` is an optional eSignet-oriented story for a
citizen-facing Registry Witness on port `4325`. It supports either a JWT access
token carrying the subject-binding claim and `auth_time`, or the eSignet-style
split where UserInfo carries the subject claim and the ID token carries
`auth_time`/`acr`. For stock local eSignet tokens that omit `scope`, the demo
uses `ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled` and relies on issuer,
client/audience, assurance, and subject binding instead. If a live eSignet
profile uses a separate signed UserInfo issuer, mixed token/UserInfo algorithms,
missing access-token `typ`, or a 1200s token lifetime, the script detects or
accepts explicit env overrides for those settings. The script generates
`output/citizen-self-attestation/citizen-civil-witness.yaml`, starts a host-side
Witness against the existing civil Relay, evaluates `person-is-alive` for the
token-bound citizen, and proves `NID-1002` is denied. See
`output/citizen-self-attestation/report.md` and
`output/citizen-self-attestation/flow-transcript.txt` for the evidence trail,
and `docs/citizen-self-attestation-esignet-use-case.md` for the use case and
setup details. The lab intentionally keeps raw demo tokens, decoded claims, and
seeded civil IDs in `output/` for replay and debugging, so treat the directory
as sensitive local evidence.

For the local eSignet profile used by the lab, prefer the Just wrappers:

```bash
just citizen-login
```

Open the printed `http://localhost:3000/authorize?...` URL, authenticate as the
citizen, and leave the terminal running. The recipe waits on
`http://127.0.0.1:4325/callback`, captures the browser redirect, and writes
`output/citizen-self-attestation/esignet-callback.env`. The local wrapper also
requests `scope=openid profile`, `acr_values=mosip:idp:acr:generated-code`, and
the OIDC `claims` parameter needed for signed UserInfo to include
`individual_id`. The login command prints the seeded demo login values:
`NID-1001` with generated code `111111`, and PIN `545411` if the UI asks for a
static code.

Then run:

```bash
just citizen-code
```

`citizen-code` reads the saved callback code. If the local live eSignet setup
created `/tmp/esignet-live-test/client-private.pem`, it uses that client key;
otherwise set `ESIGNET_CLIENT_PRIVATE_KEY_FILE=/path/to/client-private-key.pem`.
The command narrates the verified token metadata, UserInfo subject binding,
Witness discovery, successful self claim, other-person denial, and audit check
without printing raw tokens.

If you already have tokens:

```bash
ESIGNET_CITIZEN_ACCESS_TOKEN="<access-token>" \
ESIGNET_CITIZEN_ID_TOKEN="<id-token>" \
just citizen-token
```

Inspect the latest result with:

```bash
just citizen-report
```

The optional OID4VCI probe is deliberately outside `just quick`. It reuses the
same citizen eSignet login/code/token flow, starts the citizen Witness with an
OID4VCI config block, and writes evidence under `output/citizen-oid4vci`:

```bash
just citizen-oid4vci-login
just citizen-oid4vci-code
```

or, when tokens are already available:

```bash
ESIGNET_CITIZEN_ACCESS_TOKEN="<access-token>" \
ESIGNET_CITIZEN_ID_TOKEN="<id-token>" \
just citizen-oid4vci-token
```

The probe checks issuer metadata, credential offer, nonce, holder proof, and
credential issuance. V1 targets Draft 13-style offer and credential response
compatibility, plus a Final-style nonce endpoint for wallets that require it.
The probe prints each endpoint result in plain language and avoids printing
bearer tokens or credential values to the terminal, but it intentionally writes
raw local replay/debug artifacts under `output/`, including proof JWTs,
credential request and response bodies, and seeded demo civil IDs where present.
The nonce request is bound to the selected `credential_configuration_id`,
matching the Witness nonce replay checks. To test the same facade with Walt
Wallet API or Inji/Mimoto, see `docs/wallet-interop-testing.md`.

## OpenFn Sidecar Demo

The OpenFn nodes prove the Registry Witness `registry_data_api` connector can
source one-item civil lookups from an OpenFn HTTP adaptor sidecar:

```bash
just generate
just build
just up
just openfn
```

The default OpenFn build uses `../registry-witness` through
`REGISTRY_OPENFN_WITNESS_SOURCE_DIR` until the vendored Witness pin contains
`crates/registry-witness-openfn-sidecar`.

OpenFn is part of the default Compose topology. The sidecar and mock registry
are not published to host ports; they run only on the private
`openfn-internal` network. `scripts/smoke-openfn.sh` recreates the three OpenFn
containers with `--force-recreate --remove-orphans` so repeated local runs do
not get stuck on stale Compose container IDs.

The smoke writes `output/smoke-openfn-witness-evaluation.json`. The sidecar is
not published to the host; use the Witness API for evidence requests:

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

## Live-Service Story Runner

`scripts/demo-live-stories.sh` turns the default live services into narrated
demo stories. The terminal output shows each discovery query, key response
fields, and the conclusion being proved. Each run also writes artifacts under
`output/live-stories/` and generates an interactive `index.html`,
`briefing.md`, `case-file.json`, and `conformance-map.json` so the demo can be
presented as a guided case file rather than a pile of API responses:

1. **Service-first discovery through Atlas** publishes `/metadata/cpsv-ap`,
   invokes the Atlas semantic discovery CLI and ServiceGraph API, selects the
   health-linked child support service, maps grouped CCCEV evidence options to
   evidence types and providers, validates a sample form payload against the
   published form JSON Schema, then calls the relevant Witness endpoints from
   discovered access-service endpoints in that service context.
2. **Database-source cutover with live Postgres** starts a temporary
   Postgres-backed Relay on port `4315`, reads benefit cases, inserts a new
   database row, then proves the live Relay sees it without a restart.
3. **Zitadel-issued JWT at a separate OIDC Relay node** starts a temporary
   OIDC-protected Relay on port `4316`, mints a Zitadel machine-user token,
   records the non-secret JWT claims, and shows whether the token authorizes or
   reaches a scope denial after successful verification.
4. **OpenFn sidecar lookup behind Registry Witness** calls the default
   OpenFn-backed Witness on port `4324` and records the date-of-birth claim
   result while keeping the sidecar private to the Compose network.

```bash
just live-stories
just story-page
just briefing
just case-file
just conformance
```

Generated artifacts are written to `output/`. Generated static publication
files are written under `static-metadata/`. Both directories keep only their
`.gitignore` files in git.

See `docs/service-first-discovery.md` for the Atlas-backed service-first story
artifact contract.

In the service-first story, Registry Witness dispatch uses access-service
`endpoint_url` values discovered from Atlas output. The runner records the
discovered endpoint and validates that the host URL used for the HTTP call is
derived from it. The only local rewrite is Compose hostname-to-host-port
translation, for example `http://shared-eligibility-witness:8080` to
`http://127.0.0.1:4323`, so the host-side story runner can reach the same
container service.

This lab does not call OOTS Evidence Broker or Data Service Directory services.
Those remain future cross-border integration points rather than hidden demo
behavior.

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
just build
```

Use the same variables with `scripts/generate-demo-secrets.py` when you want
that script to use a sibling Relay checkout instead of the
`vendor/registry-relay` submodule. `scripts/publish-static-metadata.sh` uses
the Registry Manifest CLI from `REGISTRY_MANIFEST_REPO`, defaulting to the
`../registry-manifest` sibling checkout. For a release, pin the submodules to
commits that already include the Registry Platform, Registry Relay, and Registry
Witness behavior required by this demo.

OpenFn image builds can use `REGISTRY_OPENFN_WITNESS_SOURCE_DIR` separately from
the core Witness image. The current lab default points OpenFn at
`../registry-witness` because the vendored Witness pin does not yet include the
OpenFn sidecar crate.

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
matching SHA-256 fingerprints for Relay, Witness, and OpenFn sidecar auth. The
committed `.env.example` contains inert examples only.

Credential classes:

- metadata client tokens for each Relay;
- evidence source tokens used by Registry Witness instances when calling Relay;
- evidence-only Relay tokens used to prove verification scope does not imply
  row or aggregate access;
- row-reader tokens for the explicit positive row-read check;
- aggregate-reader tokens for the aggregate consultation;
- OpenFn sidecar tokens, stored as raw caller tokens plus `OPENFN_SIDECAR_TOKEN_HASH`;
- OpenFn mock registry target tokens, used only inside the private OpenFn network;
- separate Registry Witness client API keys and bearer tokens;
- distinct shared Registry Witness source tokens for civil, social, and health;
- per-deployment audit hash secrets for Relay and Witness redaction.

The social protection Relay config keeps row and aggregate scopes on separate
credentials so the smoke flow can prove row-reader credentials cannot run the
aggregate endpoint. Civil and health aggregate credentials are generated for
future symmetry but are not used by the v1 walkthrough.

Relay and Registry Witness auth configs should reference only `*_HASH` env vars.
Registry Witness upstream source connections still reference raw `token_env`
names for outbound calls to Relay. The OpenFn sidecar auth config also requires
`OPENFN_SIDECAR_TOKEN_HASH`; plaintext sidecar token config is rejected. No raw
token should be committed.

## Static Metadata

`scripts/publish-static-metadata.sh` runs
`registry-manifest-cli publish` from `REGISTRY_MANIFEST_REPO`, defaulting to the
`../registry-manifest` sibling checkout, and publishes the portable manifest at
`config/static-metadata/metadata.yaml` into `static-metadata/metadata/`. The
publisher serves it at paths such as:

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
