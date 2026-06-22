# registry-lab

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Release label: pre-1.0 technical release for evaluation and integration pilots.

This demo runs three independent Registry Relay authorities, four Registry
Notary verifiers, a live Postgres source, a live Zitadel IdP, a default OpenFn
sidecar scenario, a static metadata publisher, and a narrated client. It uses
functional domains only. The services simulate civil, social protection, and
health registry patterns, but they are not real OpenCRVS, OpenSPP, DHIS2,
OpenIMIS, MOSIP, or other product integrations unless an optional live-service
profile explicitly says otherwise.

## Documentation map

Use this README for setup, service ports, and command reference. Use
[`docs/README.md`](docs/README.md) to choose a guided tutorial:

- [Operations posture lab contract](docs/ops-posture-lab-contract.md)
- [OpenFn sidecar Notary tutorial](docs/openfn-sidecar-notary-tutorial.md)
- [OpenCRVS DCI Notary tutorial](docs/opencrvs-dci-notary-tutorial.md)
- [DHIS2 OpenFn Notary tutorial](docs/dhis2-openfn-notary-tutorial.md)
- [Citizen self-attestation eSignet use case](docs/citizen-self-attestation-esignet-use-case.md)
- [Wallet interop testing](docs/wallet-interop-testing.md)
- [Social protection attestation demo refresh spec](docs/social-protection-attestation-demo-refresh-spec.md)
- [Lab 2 governed operations demo spec](docs/lab2-governed-operations-demo-spec.md)

## Topology

- `civil-registry-relay`: CSV-backed civil registry authority on host port `4311`.
- `social-protection-registry-relay`: XLSX-backed social protection authority on host port `4312`.
- `health-registry-relay`: Parquet-backed health authority on host port `4313`.
- `postgres`: live Postgres service for Relay database-source scenarios on host port `54329`.
- `redis`: live Redis service for Notary replay/status storage checks on host port `63799`.
- `zitadel`: live Zitadel IdP for Relay OIDC scenarios on host port `4380`.
- `civil-notary`: civil evidence verifier on host port `4321`.
- `social-protection-notary`: social protection verifier on host port `4322`.
- `shared-eligibility-notary`: cross-authority civil, social, and health verifier on host port `4323`.
- `openfn-civil-notary`: built-in http_json sidecar-backed civil verifier on host port `4324`.
- `openfn-civil-sidecar`: built-in http_json sidecar on the private Compose network.
- `openfn-mock-registry`: registry-like HTTP API on the private OpenFn network.
- `dhis2-health-notary`: optional live DHIS2 health evidence verifier on host port `4326`.
- `openfn-dhis2-sidecar`: optional built-in http_json DHIS2 sidecar on the private Compose network.
- `static-metadata-publisher`: generated static metadata on host port `4331`.

Inside Compose, services use DNS names like
`http://civil-registry-relay:8080` and
`http://shared-eligibility-notary:8080`. Registry Notary containers do
not mount source data. They read registry facts over HTTP from Relay. The demo
client also has no `data/` mount.

## Quick start

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

The service-first metadata path uses the `vendor/registry-manifest` submodule by
default. Override `REGISTRY_MANIFEST_REPO` when you want to test a sibling
checkout or another local path. `just generate` and `just smoke` fail early when
`registry-manifest` is missing.

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

For commons release validation across sibling source checkouts:

```bash
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform \
REGISTRY_MANIFEST_REPO=../registry-manifest \
REGISTRY_RELAY_SOURCE_DIR=../registry-relay \
REGISTRY_NOTARY_SOURCE_DIR=../registry-notary \
just commons-check
```

`commons-check` intentionally uses source dirs instead of `vendor/` pins. Update
Lab vendor or submodule pins only after Platform, Manifest, Relay, and Notary
source changes are committed.

For the first release, keep the two proof paths separate:

- Source proof: run against sibling Platform, Relay, and Notary checkouts with
  `REGISTRY_LAB_RELEASE_SOURCE_MODE=source`. If the sibling commits are not yet
  reflected in Lab `vendor/` pins, also set
  `REGISTRY_LAB_ALLOW_PENDING_PINS=1`; the release source model check will print
  each pending pin or dirty source checkout. This is a pre-tag proof only.
- Lab pin proof: run `scripts/release-check.sh` without
  `REGISTRY_LAB_RELEASE_SOURCE_MODE`. The script forces Platform, Relay, Notary,
  Manifest, and Crosswalk to the committed `vendor/` submodules even when
  sibling checkouts exist. This is the clean-clone/no-sibling release proof.

## Demo commands

List available recipes:

```bash
just
```

Core setup and lifecycle:

```bash
just setup       # initialize submodules
just generate    # write fixtures, .env secrets, and static metadata
just build       # build the default topology
just up          # start Relay, Notary, Postgres, Zitadel, OpenFn, metadata
just ps          # show service status
just logs        # follow all logs
just logs -- zitadel openfn-civil-notary
just down        # stop containers and remove demo volumes
```

Run the default API-key demo:

```bash
just smoke       # API-level smoke for Relay and Notary
just federation  # signed Notary-to-Notary delegated evaluation smoke
just civil       # built-in http_json civil sidecar Notary smoke  (just openfn also works)
just opencrvs-dci # live OpenCRVS DCI-backed Notary smoke
just dhis2       # live DHIS2 health evidence smoke (just dhis2-openfn also works)
just notary-client # Registry Notary Python client smoke against lab Notaries
just evidence-gateway-test # fast Evidence Gateway pack contract checks
just evidence-gateway-crvs-live # live CRVS relay-backed certificate pack check
just client      # narrated default client flow
just quick       # generate, build, up, smoke, openfn, client
```

`just federation` proves the default non-agricultural federation slice. A demo
benefits peer signs compact JWS requests to the civil and social protection
Notaries, verifies their signed responses, composes a local benefit-screen
artifact from `age-band`, `person-is-alive`, `beneficiary-active`, and
`household-eligibility-band`, and writes artifacts to `output/federation/`. It
also proves replay and unsupported-purpose denials without embedding raw
registry rows.

Run the live-service demos:

```bash
just relay-postgres  # Relay ignored Postgres integration test
just relay-zitadel   # Relay ignored Zitadel integration test
just notary-redis   # Notary and Platform live Redis integration tests
just oidc-relay      # separate OIDC-protected Relay node
just esignet-up     # start local MOSIP eSignet for citizen wallet/self-attestation demos
just citizen-login  # print local eSignet login URL
just citizen-code   # exchange returned code and run flow
just citizen-token  # run flow with exported tokens
just citizen-oid4vci-token # optional OID4VCI endpoint probe with exported tokens
```

Run the NAgDI agricultural registries demo:

```bash
just agri-generate  # write agricultural XLSX fixtures, AGRI_* secrets, and static metadata
just agri-build     # build the agricultural Relay, Notary, and metadata publisher
just agri-up        # start the agricultural profile
just agri-smoke     # API-level agricultural smoke and narrated client assertions
just agri-federation # signed Notary-to-Notary delegated evaluation smoke
just agri-client    # narrated agricultural client flow only
just agri-down      # stop agricultural services
```

The agricultural flow expects:

- `agri-registry-relay` on host port `4341`
- `nagdi-agriculture-notary` on host port `4342`
- `agri-static-metadata-publisher` on host port `4343`
- credentials in `.env` named with the `AGRI_*` prefix, including
  `AGRI_METADATA_CLIENT_RAW`, `AGRI_EVIDENCE_ONLY_RAW`,
  `AGRI_ROW_READER_RAW`, `AGRI_AGGREGATE_READER_RAW`, and
  `AGRI_EVIDENCE_CLIENT_BEARER`

The default agricultural smoke/client paths follow the NAgDI spec:

- purpose: `https://demo.example.gov/purpose/nagdi/climate-smart-input-support`
- voucher claim: `eligible-for-climate-smart-input-voucher`
- land-size value claim: `farmer-holding-total-area-hectares`
- positive subject: `FARMER-1001`
- negative subjects: `FARMER-1002`, `FARMER-1003`, `FARMER-1004`
- manual-review subject: `FARMER-1005`
- livestock subjects: `HERD-2001` eligible, `HERD-2002` vaccination denial,
  `HERD-2003` quarantine denial
- default farmer row route:
  `/v1/datasets/agri_registry/entities/farmer/records?limit=1`
- default market-sizing aggregate:
  `/v1/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input`
- default livestock herd aggregate:
  `/v1/datasets/agri_registry/aggregates/livestock_herds_by_species_district`

Agricultural metadata discovery should distinguish the two evidence surfaces:
voucher and livestock eligibility are Registry Notary offerings, while market
sizing and livestock herd planning are Registry Relay aggregate offerings served
from the default aggregate paths above.
The narrated agricultural client also proves demo-grade holder-bound SD-JWT
credential issuance from the successful voucher evaluation. Full wallet or
OID4VCI ceremonies are outside the default agricultural smoke path.

Run the live OpenCRVS DCI demo:

```bash
just opencrvs-dci
```

The OpenCRVS DCI smoke starts `opencrvs-dci-notary` on host port `4352` by
default and evaluates OpenCRVS birth-record claims against the Farajaland
integration DCI API:

- `opencrvs-birth-record-exists`
- `opencrvs-date-of-birth`
- `opencrvs-sex`
- `opencrvs-age-band`
- `opencrvs-child-given-name`
- `opencrvs-child-family-name`
- `opencrvs-child-date-of-birth`
- `opencrvs-child-place-of-birth`

It then issues a demo `application/dc+sd-jwt` VC with credential profile
`opencrvs_birth_attributes_sd_jwt`. The full response is written to
`output/opencrvs-dci/credential.json`.

The current OpenCRVS DCI evidence path is UIN-backed. Demographic matching is
tracked as not implemented in the Evidence Gateway pack metadata until a
configured claim and live fixture prove unique-match, no-match, and
multiple-match behavior.

Put the live OpenCRVS values in `.env.local`, which is ignored by Git:

```bash
OPENCRVS_DCI_CLIENT_ID='<client id>'
OPENCRVS_DCI_CLIENT_SECRET='<client secret>'
OPENCRVS_DCI_SHA_SECRET='<sha secret, reserved for signed-request testing>'
OPENCRVS_EVIDENCE_CLIENT_TOKEN='api-token'
OPENCRVS_DCI_NOTARY_PORT=4352
```

Registry Notary fetches OpenCRVS source tokens with OAuth client credentials.
The smoke script also fetches a short-lived token to discover a seeded demo UIN
when `OPENCRVS_DEMO_SUBJECT_UIN` is unset, but it does not store that token.
It derives local Registry Notary API-key hashes from the corresponding token
values when the hash env vars are unset or still contain placeholder zero
digests.
Set `OPENCRVS_DEMO_SUBJECT_UIN` locally for a fixed smoke subject.

The VC profile uses `holder_binding.mode: none` so the lab can show direct
machine-to-machine issuance without wallet ceremony. Use a holder-bound
`did:jwk` proof profile before presenting this as citizen-wallet issuance.
See [`docs/opencrvs-dci-notary-tutorial.md`](docs/opencrvs-dci-notary-tutorial.md)
for the non-developer step-by-step walkthrough.
See [`docs/evidence-gateway-packs.md`](docs/evidence-gateway-packs.md) for pack
IDs, binding IDs, implemented inputs, and focused test commands, including the
local CRVS relay-backed certificate pack check.

`just agri-federation` proves the first Registry Notary federation slice. The
demo benefits peer signs compact JWS requests to
`POST /federation/v1/evaluations` on `nagdi-agriculture-notary`, verifies the
signed responses, composes a local benefits decision from the returned
predicates, and writes artifacts to `output/agri-federation/`. It also proves a
replay denial and an unsupported-purpose denial. This is delegated evaluation
only: it does not enable open federation, outbound Notary composition, or
federated credential issuance.

Use environment overrides such as `AGRI_RELAY_URL`, `AGRI_WITNESS_URL`,
`AGRI_STATIC_METADATA_URL`, `AGRI_FARMER_DATASET`, `AGRI_FARMER_ENTITY`,
`AGRI_INPUT_VOUCHER_CLAIM`, `AGRI_MARKET_SIZING_PATH`,
`AGRI_LIVESTOCK_AGGREGATE_PATH`, or `AGRI_SUPPRESSED_AGGREGATE_PATH` if the
agricultural Relay config names differ.
`just agri-smoke` writes artifacts to `output/agri-smoke/` and also runs the
narrated client, which writes to `output/agri-client/`.

Run the broader checks:

```bash
just try          # standard demo sequence, leaves containers up
just evidence-gateway-test # fast Evidence Gateway pack contract checks
just evidence-gateway-crvs-live # live CRVS relay-backed certificate pack check
just release      # full release check, cleans up volumes on success
just release-fast # release check without slower live-service extras
```

The release wrapper ends with `docker compose -f compose.yaml down -v`, so it
removes demo volumes after a successful run. Use the individual checks above
when you want to keep the current Postgres, Zitadel, or OpenFn containers
running for inspection.

The `justfile` defaults `REGISTRY_RELAY_SOURCE_DIR`,
`REGISTRY_NOTARY_SOURCE_DIR`, and `REGISTRY_PLATFORM_SOURCE_DIR` to sibling
checkouts when present, otherwise to the pinned `vendor/` submodules.
`REGISTRY_OPENFN_NOTARY_SOURCE_DIR` follows `REGISTRY_NOTARY_SOURCE_DIR` by
default. Override those variables when you want to build from another local
path.

## Live Notary Redis checks

The lab includes a Redis service so the Redis-backed replay and credential
status paths can be tested against a real backend without requiring a local
Redis install:

```bash
just notary-redis
```

That recipe starts the `redis` Compose service, waits for `redis-cli ping`, and
runs the focused live Redis tests from sibling `registry-platform` and
`registry-notary` checkouts with
`REGISTRY_PLATFORM_REDIS_TEST_URL=redis://127.0.0.1:63799/`. Override
`REGISTRY_LAB_REDIS_PORT`, `REGISTRY_PLATFORM_SOURCE_DIR`, or
`REGISTRY_NOTARY_SOURCE_DIR` if your local layout differs. Inside Compose,
Notary containers also receive `REGISTRY_NOTARY_REDIS_URL=redis://redis:6379/`
for configs that opt into Redis-backed storage.

## Live Relay scenarios

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
citizen-facing Registry Notary on port `4325`. It supports either a JWT access
token carrying the subject-binding claim and `auth_time`, or the eSignet-style
split where UserInfo carries the subject claim and the ID token carries
`auth_time`/`acr`. For stock local eSignet tokens that omit `scope`, the demo
uses `ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled` and relies on issuer,
client/audience, assurance, and subject binding instead. If a live eSignet
profile uses a separate signed UserInfo issuer, mixed token/UserInfo algorithms,
missing access-token `typ`, or a 1200s token lifetime, the script detects or
accepts explicit env overrides for those settings. The script generates
`output/citizen-self-attestation/citizen-civil-notary.yaml`, starts a host-side
Notary against the existing civil Relay, evaluates `person-is-alive` for the
token-bound citizen, and proves `NID-1002` is denied by subject binding. See
`output/citizen-self-attestation/report.md` and
`output/citizen-self-attestation/flow-transcript.txt` for the evidence trail,
and `docs/citizen-self-attestation-esignet-use-case.md` for the use case and
setup details. The lab intentionally keeps raw demo tokens, decoded claims, and
seeded civil IDs in `output/` for replay and debugging, so treat the directory
as sensitive local evidence.

For the local eSignet profile used by the lab, prefer the Just wrappers:

```bash
just esignet-up
just citizen-login
```

`just esignet-up` starts a separate MOSIP eSignet Compose project from
`compose.esignet-live.yaml`: eSignet on port `8088`, the browser UI on port
`3000`, mock identity on port `8082`, and a Postgres database on port `5455`.
It also seeds the `registry-lab-live-client` OIDC client and writes the matching
demo private key to `output/esignet-live/client-private.pem`. The mock identity
store is seeded with the civil fixture people `NID-1001` through `NID-1009`;
the local generated code is `111111`, and the static PIN is `545411`.

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

`citizen-code` reads the saved callback code. It uses
`output/esignet-live/client-private.pem` from `just esignet-up` when present,
falls back to `/tmp/esignet-live-test/client-private.pem` for older local
stacks, or accepts `ESIGNET_CLIENT_PRIVATE_KEY_FILE=/path/to/client-private-key.pem`.
The command narrates the verified token metadata, UserInfo subject binding,
Notary discovery, successful self claim, other-person denial, and audit check
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
same citizen eSignet login/code/token flow, starts the citizen Notary with an
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
matching the Notary nonce replay checks. To test the same facade with Walt
Wallet API or Inji/Mimoto, see `docs/wallet-interop-testing.md`.

## Built-in sidecar civil demo

The civil sidecar nodes prove the Registry Notary `openfn_sidecar` connector can
source one-item civil lookups from a built-in `http_json` sidecar and issue a
date-of-birth SD-JWT VC from that evidence. For the guided path, see
[`docs/openfn-sidecar-notary-tutorial.md`](docs/openfn-sidecar-notary-tutorial.md).

```bash
just generate
just build
just up
just civil
```

(`just openfn` is a backwards-compatible alias for `just civil`.)

The build uses `REGISTRY_OPENFN_NOTARY_SOURCE_DIR`, which follows
`REGISTRY_NOTARY_SOURCE_DIR` unless overridden.

The civil sidecar is part of the default Compose topology. The sidecar and mock
registry are not published to host ports; they run only on the private
`openfn-internal` network. `scripts/smoke-civil.sh` recreates the three
containers with `--force-recreate --remove-orphans` so repeated local runs do
not get stuck on stale Compose container IDs.

The smoke writes `output/smoke-openfn-notary-evaluation.json`,
`output/smoke-openfn-vc-evaluation.json`, and
`output/smoke-openfn-credential-summary.json`. The sidecar is not published to
the host; use the Notary API for evidence and credential requests:

```bash
set -a
. ./.env
set +a

curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/openfn-sidecar-demo" \
  http://127.0.0.1:4324/v1/evaluations \
  --data '{"target":{"type":"Person","identifiers":[{"scheme":"national_id","value":"person-123"}]},"claims":["date-of-birth"],"disclosure":"value","format":"application/vnd.registry-notary.claim-result+json"}' | jq
```

## Live DHIS2 demo

The optional DHIS2 profile uses the public DHIS2 2.43 demo at
`https://play.im.dhis2.org/stable-2-43-0` through the built-in `http_json`
engine against the DHIS2 Tracker API. It keeps the sidecar private on the Compose
network and exposes only the Registry Notary API on host port `4326`.
Because the DHIS2 demo is a live public sandbox, this smoke is outside
`just quick` and may need sample subject refreshes if the upstream demo data is
reset.

For the guided path, see
[`docs/dhis2-openfn-notary-tutorial.md`](docs/dhis2-openfn-notary-tutorial.md).

```bash
just generate
just build
just dhis2
```

(`just dhis2-openfn` is a backwards-compatible alias for `just dhis2`.)

The DHIS2 Notary exposes four health predicate claims:

- `dhis2-child-program-active`
- `dhis2-maternal-pnc-active`
- `dhis2-child-health-visit-recorded`
- `dhis2-tb-program-active`

For the credential path it also exposes two value claims from the same DHIS2
tracked entity:

- `dhis2-tracked-entity-first-name`
- `dhis2-tracked-entity-last-name`

The smoke writes positive and negative predicate responses under
`output/dhis2-openfn/smoke-dhis2-*.json`, then issues a demo
`application/dc+sd-jwt` credential with profile `dhis2_child_program_sd_jwt` at
`output/dhis2-openfn/smoke-dhis2-child-program-credential.json`.

Generated artifacts are written to `output/`. Generated static publication
files are written under `static-metadata/`. Both directories keep only their
`.gitignore` files in git.

This lab does not call OOTS Evidence Broker or Data Service Directory services.
Those remain future cross-border integration points rather than hidden demo
behavior.

## Hosted Citizen Services Portal

The hosted Citizen Services Portal is published at
`https://portal.lab.registrystack.org/` with `PORTAL_PROVIDER=mock`. Its proof
feed uses the public-link posture from the hosted integration spec: Option B,
scoped per opaque `solmara_session`. Each browser session replays only its own
redacted proof traces, abandoned feed buckets are reclaimed with TTL/LRU cleanup,
and the SSE route disables proxy buffering with `X-Accel-Buffering: no`.

## Governed configuration baseline

The committed Relay and Notary YAML files remain simple static configs. They
include local `config_trust` state paths and a one-per-hour break-glass rate
limit. They do not include `accepted_roots`; signed governed apply stays disabled
until an opt-in Lab 2 flow renders demo configs with generated TUF roots under
`output/lab2/`.

Relay stores that local trust state in its existing per-service cache volumes.
Notary stores it in the `notary-config-state` volume mounted at
`/var/lib/registry-notary/config-state`.

Use `just lab2-demo` for a narrated operator-facing walkthrough. It resets only
Lab 2 containers and volumes, renders governed config, starts the overlay, shows
before/after posture and credential issuance, applies a signed Relay metadata
owner change that is visible through posture, rotates the Notary signing key,
proves threshold guardrails, and writes the transcript to
`output/lab2/evidence/demo/story.md`. Set `LAB2_DEMO_PAUSE=1` to pause between
steps.

Use `just lab2-smoke` for the exhaustive gate. Use `just lab2-demo-reset` to
remove only Lab 2 containers and volumes, and `just lab2-demo-open-evidence` to
open the latest story file.

Use `just lab2-doctor` after `just lab2-up` to capture Registry Relay and
Registry Notary deployment-profile doctor reports for the running Lab 2
topology. It defaults to `LAB2_DOCTOR_PROFILE=hosted_lab` and writes redacted
JSON under `output/lab2/evidence/doctor/`. Set `LAB2_DOCTOR_STRICT=1` when the
selected profile should be treated as a gate instead of an operator review.

The Bruno API workspace also includes a local-only `40 - Lab 2 Governed Config`
folder for stepping through the governed apply story request by request. Open
`requests/registry-lab/` in Bruno, select the `Local Lab 2` environment, and
paste the Lab 2 tokens from `.env`. See `requests/registry-lab/README.md` for
the full setup sequence, which starts with `just generate` before
`just lab2-generate` and `just lab2-up`.

## Source repositories

This demo keeps runtime orchestration, fixtures, static metadata config, and
walkthrough scripts in this repository. Supporting source repositories are
submodules under `vendor/`:

- `vendor/registry-platform`: shared platform crates used by Relay and Notary.
- `vendor/registry-relay`: Relay source used by `Dockerfile.registry-relay`.
- `vendor/registry-notary`: Registry Notary source used by
  `Dockerfile.registry-notary`.
- `vendor/registry-manifest`: static metadata publishing CLI and profiles.

The Compose build uses Docker named contexts so local source checkouts can be
used without changing `compose.yaml`:

```bash
REGISTRY_RELAY_SOURCE_DIR=../registry-relay \
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform \
REGISTRY_NOTARY_SOURCE_DIR=../registry-notary \
CROSSWALK_SOURCE_DIR=../crosswalk \
just build
```

`just lab2-up` uses the same source selection model through `compose.lab2.yaml`.
That makes Lab 2 useful as a pre-pin regression pass against sibling Relay,
Notary, and Platform checkouts. `just lab2-generate` also rewrites a temporary
tool manifest when `REGISTRY_PLATFORM_SOURCE_DIR` points outside the vendored
Platform submodule, so generated governed artifacts can be checked against a
Platform source checkout. For release evidence, keep using `scripts/release-check.sh`
in `vendor` mode or pin the `vendor/` submodules before tagging.

Use the same variables with `scripts/generate-demo-secrets.py` when you want
that script to use a sibling Relay checkout instead of the
`vendor/registry-relay` submodule. `scripts/publish-static-metadata.sh` uses
the Registry Manifest CLI from `REGISTRY_MANIFEST_REPO`, defaulting to the
`vendor/registry-manifest` submodule. For a release, pin the submodules to
commits that already include the Registry Platform, Registry Relay, and Registry
Notary behavior required by this demo.

OpenFn image builds can use `REGISTRY_OPENFN_NOTARY_SOURCE_DIR` separately from
the core Notary image. The lab default points OpenFn at the selected Notary
source, so local source checkouts can be tested before the lab submodule pin
moves.

`scripts/check-release-source-model.sh source` compares sibling Platform,
Relay, and Notary SHAs with the Lab `vendor/` pins and fails on mismatches or
dirty source checkouts. Use `REGISTRY_LAB_ALLOW_PENDING_PINS=1` only while the
final source commits are still waiting for the Lab submodule pin update.
`scripts/check-release-source-model.sh vendor` proves that the selected release
paths resolve to committed Lab pins.

`just notary-client` imports the Registry Notary Python client directly from a
source checkout and runs it against the default lab Notary services. It looks at
`REGISTRY_NOTARY_CLIENT_SOURCE_DIR` first, then `REGISTRY_NOTARY_SOURCE_DIR`,
then `../registry-notary`, and finally `vendor/registry-notary`. Use
`REGISTRY_NOTARY_CLIENT_SOURCE_DIR` when validating a client SDK branch before
the lab submodule pin has moved. This smoke is explicit and is not part of
`just quick`.

## Fixture data

`scripts/generate-fixtures.py` is the source of truth for the synthetic CSV,
XLSX, and Parquet extracts. It writes a small but non-trivial fixture set:

- civil registry CSV: children, caregivers, living adults, and deceased adults
  across five districts, plus event-level person details, identifiers, birth
  events, death events, civil status records, certificates, and relationships;
- social protection XLSX: households, household members, memberships,
  socio-economic profiles, scoring events, programmes, enrollments,
  entitlements, payments, functioning profiles, and disability determinations
  with active, inactive, suspended, stale, expired, review-required, and
  policy-denied cases;
- health registry Parquet: an applicant service availability projection with
  active, suspended, pending-renewal, and partially-serviceable facilities.

The generator validates key coverage before writing files so the demo keeps a
successful subject, failed predicates, ambiguous demographic matches, stale
or expired source facts, policy-denied cases, deceased-member cases,
cross-source subjects, and health-linked support cases.

The shared OpenSPP and Registry Lab v1 subject matrix is:

| ID | Story person | Type | Civil | Social protection | Health | Notary purpose |
| --- | --- | --- | --- | --- | --- | --- |
| `NID-1001` | Miguel Santos | child | alive | active | available | happy path combined support |
| `NID-1002` | Maria Dela Cruz | child | alive | inactive | unavailable | social or health negative |
| `NID-1003` | dedicated negative-control persona | adult | deceased | review/none | available | civil negative control |
| `NID-1004` | Rafael Aquino | child | alive | active | available | single-parent household positive |
| `NID-1005` | Rosalie Bautista | child | alive | active | partial health | large family mixed case |
| `NID-1006` | Miguel Martinez | child | alive | active | available | disability support story |
| `NID-1007` | Lola Santos | elderly | alive | inactive | available | elderly age-band and pension story |
| `NID-1008` | Rosa Garcia | elderly | alive | active | available | individual elderly positive |
| `NID-1009` | Ana Mendoza | adult | alive | none | available | registered adult, not social-active |
| `NID-1010` | Pedro Reyes | adult | alive | none | unavailable | community leader negative |

Expected Registry Notary outcomes:

| Claim | Positive IDs | Negative IDs |
| --- | --- | --- |
| `person-is-alive` | `NID-1001`, `NID-1002`, `NID-1004`, `NID-1005`, `NID-1006`, `NID-1007`, `NID-1008`, `NID-1009`, `NID-1010` | `NID-1003` |
| `health-service-available` | `NID-1001`, `NID-1003`, `NID-1004`, `NID-1006`, `NID-1007`, `NID-1008`, `NID-1009` | `NID-1002`, `NID-1005`, `NID-1010` |
| `eligible-for-combined-support` | `NID-1001`, `NID-1004`, `NID-1006`, `NID-1008` | `NID-1002`, `NID-1003`, `NID-1005`, `NID-1007`, `NID-1009`, `NID-1010` |

Regenerate aligned local fixtures with `just generate`. For release validation,
run `scripts/release-check.sh`. The release check runs the default smoke,
federation, Notary client, narrated client, and selected live-service checks.

## Credentials

`scripts/generate-demo-secrets.py` writes `.env` with local demo credentials and
matching SHA-256 fingerprints for Relay, Notary, and OpenFn sidecar auth. The
committed `.env.example` contains inert examples only.

By default, the script updates only local demo configs under `config/relay/` and
`config/notary/`. It intentionally leaves hosted Coolify configs byte-identical
because those commitments must match the live Coolify credential fingerprints.
Use `--include-hosted` only when rotating hosted credentials and installing the
matching raw values and fingerprints in Coolify in the same deployment change.

Credential classes:

- metadata client tokens for each Relay;
- evidence source tokens used by Registry Notary instances when calling Relay;
- evidence-only Relay tokens used to prove verification scope does not imply
  row or aggregate access;
- row-reader tokens for the explicit positive row-read check;
- aggregate-reader tokens for the aggregate consultation;
- OpenFn sidecar tokens, stored as raw caller tokens plus `OPENFN_SIDECAR_TOKEN_HASH`;
- OpenFn mock registry target tokens, used only inside the private OpenFn network;
- separate Registry Notary client API keys and bearer tokens;
- distinct shared Registry Notary source tokens for civil, social, and health;
- per-deployment audit hash secrets for Relay and Notary redaction.

The social protection Relay config keeps row and aggregate scopes on separate
credentials so the smoke flow can prove row-reader credentials cannot run the
aggregate endpoint. Civil and health aggregate credentials are generated for
future symmetry but are not used by the v1 walkthrough.

Relay and Registry Notary auth configs should reference only `*_HASH` env vars.
Registry Notary upstream source connections still reference raw `token_env`
names for outbound calls to Relay. The OpenFn sidecar auth config also requires
`OPENFN_SIDECAR_TOKEN_HASH`; plaintext sidecar token config is rejected. No raw
token should be committed.

## Static metadata

`scripts/publish-static-metadata.sh` runs
`registry-manifest-cli publish` from `REGISTRY_MANIFEST_REPO`, defaulting to the
`../registry-manifest` sibling checkout, and publishes the portable manifest at
`config/static-metadata/metadata.yaml` into `static-metadata/metadata/`. The
publisher serves it at paths such as:

- `http://127.0.0.1:4331/.well-known/api-catalog`
- `http://127.0.0.1:4331/metadata/index.json`
- `http://127.0.0.1:4331/metadata/cpsv-ap.jsonld`
- `http://127.0.0.1:4331/metadata/catalog.json`
- `http://127.0.0.1:4331/metadata/evidence-offerings.json`
- `http://127.0.0.1:4331/metadata/policies.jsonld`

The static bundle is generated from portable metadata, not scraped from a
running Relay. It must not include source paths, table ids, scopes, cache paths,
or backend runtime details.

For the hosted lab, Coolify builds `Dockerfile.static-metadata`, which generates
this bundle with `registry-manifest-cli publish` from the pinned
`registry-manifest` ref in `compose.coolify.yaml`.

## Demo flow

`scripts/demo-flow.py` narrates five scenarios:

1. Birth Registration To Child Support: Registry Notary verifies civil facts and
   issues a demo-grade credential without exposing raw civil rows.
2. Household Benefit Review From Registry Data: the client performs a protected
   Relay row read, dataset-scoped aggregate consultation, and OGC EDR `/area`
   aggregate over configured district geometries with `Data-Purpose`, then
   writes a demo household-benefit decision artifact without writing back to
   Relay.
3. Governed Purpose Policy Denial: the client repeats a protected household row
   read with an unapproved `Data-Purpose` and captures the stable denial.
4. Governed Field Redaction: Registry Notary returns a household summary object
   while policy redacts `national_id` and `poverty_score` without downgrading
   the whole value disclosure.
5. Cross-Authority Conditional Support: static metadata leads the client to a
   shared Registry Notary claim that depends on civil, social protection, and
   health authorities.

Every client request sends `x-request-id` using
`decentralized-demo-correlation-001` by default and saves JSON artifacts.

## Notes

The Relay demo image is built by `Dockerfile.registry-relay` with configurable
Cargo features. Docker Compose and the `just` recipes default to
`spdci-api-standards,standards-cel-mapping,ogcapi-edr` so DCI source routes and
the aggregate-only OGC EDR `/area` surface are available. Set
`REGISTRY_RELAY_FEATURES` explicitly when using a different Relay source.
The lab Relay image follows the product distroless runtime policy and its
healthcheck uses `registry-relay healthcheck`; do not add `curl`, `wget`, or
shell-dependent probes to the Relay image.
Before applying `compose.coolify.yaml`, publish a Relay image built from a
source revision that includes that healthcheck command and refresh the
`REGISTRY_RELAY_IMAGE` Coolify env var. The compose digest is only the fallback
used when that env var is unset.

The social protection walkthrough uses the dataset-scoped aggregate endpoint at
`/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band`
and the EDR collection at
`/ogc/edr/v1/collections/social_protection_households_by_district`.

Registry Lab configures Relay and Registry Notary to expose API docs at `/docs`
and demo OpenAPI at `/openapi.json` without credentials. Data, metadata, claim,
and evidence routes still use the configured demo credentials.
