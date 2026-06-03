set dotenv-load := true
set positional-arguments := true

default_relay_src := if path_exists("../registry-relay/Cargo.toml") == "true" { "../registry-relay" } else { "./vendor/registry-relay" }
default_notary_src := if path_exists("../registry-notary/Cargo.toml") == "true" { "../registry-notary" } else { "./vendor/registry-notary" }
default_platform_src := if path_exists("../registry-platform/Cargo.toml") == "true" { "../registry-platform" } else { "./vendor/registry-platform" }
default_atlas_src := if path_exists("../registry-atlas/Cargo.toml") == "true" { "../registry-atlas" } else { "./vendor/registry-atlas" }

relay_src := env_var_or_default("REGISTRY_RELAY_SOURCE_DIR", default_relay_src)
notary_src := env_var_or_default("REGISTRY_NOTARY_SOURCE_DIR", default_notary_src)
openfn_notary_src := env_var_or_default("REGISTRY_OPENFN_NOTARY_SOURCE_DIR", notary_src)
platform_src := env_var_or_default("REGISTRY_PLATFORM_SOURCE_DIR", default_platform_src)
atlas_src := env_var_or_default("REGISTRY_ATLAS_SOURCE_DIR", default_atlas_src)
manifest_src := env_var_or_default("REGISTRY_MANIFEST_REPO", "./vendor/registry-manifest")
cel_mapping_src := env_var_or_default("CEL_MAPPING_SOURCE_DIR", "./vendor/cel-mapping")
relay_features := env_var_or_default("REGISTRY_RELAY_FEATURES", "spdci-api-standards,standards-cel-mapping,ogcapi-edr")

export REGISTRY_RELAY_SOURCE_DIR := relay_src
export REGISTRY_NOTARY_SOURCE_DIR := notary_src
export REGISTRY_OPENFN_NOTARY_SOURCE_DIR := openfn_notary_src
export REGISTRY_PLATFORM_SOURCE_DIR := platform_src
export REGISTRY_RELAY_PLATFORM_SOURCE_DIR := platform_src
export REGISTRY_NOTARY_PLATFORM_SOURCE_DIR := platform_src
export REGISTRY_MANIFEST_REPO := manifest_src
export REGISTRY_ATLAS_SOURCE_DIR := atlas_src
export CEL_MAPPING_SOURCE_DIR := cel_mapping_src
export REGISTRY_RELAY_FEATURES := relay_features

# List available demo commands.
default:
    @just --list

# Initialize git submodules.
setup:
    git submodule update --init --recursive

# Generate deterministic fixtures, demo secrets, and static metadata.
generate:
    uv run scripts/generate-fixtures.py
    scripts/generate-demo-secrets.py
    scripts/ensure-postgres-ssl.sh
    scripts/publish-static-metadata.sh

# Build the default demo topology.
build:
    docker compose -f compose.yaml build

# Start the default demo topology.
up:
    docker compose -f compose.yaml up -d

# Stop containers and remove demo volumes.
down:
    docker compose -f compose.yaml down -v

# Start the local MOSIP eSignet stack used by citizen wallet/self-attestation demos.
esignet-up:
    docker compose -f compose.esignet-live.yaml up -d

# Stop the local MOSIP eSignet stack and remove its demo volumes.
esignet-down:
    docker compose -f compose.esignet-live.yaml down -v

# Follow local MOSIP eSignet logs. Pass service names after `--`, for example: just esignet-logs -- esignet esignet-seed
esignet-logs *services:
    docker compose -f compose.esignet-live.yaml logs -f {{services}}

# Show running demo services.
ps:
    docker compose -f compose.yaml ps

# Follow demo service logs. Pass service names after `--`, for example: just logs -- zitadel openfn-civil-notary
logs *services:
    docker compose -f compose.yaml logs -f {{services}}

# Run the API-key Relay/Notary smoke.
smoke:
    scripts/smoke.sh

# Run the default signed Notary-to-Notary delegated-evaluation smoke.
federation:
    scripts/smoke-federation.sh

# Run the narrated default client flow.
client:
    docker compose -f compose.yaml --profile client run --rm demo-client

# Run the Registry Notary Python client against the default Notary services.
notary-client:
    scripts/smoke-notary-client.py

# Run the OpenFn sidecar smoke.
openfn:
    scripts/smoke-openfn.sh

# Run the live DHIS2 OpenFn sidecar smoke.
dhis2-openfn:
    scripts/smoke-dhis2-openfn.sh

# Run the live OpenCRVS DCI-backed Notary smoke.
opencrvs-dci:
    scripts/smoke-opencrvs-dci.sh

# Run Relay's ignored live Postgres integration test against lab Postgres.
relay-postgres:
    scripts/check-relay-postgres.sh

# Run Relay's ignored live Zitadel integration test against lab Zitadel.
relay-zitadel:
    scripts/check-relay-zitadel.sh

# Run Notary and Platform live Redis tests against lab Redis.
notary-redis:
    scripts/check-notary-redis.sh

# Run cross-repository commons release checks against sibling source dirs.
commons-check:
    scripts/commons-check.sh

# Run the OIDC Relay smoke with a lab-managed Zitadel token.
oidc-relay:
    scripts/smoke-oidc-relay.sh

# Run the optional eSignet-backed citizen self-attestation Notary smoke.
citizen-self-attestation:
    scripts/smoke-citizen-self-attestation.sh

# Validate hosted Coolify compose artifacts before deployment.
hosted-validate:
    docker compose -f compose.coolify.yaml config >/dev/null
    REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD="${REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD:-hosted-validation-placeholder}" docker compose -f compose.esignet-hosted.yaml config >/dev/null
    REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD="${REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD:-hosted-validation-placeholder}" uv run scripts/validate-hosted-deploy.py

# Validate hosted artifacts and require real secret values in the current environment.
hosted-validate-strict:
    docker compose -f compose.coolify.yaml config >/dev/null
    REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD="${REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD:-hosted-validation-placeholder}" docker compose -f compose.esignet-hosted.yaml config >/dev/null
    uv run scripts/validate-hosted-deploy.py --require-secret-values

# Run focused tests for hosted deployment validation.
hosted-validate-test:
    python3 scripts/test_validate_hosted_deploy.py

# Validate the committed public Bruno API workspace.
api-workspace-validate:
    python3 scripts/validate-public-api-workspace.py

# Run focused tests for public API workspace validation.
api-workspace-validate-test:
    python3 scripts/test_validate_public_api_workspace.py

# Print the local eSignet authorization URL and save PKCE state.
citizen-self-attestation-esignet-login:
    @set +e; \
    ESIGNET_ISSUER=http://localhost:8088 \
    ESIGNET_DISCOVERY_URL=http://localhost:8088/v1/esignet/oidc/.well-known/openid-configuration \
    ESIGNET_AUTHORIZATION_URL=http://localhost:3000/authorize \
    ESIGNET_JWKS_URI=http://localhost:8088/v1/esignet/oauth/.well-known/jwks.json \
    ESIGNET_USERINFO_ENDPOINT=http://localhost:8088/v1/esignet/oidc/userinfo \
    ESIGNET_CLIENT_ID=registry-lab-live-client \
    ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo \
    ESIGNET_SUBJECT_CLAIM=individual_id \
    ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token \
    ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled \
    ESIGNET_AUTHORIZE_SCOPE='openid profile' \
    ESIGNET_AUTHORIZE_ACR_VALUES=mosip:idp:acr:generated-code \
    ESIGNET_AUTHORIZE_PROMPT=login \
    ESIGNET_AUTHORIZE_DISPLAY=popup \
    ESIGNET_CLAIMS_LOCALES=en \
    ESIGNET_MAX_AUTH_AGE_SECONDS=1200 \
    ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS=1200 \
    ESIGNET_CAPTURE_CALLBACK_HINT=1 \
    ESIGNET_CITIZEN_ACCESS_TOKEN= \
    ESIGNET_CITIZEN_ID_TOKEN= \
    ESIGNET_AUTHORIZATION_CODE= \
    scripts/smoke-citizen-self-attestation.sh; \
    status=$?; \
    if [ "$status" -eq 2 ]; then scripts/capture-esignet-callback.py; exit 0; fi; \
    exit "$status"

# Exchange the returned eSignet code and run the citizen self-attestation smoke.
citizen-self-attestation-esignet-code:
    @test -n "${ESIGNET_AUTHORIZATION_CODE:-}" || test -f output/citizen-self-attestation/esignet-callback.env || (echo "Run just citizen-login first, or set ESIGNET_AUTHORIZATION_CODE." >&2; exit 1)
    @test -n "${ESIGNET_CLIENT_PRIVATE_KEY_FILE:-}" || test -f output/esignet-live/client-private.pem || test -f /tmp/esignet-live-test/client-private.pem || (echo "Run just esignet-up, or set ESIGNET_CLIENT_PRIVATE_KEY_FILE to the client RSA private key." >&2; exit 1)
    @set -a; \
    if [ -z "${ESIGNET_AUTHORIZATION_CODE:-}" ] && [ -f output/citizen-self-attestation/esignet-callback.env ]; then . output/citizen-self-attestation/esignet-callback.env; fi; \
    if [ -z "${ESIGNET_CLIENT_PRIVATE_KEY_FILE:-}" ] && [ -f output/esignet-live/client-private.pem ]; then ESIGNET_CLIENT_PRIVATE_KEY_FILE=output/esignet-live/client-private.pem; fi; \
    if [ -z "${ESIGNET_CLIENT_PRIVATE_KEY_FILE:-}" ] && [ -f /tmp/esignet-live-test/client-private.pem ]; then ESIGNET_CLIENT_PRIVATE_KEY_FILE=/tmp/esignet-live-test/client-private.pem; fi; \
    set +a; \
    ESIGNET_ISSUER=http://localhost:8088 \
    ESIGNET_DISCOVERY_URL=http://localhost:8088/v1/esignet/oidc/.well-known/openid-configuration \
    ESIGNET_AUTHORIZATION_URL=http://localhost:3000/authorize \
    ESIGNET_JWKS_URI=http://localhost:8088/v1/esignet/oauth/.well-known/jwks.json \
    ESIGNET_USERINFO_ENDPOINT=http://localhost:8088/v1/esignet/oidc/userinfo \
    ESIGNET_CLIENT_ID=registry-lab-live-client \
    ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo \
    ESIGNET_SUBJECT_CLAIM=individual_id \
    ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token \
    ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled \
    ESIGNET_AUTHORIZE_SCOPE='openid profile' \
    ESIGNET_AUTHORIZE_ACR_VALUES=mosip:idp:acr:generated-code \
    ESIGNET_AUTHORIZE_PROMPT=login \
    ESIGNET_AUTHORIZE_DISPLAY=popup \
    ESIGNET_CLAIMS_LOCALES=en \
    ESIGNET_MAX_AUTH_AGE_SECONDS=1200 \
    ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS=1200 \
    scripts/smoke-citizen-self-attestation.sh

# Run the local eSignet citizen smoke with ESIGNET_CITIZEN_ACCESS_TOKEN and ESIGNET_CITIZEN_ID_TOKEN from the environment.
citizen-self-attestation-esignet-token:
    @test -n "${ESIGNET_CITIZEN_ACCESS_TOKEN:-}" || (echo "Set ESIGNET_CITIZEN_ACCESS_TOKEN." >&2; exit 1)
    @test -n "${ESIGNET_CITIZEN_ID_TOKEN:-}" || (echo "Set ESIGNET_CITIZEN_ID_TOKEN." >&2; exit 1)
    @ESIGNET_ISSUER=http://localhost:8088 \
    ESIGNET_DISCOVERY_URL=http://localhost:8088/v1/esignet/oidc/.well-known/openid-configuration \
    ESIGNET_AUTHORIZATION_URL=http://localhost:3000/authorize \
    ESIGNET_JWKS_URI=http://localhost:8088/v1/esignet/oauth/.well-known/jwks.json \
    ESIGNET_USERINFO_ENDPOINT=http://localhost:8088/v1/esignet/oidc/userinfo \
    ESIGNET_CLIENT_ID=registry-lab-live-client \
    ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo \
    ESIGNET_SUBJECT_CLAIM=individual_id \
    ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token \
    ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled \
    ESIGNET_AUTHORIZE_SCOPE='openid profile' \
    ESIGNET_AUTHORIZE_ACR_VALUES=mosip:idp:acr:generated-code \
    ESIGNET_AUTHORIZE_PROMPT=login \
    ESIGNET_AUTHORIZE_DISPLAY=popup \
    ESIGNET_CLAIMS_LOCALES=en \
    ESIGNET_MAX_AUTH_AGE_SECONDS=1200 \
    ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS=1200 \
    scripts/smoke-citizen-self-attestation.sh

# Show the latest citizen self-attestation evidence report.
citizen-self-attestation-report:
    less output/citizen-self-attestation/report.md

# Wait for the eSignet browser redirect and save the callback code.
citizen-self-attestation-callback:
    scripts/capture-esignet-callback.py

# Print the local eSignet citizen login URL.
citizen-login: citizen-self-attestation-esignet-login

# Exchange the local eSignet callback code and run the citizen flow.
citizen-code: citizen-self-attestation-esignet-code

# Run the local eSignet citizen flow with exported tokens.
citizen-token: citizen-self-attestation-esignet-token

# Show the latest local eSignet citizen evidence report.
citizen-report: citizen-self-attestation-report

# Wait for the local eSignet citizen callback.
citizen-callback: citizen-self-attestation-callback

# Print the local eSignet login URL for the optional citizen OID4VCI probe.
citizen-oid4vci-login:
    @set +e; \
    ESIGNET_ISSUER=http://localhost:8088 \
    ESIGNET_DISCOVERY_URL=http://localhost:8088/v1/esignet/oidc/.well-known/openid-configuration \
    ESIGNET_AUTHORIZATION_URL=http://localhost:3000/authorize \
    ESIGNET_JWKS_URI=http://localhost:8088/v1/esignet/oauth/.well-known/jwks.json \
    ESIGNET_USERINFO_ENDPOINT=http://localhost:8088/v1/esignet/oidc/userinfo \
    ESIGNET_CLIENT_ID=registry-lab-live-client \
    ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo \
    ESIGNET_SUBJECT_CLAIM=individual_id \
    ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token \
    ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled \
    ESIGNET_AUTHORIZE_SCOPE='openid profile' \
    ESIGNET_AUTHORIZE_ACR_VALUES=mosip:idp:acr:generated-code \
    ESIGNET_AUTHORIZE_PROMPT=login \
    ESIGNET_AUTHORIZE_DISPLAY=popup \
    ESIGNET_CLAIMS_LOCALES=en \
    ESIGNET_MAX_AUTH_AGE_SECONDS=1200 \
    ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS=1200 \
    ESIGNET_CAPTURE_CALLBACK_HINT=1 \
    ESIGNET_CITIZEN_ACCESS_TOKEN= \
    ESIGNET_CITIZEN_ID_TOKEN= \
    ESIGNET_AUTHORIZATION_CODE= \
    scripts/smoke-citizen-oid4vci.sh; \
    status=$?; \
    if [ "$status" -eq 2 ]; then scripts/capture-esignet-callback.py; exit 0; fi; \
    exit "$status"

# Exchange the local eSignet callback code and probe citizen OID4VCI endpoints.
citizen-oid4vci-code:
    @test -n "${ESIGNET_AUTHORIZATION_CODE:-}" || test -f output/citizen-self-attestation/esignet-callback.env || (echo "Run just citizen-oid4vci-login first, or set ESIGNET_AUTHORIZATION_CODE." >&2; exit 1)
    @test -n "${ESIGNET_CLIENT_PRIVATE_KEY_FILE:-}" || test -f output/esignet-live/client-private.pem || test -f /tmp/esignet-live-test/client-private.pem || (echo "Run just esignet-up, or set ESIGNET_CLIENT_PRIVATE_KEY_FILE to the client RSA private key." >&2; exit 1)
    @set -a; \
    if [ -z "${ESIGNET_AUTHORIZATION_CODE:-}" ] && [ -f output/citizen-self-attestation/esignet-callback.env ]; then . output/citizen-self-attestation/esignet-callback.env; fi; \
    if [ -z "${ESIGNET_CLIENT_PRIVATE_KEY_FILE:-}" ] && [ -f output/esignet-live/client-private.pem ]; then ESIGNET_CLIENT_PRIVATE_KEY_FILE=output/esignet-live/client-private.pem; fi; \
    if [ -z "${ESIGNET_CLIENT_PRIVATE_KEY_FILE:-}" ] && [ -f /tmp/esignet-live-test/client-private.pem ]; then ESIGNET_CLIENT_PRIVATE_KEY_FILE=/tmp/esignet-live-test/client-private.pem; fi; \
    set +a; \
    ESIGNET_ISSUER=http://localhost:8088 \
    ESIGNET_DISCOVERY_URL=http://localhost:8088/v1/esignet/oidc/.well-known/openid-configuration \
    ESIGNET_AUTHORIZATION_URL=http://localhost:3000/authorize \
    ESIGNET_JWKS_URI=http://localhost:8088/v1/esignet/oauth/.well-known/jwks.json \
    ESIGNET_USERINFO_ENDPOINT=http://localhost:8088/v1/esignet/oidc/userinfo \
    ESIGNET_CLIENT_ID=registry-lab-live-client \
    ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo \
    ESIGNET_SUBJECT_CLAIM=individual_id \
    ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token \
    ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled \
    ESIGNET_AUTHORIZE_SCOPE='openid profile' \
    ESIGNET_AUTHORIZE_ACR_VALUES=mosip:idp:acr:generated-code \
    ESIGNET_AUTHORIZE_PROMPT=login \
    ESIGNET_AUTHORIZE_DISPLAY=popup \
    ESIGNET_CLAIMS_LOCALES=en \
    ESIGNET_MAX_AUTH_AGE_SECONDS=1200 \
    ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS=1200 \
    scripts/smoke-citizen-oid4vci.sh

# Run the citizen OID4VCI probe with exported eSignet tokens.
citizen-oid4vci-token:
    @test -n "${ESIGNET_CITIZEN_ACCESS_TOKEN:-}" || (echo "Set ESIGNET_CITIZEN_ACCESS_TOKEN." >&2; exit 1)
    @test -n "${ESIGNET_CITIZEN_ID_TOKEN:-}" || (echo "Set ESIGNET_CITIZEN_ID_TOKEN." >&2; exit 1)
    @ESIGNET_ISSUER=http://localhost:8088 \
    ESIGNET_DISCOVERY_URL=http://localhost:8088/v1/esignet/oidc/.well-known/openid-configuration \
    ESIGNET_AUTHORIZATION_URL=http://localhost:3000/authorize \
    ESIGNET_JWKS_URI=http://localhost:8088/v1/esignet/oauth/.well-known/jwks.json \
    ESIGNET_USERINFO_ENDPOINT=http://localhost:8088/v1/esignet/oidc/userinfo \
    ESIGNET_CLIENT_ID=registry-lab-live-client \
    ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo \
    ESIGNET_SUBJECT_CLAIM=individual_id \
    ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token \
    ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=disabled \
    ESIGNET_AUTHORIZE_SCOPE='openid profile' \
    ESIGNET_AUTHORIZE_ACR_VALUES=mosip:idp:acr:generated-code \
    ESIGNET_AUTHORIZE_PROMPT=login \
    ESIGNET_AUTHORIZE_DISPLAY=popup \
    ESIGNET_CLAIMS_LOCALES=en \
    ESIGNET_MAX_AUTH_AGE_SECONDS=1200 \
    ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS=1200 \
    scripts/smoke-citizen-oid4vci.sh

# Probe an already-running citizen Notary OID4VCI surface with exported tokens.
citizen-oid4vci-probe:
    scripts/probe-citizen-oid4vci.sh

# Show the latest citizen OID4VCI probe report.
citizen-oid4vci-report:
    less output/citizen-oid4vci/report.md

# Run live-service stories with narrated discovery queries and generated artifacts.
live-stories:
    scripts/demo-live-stories.sh

# Generate agricultural fixtures, demo secrets, and static metadata.
agri-generate:
    uv run scripts/generate-agri-fixtures.py
    scripts/generate-demo-secrets.py
    scripts/ensure-postgres-ssl.sh
    scripts/publish-static-metadata.sh
    @if docker compose -f compose.yaml --profile agri ps -q agri-registry-relay 2>/dev/null | grep -q .; then just agri-down && just agri-up; fi

# Generate planning-scale agricultural fixtures and refresh running agri services when present.
agri-generate-planning:
    AGRI_FIXTURE_SCALE=planning uv run scripts/generate-agri-fixtures.py
    scripts/generate-demo-secrets.py
    scripts/ensure-postgres-ssl.sh
    scripts/publish-static-metadata.sh
    @if docker compose -f compose.yaml --profile agri ps -q agri-registry-relay 2>/dev/null | grep -q .; then just agri-down && just agri-up; fi

# Build the agricultural NAgDI profile.
agri-build:
    docker compose -f compose.yaml --profile agri build agri-registry-relay nagdi-agriculture-notary agri-static-metadata-publisher

# Start the agricultural NAgDI profile.
agri-up:
    docker compose -f compose.yaml --profile agri up -d agri-registry-relay nagdi-agriculture-notary agri-static-metadata-publisher

# Stop the agricultural NAgDI profile and remove demo volumes.
agri-down:
    docker compose -f compose.yaml --profile agri stop agri-registry-relay nagdi-agriculture-notary agri-static-metadata-publisher
    docker compose -f compose.yaml --profile agri rm -f -v agri-registry-relay nagdi-agriculture-notary agri-static-metadata-publisher
    docker volume rm registry-lab_agri-registry-cache 2>/dev/null || true

# Run the agricultural NAgDI smoke.
agri-smoke:
    scripts/smoke-agri.sh

# Run the agricultural federated delegated-evaluation smoke.
agri-federation:
    scripts/smoke-agri-federation.sh

# Run the narrated agricultural NAgDI client flow.
agri-client:
    docker compose -f compose.yaml --profile agri --profile agri-client run --rm agri-demo-client

# Run the voucher MIS agriculture consumer demo.
agri-voucher-mis:
    uv run scripts/demo-voucher-mis.py

# Run the QGIS-ready aggregate agriculture planner demo.
agri-qgis-planner:
    uv run scripts/demo-qgis-planner.py

# Run the PublicSchema-shaped agriculture projection demo.
agri-publicschema-integrator:
    uv run scripts/demo-publicschema-integrator.py

# Build the local Crosswalk Python binding used by the strict PublicSchema projection check.
agri-crosswalk-python:
    cd ../cel-mapping/crates/crosswalk-python && test -d .venv || uv venv --python 3.13 .venv
    cd ../cel-mapping/crates/crosswalk-python && . .venv/bin/activate && uv pip install maturin pytest && maturin develop --release && pytest -q

# Run the PublicSchema projection and require executable Crosswalk mappings.
agri-publicschema-integrator-strict:
    bash -lc 'source ../cel-mapping/crates/crosswalk-python/.venv/bin/activate && python scripts/demo-publicschema-integrator.py --require-crosswalk'

# Run the agriculture wallet-holder credential demo.
agri-wallet:
    uv run scripts/demo-agri-wallet.py

# Run every agriculture consumer demo.
agri-consumers: agri-voucher-mis agri-qgis-planner agri-publicschema-integrator agri-wallet

# Run every agriculture consumer demo and require Crosswalk-backed PublicSchema output.
agri-consumers-strict: agri-voucher-mis agri-qgis-planner agri-crosswalk-python agri-publicschema-integrator-strict agri-wallet agri-verify-consumer-artifacts-strict

# Validate agriculture consumer artifacts after the demos run.
agri-verify-consumer-artifacts:
    uv run scripts/check-agri-consumer-artifacts.py

# Validate agriculture consumer artifacts and require Crosswalk-backed PublicSchema output.
agri-verify-consumer-artifacts-strict:
    bash -lc 'source ../cel-mapping/crates/crosswalk-python/.venv/bin/activate && python scripts/check-agri-consumer-artifacts.py --require-crosswalk'

# Open the generated live story briefing in the terminal.
briefing:
    less output/live-stories/briefing.md

# Open the generated interactive live story walkthrough.
story-page:
    python3 -c 'from pathlib import Path; import webbrowser; webbrowser.open(Path("output/live-stories/index.html").resolve().as_uri())'

# Pretty-print the generated case file.
case-file:
    python -m json.tool output/live-stories/case-file.json

# Pretty-print the generated conformance map.
conformance:
    python -m json.tool output/live-stories/conformance-map.json

# Generate, build, start, and run core smoke checks.
quick: generate build up smoke openfn client

# Run the full default release check.
release:
    scripts/release-check.sh

# Run release check without slower live-service extras.
release-fast:
    REGISTRY_LAB_CHECK_RELAY_POSTGRES=0 \
    REGISTRY_LAB_CHECK_RELAY_ZITADEL=0 \
    REGISTRY_LAB_CHECK_OIDC_RELAY=0 \
    REGISTRY_LAB_CHECK_OPENFN=0 \
    REGISTRY_LAB_RUN_LIVE_STORIES=0 \
    scripts/release-check.sh

# Run the standard sequence while leaving containers up for inspection.
try: generate build up smoke openfn client relay-postgres relay-zitadel oidc-relay live-stories
