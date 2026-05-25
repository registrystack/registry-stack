set dotenv-load := true
set positional-arguments := true

relay_src := env_var_or_default("REGISTRY_RELAY_SOURCE_DIR", "../registry-relay")
witness_src := env_var_or_default("REGISTRY_WITNESS_SOURCE_DIR", "../registry-witness")
openfn_witness_src := env_var_or_default("REGISTRY_OPENFN_WITNESS_SOURCE_DIR", "../registry-witness")
platform_src := env_var_or_default("REGISTRY_PLATFORM_SOURCE_DIR", "../registry-platform")

export REGISTRY_RELAY_SOURCE_DIR := relay_src
export REGISTRY_WITNESS_SOURCE_DIR := witness_src
export REGISTRY_OPENFN_WITNESS_SOURCE_DIR := openfn_witness_src
export REGISTRY_PLATFORM_SOURCE_DIR := platform_src
export REGISTRY_RELAY_PLATFORM_SOURCE_DIR := platform_src
export REGISTRY_WITNESS_PLATFORM_SOURCE_DIR := platform_src

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

# Show running demo services.
ps:
    docker compose -f compose.yaml ps

# Follow demo service logs. Pass service names after `--`, for example: just logs -- zitadel openfn-civil-witness
logs *services:
    docker compose -f compose.yaml logs -f {{services}}

# Run the API-key Relay/Witness smoke.
smoke:
    scripts/smoke.sh

# Run the narrated default client flow.
client:
    docker compose -f compose.yaml --profile client run --rm demo-client

# Run the OpenFn sidecar smoke.
openfn:
    scripts/smoke-openfn.sh

# Run Relay's ignored live Postgres integration test against lab Postgres.
relay-postgres:
    scripts/check-relay-postgres.sh

# Run Relay's ignored live Zitadel integration test against lab Zitadel.
relay-zitadel:
    scripts/check-relay-zitadel.sh

# Run the OIDC Relay smoke with a lab-managed Zitadel token.
oidc-relay:
    scripts/smoke-oidc-relay.sh

# Run the optional eSignet-backed citizen self-attestation Witness smoke.
citizen-self-attestation:
    scripts/smoke-citizen-self-attestation.sh

# Run live-service stories with narrated discovery queries and generated artifacts.
live-stories:
    scripts/demo-live-stories.sh

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
