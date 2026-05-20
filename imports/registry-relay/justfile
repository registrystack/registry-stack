# registry-relay task runner. Requires `just` (https://github.com/casey/just).

export CARGO_NET_GIT_FETCH_WITH_CLI := "true"

# Install the Rust toolchain via mise and fetch all dependencies.
setup:
    mise install
    cargo fetch

# Build the release binary.
build:
    cargo build --release

# Build the binary shape used by the core demo configs.
# Usage: just demo-build
#        just demo-build ogcapi-features
demo-build features="":
    if [ -n "{{features}}" ]; then cargo build --features "{{features}}"; else cargo build; fi

# Run all tests with all features enabled.
test:
    cargo test --all-features

# Run the default binary shape. This keeps optional-feature guardrails
# covered separately from the all-features build.
test-default:
    cargo test

# Run clippy on all targets and features; treat warnings as errors.
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Run clippy on the default binary shape.
lint-default:
    cargo clippy --all-targets -- -D warnings

# Format all source files in place.
fmt:
    cargo fmt --all

# Check formatting without modifying files (used in CI).
fmt-check:
    cargo fmt --all -- --check

# Run all cargo-deny checks (licenses, advisories, bans, sources).
deny:
    if [ -x "$HOME/.cargo/bin/cargo-deny" ]; then "$HOME/.cargo/bin/cargo-deny" check; else cargo deny check; fi

# Validate a generated DCAT-AP JSON-LD catalog with pySHACL.
# Usage: just validate-catalog-shacl catalog=target/catalog.dcat-ap.jsonld
#        just validate-catalog-shacl catalog=http://127.0.0.1:8080/catalog/dcat-ap.jsonld
validate-catalog-shacl catalog:
    uv run --with 'pyshacl>=0.27,<0.31' --with 'rdflib-jsonld>=0.6' python scripts/validate_dcat_shacl.py --catalog {{catalog}}

# Validate a generated DCAT-AP JSON-LD catalog with the external SEMIC validator.
# Usage: just validate-catalog-semic catalog=target/catalog.dcat-ap.jsonld
#        just validate-catalog-semic catalog=http://127.0.0.1:8080/catalog/dcat-ap.jsonld validation_type=dcatap.3_0_1_full
validate-catalog-semic catalog validation_type="dcatap.3_0_1_base":
    python scripts/validate_semic_dcat_ap.py --catalog {{catalog}} --validation-type {{validation_type}}

# Validate one portable metadata manifest.
# Usage: just metadata-validate
#        just metadata-validate profiles/example-benefits-sync/fixtures/metadata.yaml
metadata-validate manifest="profiles/example-civil-registration/fixtures/metadata.yaml":
    cargo run --quiet -p registry-metadata-cli -- validate {{manifest}}

# Validate all ecosystem profile descriptors and fixture manifests.
metadata-validate-profiles:
    cargo run --quiet -p registry-metadata-cli -- validate-profiles profiles

# Render one static metadata artifact from a manifest.
# Usage: just metadata-render
#        just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml dcat target/metadata/dcat.jsonld
#        just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml json-schema target/metadata/person.schema.json "--dataset vital-events --entity person"
metadata-render manifest="profiles/example-civil-registration/fixtures/metadata.yaml" format="catalog" out="target/metadata/catalog.json" extra="":
    mkdir -p $(dirname {{out}})
    cargo run --quiet -p registry-metadata-cli -- render {{manifest}} --format {{format}} {{extra}} > {{out}}

# Publish a static metadata bundle with index, catalog, DCAT, SHACL, and schemas.
# Usage: just metadata-publish
#        just metadata-publish profiles/example-social-benefits/fixtures/metadata.yaml target/metadata/example-social-benefits
metadata-publish manifest="profiles/example-civil-registration/fixtures/metadata.yaml" out="target/metadata/public":
    cargo run --quiet -p registry-metadata-cli -- publish {{manifest}} --out {{out}}

# Check advisories only (alias for a quick security scan).
audit:
    if [ -x "$HOME/.cargo/bin/cargo-deny" ]; then "$HOME/.cargo/bin/cargo-deny" check advisories; else cargo deny check advisories; fi

# Run the full CI gate locally: fmt-check, default/all-feature lint,
# default/all-feature tests, and cargo-deny.
ci: fmt-check lint-default lint test-default test deny

# Run the development server with a config file.
# Usage: just run              (uses config/example.yaml)
#        just run config=path/to/other.yaml
run config="config/example.yaml":
    cargo run -- --config {{config}}

# Generate or rotate local demo API keys for the server and Bruno.
demo-keys env="demo/.env.local":
    uv run demo/scripts/generate_demo_keys.py --env-file {{env}}

# List demo personas and the key variable to use for each OpenAPI-style task.
# Usage: just demo-keys-list
#        just demo-keys-list demo/config/disability_registry.yaml
#        just demo-keys-list demo/config/all_standards.yaml
#        just demo-keys-list demo/config/all_demos.yaml path/to/demo.env
demo-keys-list config="demo/config/all_standards.yaml" env="demo/.env.local":
    uv run demo/scripts/list_demo_keys.py --config {{config}} --env-file {{env}}

# Run a demo config, generating demo keys first when demo/.env.local is absent.
# Usage: just demo-run
#        just demo-run demo/config/benefits_casework.yaml
#        just demo-run demo/config/all_demos.yaml ogcapi-features
#        just demo-run demo/config/disability_registry.yaml spdci-api-standards,standards-cel-mapping
demo-run config="demo/config/all_standards.yaml" features="":
    @if [ ! -f demo/.env.local ]; then uv run demo/scripts/generate_demo_keys.py --env-file; fi
    set -a; . demo/.env.local; set +a; demo_features="{{features}}"; if [ -z "$demo_features" ] && [ "{{config}}" = "demo/config/all_standards.yaml" ]; then demo_features="ogcapi-records,ogcapi-features,spdci-api-standards,standards-cel-mapping"; fi; if [ -n "$demo_features" ]; then cargo run --features "$demo_features" -- --config {{config}}; else cargo run -- --config {{config}}; fi

# Generate synthetic perf fixtures under perf/fixtures/generated/.
# Usage: just perf-gen                       (default: all profiles)
#        just perf-gen profile=medium
#        just perf-gen profile=large extra="--include-5m"
perf-gen profile="all" extra="":
    uv run perf/scripts/generate_perf_data.py --profile {{profile}} {{extra}}

# Generate synthetic perf API keys and write target/perf/perf.env.
# Usage: just perf-keys                                 (default path)
#        just perf-keys env="target/perf/other.env" force="--force"
perf-keys env="target/perf/perf.env" force="":
    mkdir -p $(dirname {{env}})
    uv run perf/scripts/generate_perf_keys.py --env-file {{env}} {{force}}

# Compile the perf benches without running them. Used as a CI smoke check.
perf-bench-build:
    cargo bench --no-run

# Run all Criterion microbenchmarks (manual; not for CI).
perf-bench:
    cargo bench

# Run one k6 scenario under perf/k6/, sampling the server process.
# Requires: k6 on PATH, a running registry-relay (or pass --start-server via extra).
# Usage: just perf-run scenario=perf/k6/cached_304.js
#        just perf-run scenario=perf/k6/hot_200.js extra="--server-pid 12345"
perf-run scenario extra="--env-file target/perf/perf.env":
    uv run perf/scripts/run_scenario.py --scenario {{scenario}} {{extra}}

# Start registry-relay and run one named k6 scenario against a perf profile.
# Usage: just perf-scenario cached_304
#        just perf-scenario large_304 large 10s
#        just perf-scenario mixed_read medium 2m
perf-scenario scenario profile="medium" duration="30s" env="target/perf/perf.env" out="target/perf/reports" sample_interval="5":
    REGISTRY_RELAY_DURATION={{duration}} REGISTRY_RELAY_PROFILE={{profile}} uv run perf/scripts/run_scenario.py --scenario perf/k6/{{scenario}}.js --start-server --config perf/config/{{profile}}.yaml --env-file {{env}} --out-dir {{out}} --sample-interval {{sample_interval}}

# Long-running soak benchmark. Defaults to the overnight large-profile run.
# Usage: just perf-soak
#        just perf-soak large 30m
#        just perf-soak medium 10m
perf-soak profile="large" duration="60m" env="target/perf/perf.env" out="target/perf/reports" sample_interval="5":
    REGISTRY_RELAY_DURATION={{duration}} REGISTRY_RELAY_PROFILE={{profile}} uv run perf/scripts/run_scenario.py --scenario perf/k6/soak.js --start-server --config perf/config/{{profile}}.yaml --env-file {{env}} --out-dir {{out}} --sample-interval {{sample_interval}}

# Local CI-equivalent smoke: build release, generate the small fixture profile,
# compile the benches, and node-check every k6 scenario. Does not start the
# server or run k6 (CI installs k6 separately when available).
perf-smoke:
    cargo build --release
    uv run perf/scripts/generate_perf_data.py --profile small --out-dir target/perf/smoke-fixtures
    cargo bench --no-run
    for f in perf/k6/*.js perf/k6/lib/*.js; do node --check "$f" || exit 1; done
    @echo "perf-smoke OK"
