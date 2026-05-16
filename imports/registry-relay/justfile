# registry-relay task runner. Requires `just` (https://github.com/casey/just).

# Install the Rust toolchain via mise and fetch all dependencies.
setup:
    mise install
    cargo fetch

# Build the release binary.
build:
    cargo build --release

# Run all tests with all features enabled.
test:
    cargo test --all-features

# Run clippy on all targets and features; treat warnings as errors.
lint:
    cargo clippy --all-targets --all-features -- -D warnings

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

# Check advisories only (alias for a quick security scan).
audit:
    if [ -x "$HOME/.cargo/bin/cargo-deny" ]; then "$HOME/.cargo/bin/cargo-deny" check advisories; else cargo deny check advisories; fi

# Run the full CI gate locally: fmt-check, lint, test, deny.
ci: fmt-check lint test deny

# Run the development server with a config file.
# Usage: just run              (uses config/example.yaml)
#        just run config=path/to/other.yaml
run config="config/example.yaml":
    cargo run -- --config {{config}}

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
