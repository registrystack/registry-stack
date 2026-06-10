# registry-notary task runner. Requires `just` (https://github.com/casey/just).

export CARGO_NET_GIT_FETCH_WITH_CLI := "true"

# Install the Rust toolchain via mise and fetch all dependencies.
setup:
    mise install
    cargo fetch

# Build the release binary.
build:
    cargo build --release --workspace --all-features

# Format all source files in place.
fmt:
    cargo fmt --all

# Check formatting without modifying files.
fmt-check:
    cargo fmt --all -- --check

# Run clippy on all targets and features; treat warnings as errors.
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run clippy on the default feature shape.
lint-default:
    cargo clippy --workspace --all-targets -- -D warnings

# Run all workspace tests with all features enabled.
test:
    cargo test --workspace --all-features

# Run the default feature shape.
test-default:
    cargo test --workspace

# Run cargo-deny through the repo-pinned wrapper.
deny:
    ./scripts/cargo-deny-check.sh

# Check advisories only.
audit:
    ./scripts/cargo-deny-check.sh advisories

# Generate the OpenAPI document to stdout.
openapi-generate:
    cargo run -q -p registry-notary-bin -- openapi

# Validate the committed OpenAPI baseline.
openapi-check:
    python3 scripts/check_security_assurance.py openapi-baseline

# Validate exposure manifest, route inventory, and Dockerfile secret-copy guardrails.
exposure-check:
    python3 scripts/check_security_assurance.py manifest

# Validate Dockerfiles for obvious secret-copy hazards.
container-security:
    python3 scripts/check_security_assurance.py dockerfile-secrets

# Run security assurance checks that do not require external services.
security:
    ./scripts/check-security.sh

# Run the full local CI gate.
ci: fmt-check lint-default lint test-default test deny openapi-check exposure-check security

# Run the development server with a config file.
# Usage: just run
#        just run config=path/to/config.yaml
run config="demo/config/registry-notary.yaml":
    cargo run -p registry-notary-bin -- --config {{config}}
