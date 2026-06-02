# registry-notary task runner. Requires `just` (https://github.com/casey/just).

export CARGO_NET_GIT_FETCH_WITH_CLI := "true"

# Check formatting without modifying files.
fmt-check:
    cargo fmt --all -- --check

# Run clippy on all targets and features; treat warnings as errors.
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run all workspace tests with all features enabled.
test:
    cargo test --workspace --all-features

# Run cargo-deny through the repo-pinned wrapper.
deny:
    ./scripts/cargo-deny-check.sh

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
