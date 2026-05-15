# data_gate task runner. Requires `just` (https://github.com/casey/just).

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
    cargo deny check

# Check advisories only (alias for a quick security scan).
audit:
    cargo deny check advisories

# Run the full CI gate locally: fmt-check, lint, test, deny.
ci: fmt-check lint test deny

# Run the development server with a config file.
# Usage: just run              (uses config/example.yaml)
#        just run config=path/to/other.yaml
run config="config/example.yaml":
    cargo run -- --config {{config}}
