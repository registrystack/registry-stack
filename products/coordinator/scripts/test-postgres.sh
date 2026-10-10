#!/usr/bin/env bash
set -euo pipefail

# Both databases must be disposable and dedicated to this synthetic test suite.
: "${COORDINATOR_TEST_DATABASE_URL:?set the disposable local coordinator database URL}"
: "${COORDINATOR_MESSAGING_TEST_DATABASE_URL:?set a separate disposable local Messaging database URL}"
if [[ "$COORDINATOR_TEST_DATABASE_URL" == "$COORDINATOR_MESSAGING_TEST_DATABASE_URL" ]]; then
  echo "Coordinator and Messaging tests require distinct disposable databases." >&2
  exit 1
fi

cd "$(dirname "$0")/../../.."
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
# Compose through independently built Messaging executables, never a runtime
# dev-dependency. Tests refuse missing binaries rather than skipping coverage.
cargo build --locked -p registry-messaging -p registry-messagingctl \
  --features registry-messaging/postgres-test --bin messaging --bin messagingctl
coordinator_test_target=$(cargo metadata --locked --no-deps --format-version 1 | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
export COORDINATOR_MESSAGING_BIN="$coordinator_test_target/debug/messaging"
export COORDINATOR_MESSAGINGCTL_BIN="$coordinator_test_target/debug/messagingctl"
cargo test --locked -p registry-coordinator --features postgres-test --lib \
  --test postgres_state --test recovery_audit --test messaging_integration --test process_restart \
  --test deployment_postgres
