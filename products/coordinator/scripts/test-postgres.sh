#!/usr/bin/env bash
set -euo pipefail

# All databases must be disposable and dedicated to this synthetic test suite.
: "${COORDINATOR_TEST_DATABASE_URL:?set the disposable local coordinator database URL}"
: "${COORDINATOR_MESSAGING_TEST_DATABASE_URL:?set a separate disposable local Messaging database URL}"
: "${COORDINATOR_SCHEDULING_TEST_DATABASE_URL:?set a separate disposable local Scheduling database URL}"
if [[ "$COORDINATOR_TEST_DATABASE_URL" == "$COORDINATOR_MESSAGING_TEST_DATABASE_URL" ||
	"$COORDINATOR_TEST_DATABASE_URL" == "$COORDINATOR_SCHEDULING_TEST_DATABASE_URL" ||
	"$COORDINATOR_MESSAGING_TEST_DATABASE_URL" == "$COORDINATOR_SCHEDULING_TEST_DATABASE_URL" ]]; then
	printf '%s\n' "Coordinator, Messaging, and Scheduling tests require distinct disposable databases." >&2
	exit 1
fi

cd "$(dirname "$0")/../../.."
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
# Compose through independently built product executables, never runtime
# dev-dependencies. Tests refuse missing binaries rather than skipping coverage.
cargo build --locked -p registry-messaging -p registry-messagingctl \
	--features registry-messaging/postgres-test --bin messaging --bin messagingctl
cargo build --locked -p registry-scheduling -p registry-schedulingctl \
	--features registry-scheduling/postgres-test,registry-schedulingctl/postgres-test \
	--bin scheduling --bin schedulingctl
coordinator_test_target=$(cargo metadata --locked --no-deps --format-version 1 |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
export COORDINATOR_MESSAGING_BIN="$coordinator_test_target/debug/messaging"
export COORDINATOR_MESSAGINGCTL_BIN="$coordinator_test_target/debug/messagingctl"
export COORDINATOR_SCHEDULING_BIN="$coordinator_test_target/debug/scheduling"
export COORDINATOR_SCHEDULINGCTL_BIN="$coordinator_test_target/debug/schedulingctl"
cargo test --locked -p registry-coordinator --features postgres-test --lib \
	--test postgres_state --test recovery_audit --test read_lease_recovery \
	--test messaging_integration --test process_restart \
	--test deployment_postgres --test review_wait_postgres \
	--test external_wait_postgres --test external_command_postgres \
	--test standalone_review_postgres
cargo test --locked -p registry-coordinator --features postgres-test \
	--test scheduling_event_native -- --ignored --nocapture
