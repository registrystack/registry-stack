#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REGISTRY_SERVER_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_DATABASE_URL must be set for PostgreSQL journeys.' >&2
  exit 2
fi

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

cargo test --locked -p registry-server --features runtime --test http_auth
cargo test --locked -p registry-server --features runtime --test http_read_only
cargo test --locked -p registry-server --features runtime --test runtime_config
cargo test --locked -p registry-server --features runtime --test startup_http
cargo test --locked -p registry-server --features runtime --test startup_ordering
cargo test --locked -p registry-server --features runtime,tooling --test fixture_tooling
cargo test --locked -p registry-server --features postgres-test --test postgres_kernel
cargo test --locked -p registry-server --features postgres-test --test postgres_compiled_schema
cargo test --locked -p registry-server --features postgres-test --test postgres_partial_unique
cargo test --locked -p registry-server --features postgres-test --test postgres_constraint_races
cargo test --locked -p registry-server --features postgres-test --test postgres_read
cargo test --locked -p registry-server --features postgres-test --test postgres_record_profile_conformance
cargo test --locked -p registry-server --features postgres-test --test postgres_spatial_storage
cargo test --locked -p registry-server --features postgres-test --test postgres_spatial_read
cargo test --locked -p registry-server --features postgres-test --test postgres_revision_http
cargo test --locked -p registry-server --features postgres-test --test postgres_history_commit
cargo test --locked -p registry-server --features postgres-test --test postgres_historical
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_history_migration
cargo test --locked -p registry-server --features postgres-test --test postgres_history_erasure
cargo test --locked -p registry-server --features postgres-test --test postgres_workspace_metadata
cargo test --locked -p registry-server --features postgres-test --test postgres_mutation
cargo test --locked -p registry-server --features postgres-test --test postgres_immediate_actions
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_immediate_action_examples
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_immediate_action_activation
cargo test --locked -p registry-server --features postgres-test --test postgres_webhook_outbox
cargo test --locked -p registry-server --features postgres-test --test postgres_webhook_delivery
cargo test --locked -p registry-server --features postgres-test --test postgres_temporal_corrections
cargo test --locked -p registry-server --features postgres-test --test postgres_batch
cargo test --locked -p registry-server --features postgres-test --test postgres_data_facility
cargo test --locked -p registry-server --features postgres-test --test postgres_data_export
cargo test --locked -p registry-server --features postgres-test --test postgres_change_requests
cargo test --locked -p registry-server --features postgres-test --test postgres_request_authority
cargo test --locked -p registry-server --features postgres-test --test postgres_request_receipts
cargo test --locked -p registry-server --features postgres-test --test postgres_request_upgrade_retention
cargo test --locked -p registry-server --features postgres-test --test postgres_request_events
cargo test --locked -p registry-server --features postgres-test --test postgres_request_queries
cargo test --locked -p registry-server --features postgres-test --test postgres_request_read_retention
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_request_activation
cargo test --locked -p registry-server --features postgres-test --test postgres_pilot_acceptance
cargo test --locked -p registry-server --features postgres-test --test postgres_rhai_planner
cargo test --locked -p registry-server --features postgres-test --test postgres_tombstone_revision
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_package
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_migration
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_spatial_migration
cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_fixture_journeys
cargo test --locked -p registry-server --features postgres-test,tooling --test schema_fingerprint_rehearsal
cargo test --locked -p registry-server --features postgres-test --test postgres_startup
