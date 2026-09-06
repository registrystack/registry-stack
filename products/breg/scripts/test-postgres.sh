#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: test-postgres.sh [--lane all|postgres|immediate-actions]' >&2
}

# Local runs retain the full suite; CI isolates the complete slow action target.
lane=all
if [[ $# -ne 0 ]]; then
  if [[ $# -ne 2 || $1 != --lane ]]; then
    usage
    exit 2
  fi
  lane=$2
fi
case "$lane" in
  all|postgres|immediate-actions) ;;
  *) usage; exit 2 ;;
esac

if [[ -z "${BREG_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'BREG_TEST_DATABASE_URL must be set for PostgreSQL journeys.' >&2
  exit 2
fi

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

if [[ "$lane" == all || "$lane" == postgres ]]; then
  cargo test --locked -p registry-breg --features runtime \
    --test http_auth \
    --test http_read_only \
    --test runtime_config \
    --test startup_http \
    --test startup_ordering
  cargo test --locked -p registry-breg --features runtime,tooling \
    --test fixture_tooling
  cargo test --locked -p registry-breg --features postgres-test \
    --test postgres_kernel \
    --test postgres_compiled_schema \
    --test postgres_partial_unique \
    --test postgres_constraint_races \
    --test postgres_read \
    --test postgres_read_dependencies \
    --test postgres_record_profile_conformance \
    --test postgres_spatial_storage \
    --test postgres_spatial_read \
    --test postgres_revision_http \
    --test postgres_anonymous_refusals \
    --test postgres_history_commit \
    --test postgres_historical \
    --test postgres_history_erasure \
    --test postgres_history_rebaseline \
    --test postgres_workspace_metadata \
    --test postgres_mutation \
    --test postgres_mutation_logical_names \
    --test postgres_webhook_outbox \
    --test postgres_webhook_delivery \
    --test postgres_temporal_corrections \
    --test postgres_batch \
    --test postgres_data_facility \
    --test postgres_data_export \
    --test postgres_change_requests \
    --test postgres_request_authority \
    --test postgres_request_receipts \
    --test postgres_request_upgrade_retention \
    --test postgres_request_events \
    --test postgres_request_queries \
    --test postgres_request_read_retention \
    --test postgres_pilot_acceptance \
    --test postgres_rhai_planner \
    --test postgres_tombstone_revision \
    --test postgres_startup
  cargo test --locked -p registry-breg --features postgres-test,tooling \
    --test postgres_history_migration \
    --test postgres_immediate_action_examples \
    --test postgres_immediate_action_activation \
    --test postgres_request_activation \
    --test postgres_audit_tooling \
    --test postgres_package \
    --test postgres_migration \
    --test postgres_spatial_migration \
    --test postgres_fixture_journeys \
    --test schema_fingerprint_rehearsal
fi

if [[ "$lane" == all || "$lane" == immediate-actions ]]; then
  cargo test --locked -p registry-breg --features postgres-test --test postgres_immediate_actions
fi
