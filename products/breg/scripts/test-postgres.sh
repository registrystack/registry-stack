#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: test-postgres.sh [--lane all|postgres|postgres:SHARD/OF|immediate-actions]' >&2
  printf '%s\n' 'A postgres:I/N lane value runs only the targets whose position in the owned' >&2
  printf '%s\n' 'lists falls to shard I of N (N >= 2); plain postgres runs every target.' >&2
}

# Local runs retain the full suite; CI isolates the complete slow action target
# and splits the PostgreSQL journeys across parallel postgres:I/N shards.
lane=all
if [[ $# -ne 0 ]]; then
  if [[ $# -ne 2 || $1 != --lane ]]; then
    usage
    exit 2
  fi
  lane=$2
fi
shard_index=1
shard_count=1
case "$lane" in
  all|postgres|immediate-actions) ;;
  postgres:*)
    shard_spec=${lane#postgres:}
    if [[ ! "$shard_spec" =~ ^([1-9][0-9]*)/([2-9][0-9]*)$ ]]; then
      usage
      exit 2
    fi
    shard_index=${BASH_REMATCH[1]}
    shard_count=${BASH_REMATCH[2]}
    if (( shard_index > shard_count )); then
      usage
      exit 2
    fi
    lane=postgres
    ;;
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

# The owned target inventory. validate_product.py compares these lists with
# POSTGRES_TEST_COMMANDS, so every integration target appears in exactly one
# list and none is added or dropped quietly.
runtime_targets=(
  http_auth
  http_read_only
  runtime_config
  startup_http
  startup_ordering
  fixture_tooling
)
postgres_targets=(
  postgres_kernel
  postgres_connection_diagnostics
  postgres_compiled_schema
  postgres_partial_unique
  postgres_constraint_races
  postgres_read
  postgres_read_cancellation
  postgres_access_log
  postgres_read_dependencies
  postgres_derived_values
  postgres_record_profile_conformance
  postgres_client_capabilities
  postgres_client_relationships
  postgres_spatial_storage
  postgres_spatial_read
  postgres_revision_http
  postgres_unauthenticated_refusals
  postgres_history_commit
  postgres_historical
  postgres_history_erasure
  postgres_history_rebaseline
  postgres_workspace_metadata
  postgres_mutation
  postgres_reference_integrity
  postgres_immediate_action_requirements
  postgres_immediate_action_generated_identifiers
  postgres_consent_access
  postgres_membership_access
  postgres_mutation_logical_names
  postgres_webhook_outbox
  postgres_webhook_delivery
  postgres_hook_changes
  postgres_temporal_corrections
  postgres_batch
  postgres_data_facility
  postgres_data_export
  postgres_ingestion_runs
  postgres_ingestion_contract
  postgres_ingestion_receipts
  postgres_import_authority
  postgres_refactor
  postgres_proposal
  postgres_proposal_generated_identifiers
  postgres_proposal_shape_activation
  postgres_native_retention
  postgres_proposal_human_recovery
  postgres_reviewed_change_example
  postgres_proposal_hooks
  postgres_proposal_review_delivery
  postgres_proposal_security
  postgres_proposal_s3
  postgres_facility_proposal
  postgres_action_task_grants
  postgres_generated_console
  postgres_generated_identifiers
  postgres_pilot_acceptance
  postgres_tombstone_revision
  postgres_startup
  postgres_history_migration
  postgres_immediate_action_examples
  postgres_immediate_action_activation
  postgres_consent_examples
  postgres_registry_extensibility
  postgres_action_handlers
  postgres_field_encryption
  postgres_generated_identifier_batch_import
  postgres_package
  postgres_migration
  postgres_generated_identifier_migration
  postgres_spatial_migration
  postgres_reference_indexes
  postgres_list_page_plans
  postgres_fixture_journeys
  postgres_statistics
  postgres_statistics_http
  postgres_statistics_stock
  postgres_statistics_byte_limits
  postgres_statistics_first_period
  postgres_statistics_history
  postgres_logical_sql_names
  schema_fingerprint_rehearsal
)
immediate_action_targets=(
  postgres_immediate_actions
)

# Round-robin over each list's order, so related groups (history, statistics,
# proposals) spread across shards instead of pooling on one of them. Every
# target of a sharded lane still runs exactly once across the shard set.
sharded_test_flags() {
  local position=0 target
  for target in "$@"; do
    if (( position % shard_count + 1 == shard_index )); then
      printf '%s\n' "--test" "$target"
    fi
    position=$((position + 1))
  done
}

run_sharded_targets() {
  # $1: the feature set; remaining arguments: the owned target list.
  local features=$1
  shift
  local flags=() flag
  # Read line by line: the bash 3.2 macOS ships has no builtin that loads
  # lines into an array.
  while IFS= read -r flag; do
    flags+=("$flag")
  done < <(sharded_test_flags "$@")
  if (( ${#flags[@]} == 0 )); then
    printf '%s\n' "Shard ${shard_index}/${shard_count} has no targets in this list; skipping." >&2
    return 0
  fi
  cargo test --locked -p registry-breg --features "$features" "${flags[@]}"
}

# Every registry-breg target here builds against one of two feature sets, so
# the crate compiles at most twice per run instead of once per target group.
# The runtime set leaves out postgres-test because runtime_config and
# startup_http select different tests when it is on. test-attachment-s3.sh
# uses the same two sets, so a later S3 step reuses these builds.
if [[ "$lane" == all || "$lane" == postgres ]]; then
  run_sharded_targets runtime,tooling,schema "${runtime_targets[@]}"
  run_sharded_targets postgres-test,tooling,schema "${postgres_targets[@]}"

  # The Evidence proof builds the real service once and runs from the first
  # shard only, so parallel shards do not each rebuild the Evidence tree.
  # This proof must start the real Evidence service, never silently skip it.
  if (( shard_index == 1 )); then
    # Use Cargo's reported executable so configured target directories work too.
    evidence_binary=$(cargo build --locked -p registry-evidence --bin evidence --message-format=json | python3 -c '
import json, sys
artifacts = [json.loads(line) for line in sys.stdin]
binaries = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "evidence" and item.get("executable")]
if len(binaries) != 1:
    raise SystemExit("expected exactly one built Evidence executable")
print(binaries[0])
')
    [[ -x "$evidence_binary" ]] || { printf '%s\n' 'Built Evidence executable is unavailable.' >&2; exit 2; }
    export BREG_TEST_EVIDENCE_BINARY="$evidence_binary"
    # The trio runs as one unit on its owning shard, never split further.
    uv run --no-project --with PyYAML==6.0.2 cargo test --locked -p registry-breg --features postgres-test,tooling,schema \
      --test postgres_action_evidence \
      --test postgres_action_evidence_targets \
      --test postgres_action_evidence_retention
  fi
fi

if [[ "$lane" == all || "$lane" == immediate-actions ]]; then
  run_sharded_targets postgres-test,tooling,schema "${immediate_action_targets[@]}"
fi
