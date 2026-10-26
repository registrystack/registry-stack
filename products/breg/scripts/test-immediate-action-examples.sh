#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
  printf '%s\n' 'Usage: test-immediate-action-examples.sh' >&2
  exit 2
fi
if [[ -z "${BREG_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'BREG_TEST_DATABASE_URL must be set for immediate Action examples.' >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(cd -- "$script_dir/../../.." && pwd -P)
cd "$repository_root"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

# The canonical facility Action proves transactional rollback, current reference
# refusals, concurrent replay and recovery after a lost response through the
# native client and real PostgreSQL. The facility dev journey proves CLI usage.
exec cargo test --locked -p registry-breg --features postgres-test,tooling,schema \
  --test postgres_refactor \
  facility_action_is_atomic_checks_references_and_recovers_exactly_once \
  -- --exact --test-threads=1
