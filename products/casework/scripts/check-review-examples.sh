#!/bin/sh
set -eu
# Maintained review transactions use unique schemas in an explicitly disposable DB.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
if [ -z "${CASEWORK_REVIEW_TEST_DATABASE_URL:-}" ]; then
  echo 'set CASEWORK_REVIEW_TEST_DATABASE_URL to an explicitly disposable PostgreSQL database' >&2
  exit 2
fi
CASEWORK_ACTIVATION_TEST_DATABASE_URL=${CASEWORK_ACTIVATION_TEST_DATABASE_URL:-$CASEWORK_REVIEW_TEST_DATABASE_URL}
CASEWORK_ASSIGNMENT_TEST_DATABASE_URL=${CASEWORK_ASSIGNMENT_TEST_DATABASE_URL:-$CASEWORK_REVIEW_TEST_DATABASE_URL}
BREG_TEST_DATABASE_URL=${BREG_TEST_DATABASE_URL:-$CASEWORK_REVIEW_TEST_DATABASE_URL}
export CASEWORK_ACTIVATION_TEST_DATABASE_URL CASEWORK_ASSIGNMENT_TEST_DATABASE_URL BREG_TEST_DATABASE_URL
cd "$repo_root"
products/casework/scripts/check-checkpoint.sh
for target in review_acceptance_postgres review_migration_postgres review_directory_postgres review_postgres review_http review_payment_fixture_postgres breg_review_journey; do
  cargo test --locked --offline -j2 -p registry-casework --features postgres-test --test "$target"
done
cargo test --locked --offline -j2 -p registry-casework --features postgres-test --lib task_grants::
cargo test --locked --offline -j2 -p registry-caseworkctl --features postgres-test,schema --lib operator_tests
# The producer export is independently derived and sealed by BReg.
cargo test --locked --offline -j2 -p registry-breg --features runtime,tooling --test review_context_package
# Installed binaries and candidate SDK facades exercise retained local sessions.
products/casework/scripts/check-review-journeys.sh
printf '%s\n' 'Casework review transactions, migration, HTTP, grant, native contract and dev journeys passed.'
