#!/bin/sh
set -eu

# Aggregate the maintained review examples and their paired configuration
# contracts. Every PostgreSQL test below creates an isolated
# schema, so the suites may share one explicitly disposable database.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
database_url=${CASEWORK_REVIEW_EXAMPLES_DATABASE_URL:-}

if [ -z "$database_url" ]; then
  echo "set CASEWORK_REVIEW_EXAMPLES_DATABASE_URL to an explicitly disposable PostgreSQL database" >&2
  exit 2
fi

cd "$repo_root"
export CASEWORK_REVIEW_TEST_DATABASE_URL=$database_url
export BREG_TEST_DATABASE_URL=$database_url

python3 -m unittest products/casework/scripts/test_product_contracts.py

cargo test --locked -p registry-casework --features schema --lib \
  schema::tests::committed_runtime_schema_matches_generated_bytes
cargo test --locked -p registry-breg --features runtime,schema --lib \
  schema::tests::committed_runtime_schema_matches_generated_bytes
cargo test --locked -p registry-casework-core --lib \
  review_producers_are_exact_and_recovery_fits_result_retention
cargo test --locked -p registry-caseworkctl --lib \
  standalone_starter_checks_real_review_display_schema_without_a_source
cargo test --locked -p registry-caseworkctl --lib \
  review_connection_retention_diagnostic_names_the_incompatible_pair
cargo test --locked -p registry-breg --features runtime --test runtime_config \
  review_authorities_accept_one_refreshing_or_static_credential
cargo test --locked -p registry-bregctl --lib \
  local_review_authority_uses_refreshing_logical_client_without_exposing_credentials

cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/asset-site-placement-change-requests
for example in payment-review standalone-decision; do
  cargo run --locked -p registry-caseworkctl -- \
    check "products/casework/examples/$example"
  cargo run --locked -p registry-caseworkctl -- \
    test "products/casework/examples/$example"
done

cargo test --locked -p registry-casework --features postgres-test \
  --test breg_review_journey -- --nocapture
cargo test --locked -p registry-casework --features postgres-test \
  --test review_payment_fixture_postgres -- --nocapture
cargo test --locked -p registry-casework --features postgres-test \
  --test review_postgres standalone_structured_answers_support_polling_and_completion_modes \
  -- --nocapture

echo "BReg, payment, and standalone review examples and paired configuration contracts passed."
