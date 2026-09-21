#!/bin/sh
set -eu

# Aggregate the maintained review examples and their paired configuration
# contracts. Every PostgreSQL test below creates an isolated schema or child
# database, so the suites may share one explicitly disposable database. The
# native lifecycle additionally owns and removes its own Docker database.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
database_url=${CASEWORK_REVIEW_EXAMPLES_DATABASE_URL:-}

if [ -z "$database_url" ]; then
  echo "set CASEWORK_REVIEW_EXAMPLES_DATABASE_URL to an explicitly disposable PostgreSQL database" >&2
  exit 2
fi

# The transaction, visibility, source-retention, and clock suites reset public.
# Refuse a configured alias before this aggregate creates any state. Normalize
# ordinary PostgreSQL URLs without printing their credentials.
python3 -c '
import os
import sys
from urllib.parse import parse_qs, unquote, urlsplit

def target(value):
    parsed = urlsplit(value)
    query = parse_qs(parsed.query)
    host = unquote(query.get("host", [parsed.hostname or "localhost"])[-1])
    if host.lower() in {"localhost", "127.0.0.1", "::1"}:
        host = "loopback"
    port = query.get("port", [str(parsed.port or 5432)])[-1]
    database = query.get("dbname", [unquote(parsed.path.removeprefix("/"))])[-1]
    return (host, port, database)

owned = target(os.environ["CASEWORK_REVIEW_EXAMPLES_DATABASE_URL"])
for name in (
    "CASEWORK_TEST_DATABASE_URL",
    "CASEWORK_VISIBILITY_TEST_DATABASE_URL",
    "CASEWORK_SOURCE_RETENTION_TEST_DATABASE_URL",
    "CASEWORK_CLOCK_TEST_DATABASE_URL",
):
    value = os.environ.get(name)
    if value and target(value) == owned:
        sys.exit(
            f"CASEWORK_REVIEW_EXAMPLES_DATABASE_URL must not alias {name}; "
            "that suite resets public"
        )
'

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

# J2 / I8: maintained BReg adapter and exact source-owned manual application
# across the real BReg and Casework routers.
cargo test --locked -p registry-casework --features postgres-test \
  --test breg_review_journey -- --nocapture
# J4 / I1 / I3: a source-independent payment producer guards release with the
# exact producer-owned subject and terminal review result.
cargo test --locked -p registry-casework --features postgres-test \
  --test review_payment_fixture_postgres -- --nocapture
cargo test --locked -p registry-casework --features postgres-test \
  --test review_postgres standalone_structured_answers_support_polling_and_completion_modes \
  -- --nocapture

# J1 / J5 / I12: installed binaries author, migrate, diagnose, serve, and
# restart a standalone review while retaining pending and terminal state. The
# companion also drives candidate Node and Python Casework facades over HTTP.
products/casework/scripts/check-review-journeys.sh

# J3 / I7 and J6 / I10 remain in the existing BReg PostgreSQL executor, Rhai,
# WASM, planner, and task-grant gates. This aggregate composes with those gates
# without copying their scenarios into a second harness.

echo "BReg, payment, and standalone review examples and paired configuration contracts passed."
