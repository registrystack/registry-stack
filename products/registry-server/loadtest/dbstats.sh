#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$loadtest_dir/.run"

if [[ ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' "no load-test environment at $run_dir/env.json; run up.sh first" >&2
  exit 2
fi

read -r container database < <(python3 - "$run_dir/env.json" <<'PY'
import json
import sys

environment = json.load(open(sys.argv[1], encoding="utf-8"))
print(environment["database"]["container"], environment["database"]["database"])
PY
)

psql_exec() {
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -q -U postgres -d "$database"
}

printf '%s\n' '== Top statements by total execution time (pg_stat_statements)'
psql_exec <<'SQL'
SELECT round(total_exec_time::numeric, 1) AS total_ms,
       round(mean_exec_time::numeric, 2) AS mean_ms,
       calls,
       left(regexp_replace(query, '[\n\r\t ]+', ' ', 'g'), 110) AS query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 15;
SQL

printf '%s\n' '== Lock waits touching the audit chain head right now'
psql_exec <<'SQL'
SELECT wait_event_type,
       wait_event,
       count(*) AS waiters
FROM pg_stat_activity
WHERE wait_event IS NOT NULL
  AND query ILIKE '%registry_audit%'
GROUP BY wait_event_type, wait_event
ORDER BY waiters DESC;
SQL

printf '%s\n' '== Audit chain and record table sizes'
psql_exec <<'SQL'
SELECT relname,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       n_live_tup,
       n_dead_tup
FROM pg_stat_user_tables
WHERE relname LIKE 'registry_audit%' OR relname LIKE 'rs_e_%'
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 10;
SQL

printf '%s\n' '== Audit chain length'
psql_exec <<'SQL'
SELECT count(*) AS audit_rows FROM registry_internal.registry_audit;
SQL
