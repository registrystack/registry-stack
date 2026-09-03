#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$loadtest_dir/.run"
action="${1:-snapshot}"
interval="${2:-1}"

case "$action" in
  reset|snapshot|sample|analyze) ;;
  *)
    printf '%s\n' 'usage: products/breg/loadtest/dbstats.sh reset|snapshot|sample [interval-seconds]|analyze' >&2
    exit 2
    ;;
esac
if [[ "$action" == sample && ! "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  printf '%s\n' 'sample interval must be a positive number of seconds' >&2
  exit 2
fi

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
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -q -U postgres -d "$database" "$@"
}

if [[ "$action" == reset ]]; then
  psql_exec -Atc 'SELECT pg_stat_statements_reset() IS NOT NULL;' >/dev/null
  exit 0
fi

if [[ "$action" == analyze ]]; then
  psql_exec -c 'ANALYZE;' >/dev/null
  exit 0
fi

if [[ "$action" == snapshot ]]; then
  psql_exec -At <<'SQL'
WITH top_statements AS (
  SELECT queryid::text AS "queryId",
         CASE
           WHEN strpos(lower(query), 'registry_audit_head') > 0 THEN 'audit-head'
           WHEN strpos(lower(query), 'registry_audit') > 0 THEN 'audit'
           WHEN strpos(lower(query), 'breg_e_') > 0 THEN 'record'
           ELSE 'other'
         END AS category,
         calls,
         round(total_exec_time::numeric, 3) AS "totalMs",
         round(mean_exec_time::numeric, 3) AS "meanMs",
         rows
  FROM pg_stat_statements
  WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
  ORDER BY total_exec_time DESC
  LIMIT 20
), table_sizes AS (
  SELECT relname AS name,
         pg_total_relation_size(relid) AS "totalBytes",
         n_live_tup AS "liveRows",
         n_dead_tup AS "deadRows"
  FROM pg_stat_user_tables
  WHERE strpos(relname, 'registry_audit') = 1 OR strpos(relname, 'breg_e_') = 1
  ORDER BY pg_total_relation_size(relid) DESC
  LIMIT 20
), current_waits AS (
  SELECT wait_event_type AS "type", wait_event AS event, count(*) AS waiters
  FROM pg_stat_activity
  WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event IS NOT NULL
  GROUP BY wait_event_type, wait_event
  ORDER BY waiters DESC
)
SELECT json_build_object(
  'timestamp', clock_timestamp(),
  'topStatements', COALESCE((SELECT json_agg(top_statements) FROM top_statements), '[]'::json),
  'currentWaits', COALESCE((SELECT json_agg(current_waits) FROM current_waits), '[]'::json),
  'tableSizes', COALESCE((SELECT json_agg(table_sizes) FROM table_sizes), '[]'::json),
  'auditRows', (SELECT count(*) FROM registry_internal.registry_audit)
)::text;
SQL
  exit 0
fi

while true; do
  psql_exec -At <<'SQL'
WITH activity AS (
  SELECT wait_event_type,
         wait_event,
         state,
         strpos(lower(query), 'registry_audit') > 0 AS audit_query,
         cardinality(pg_blocking_pids(pid)) > 0 AS blocked
  FROM pg_stat_activity
  WHERE datname = current_database() AND pid <> pg_backend_pid()
), waits AS (
  SELECT wait_event_type AS "type", wait_event AS event, count(*) AS waiters
  FROM activity
  WHERE wait_event IS NOT NULL
  GROUP BY wait_event_type, wait_event
  ORDER BY waiters DESC
)
SELECT json_build_object(
  'timestamp', clock_timestamp(),
  'auditLockWaiters', (SELECT count(*) FROM activity WHERE state = 'active' AND audit_query AND wait_event_type = 'Lock'),
  'lockWaiters', (SELECT count(*) FROM activity WHERE state = 'active' AND wait_event_type = 'Lock'),
  'blockedBackends', (SELECT count(*) FROM activity WHERE state = 'active' AND blocked),
  'waitEvents', COALESCE((SELECT json_agg(waits) FROM waits), '[]'::json)
)::text;
SQL
  sleep "$interval"
done
