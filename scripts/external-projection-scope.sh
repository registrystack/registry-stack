#!/usr/bin/env bash
set -euo pipefail

usage() {
	printf '%s\n' 'Usage: external-projection-scope.sh inspect SERVICE PROJECTION' \
		'       external-projection-scope.sh withdraw SERVICE PROJECTION EPOCH PACKAGE_DIGEST ACTIVATION_UUID' \
		'       external-projection-scope.sh rotate SERVICE PROJECTION EPOCH PACKAGE_DIGEST ACTIVATION_UUID BINDING_DIGEST GRANT_DIGEST TTL_SECONDS' \
		'Use unbound for EPOCH only when inspect reports a null epoch. SERVICE must use the migration role.' >&2
	exit 2
}
[[ $# -ge 3 ]] || usage
action=$1
service=$2
projection=$3
[[ "$service" =~ ^[A-Za-z0-9_-]+$ ]] || usage
case "$action" in
inspect) [[ $# -eq 3 ]] || usage ;;
withdraw) [[ $# -eq 6 ]] || usage ;;
rotate) [[ $# -eq 9 ]] || usage ;;
*) usage ;;
esac
psql --no-psqlrc --dbname="service=$service" --set=ON_ERROR_STOP=1 \
	--set=action="$action" --set=projection="$projection" --set=epoch="${4:-unbound}" \
	--set=package="${5:-}" --set=activation="${6:-}" --set=binding="${7:-}" \
	--set=grant="${8:-}" --set=ttl="${9:-}" <<'SQL'
BEGIN;
SET LOCAL lock_timeout='10s';
SET LOCAL statement_timeout='30s';
SELECT jsonb_pretty(registry_internal.maintain_external_projection_scope(
  :'action', :'projection', NULLIF(:'epoch','unbound')::uuid,
  NULLIF(:'package',''), NULLIF(:'activation','')::uuid,
  NULLIF(:'binding',''), NULLIF(:'grant',''),
  NULLIF(:'ttl','')::bigint));
COMMIT;
SQL
