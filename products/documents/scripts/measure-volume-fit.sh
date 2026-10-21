#!/usr/bin/env bash
set -euo pipefail

# Volume fit of PostgreSQL bytea storage: populate DOCUMENTS documents of
# BYTES bytes each through the runtime's own routes, then report the
# database size, the custom-format dump size and time, and the restore time
# and restored size, as one JSON object on stdout.
#
# The server is named by the standard libpq variables (PGHOST, PGPORT,
# PGUSER, and PGPASSWORD or PGPASSFILE); no credential is taken on the
# command line. The script creates two databases, NAME_source and
# NAME_restored, refuses to start if either exists, and drops only those two
# when it exits. Timings depend on the host and its load; the sizes do not.

usage() {
  printf 'usage: %s DOCUMENTS BYTES [NAME]\n' "${0##*/}" >&2
  exit 2
}
[[ "$#" == 2 || "$#" == 3 ]] || usage
documents=$1
bytes=$2
name=${3:-documents_volume}
[[ "$documents" =~ ^[1-9][0-9]*$ && "$bytes" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$name" =~ ^[a-z_][a-z0-9_]{0,40}$ ]] || {
  printf 'NAME must be a lowercase PostgreSQL identifier\n' >&2
  exit 2
}
for command in psql pg_dump pg_restore cargo python3; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s is required\n' "$command" >&2
    exit 2
  }
done
: "${PGHOST:?PGHOST names the PostgreSQL server}"
: "${PGUSER:?PGUSER names a role that may create databases}"
export PGPORT=${PGPORT:-5432}

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
source_database="${name}_source"
restored_database="${name}_restored"
created=()
work=""

cleanup() {
  local status=$?
  local database
  for database in "${created[@]}"; do
    psql -X -q -d postgres -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS \"$database\" WITH (FORCE)" ||
      printf 'could not drop %s\n' "$database" >&2
  done
  if [[ -n "$work" ]]; then
    rm -f -- "$work/source.dump" "$work/populate.out"
    rmdir -- "$work" || printf 'could not remove %s\n' "$work" >&2
  fi
  return "$status"
}
trap cleanup EXIT

now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }
scalar() { psql -X -q -A -t -d "$1" -v ON_ERROR_STOP=1 -c "$2"; }

for database in "$source_database" "$restored_database"; do
  exists=$(scalar postgres "SELECT count(*) FROM pg_database WHERE datname = '$database'")
  [[ "$exists" == 0 ]] || {
    printf 'database %s already exists; choose another NAME\n' "$database" >&2
    exit 1
  }
done
for database in "$source_database" "$restored_database"; do
  psql -X -q -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$database\""
  created+=("$database")
done
temporary_root=$(CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P)
work=$(mktemp -d "$temporary_root/documents-volume.XXXXXX")

printf 'populating %s documents of %s bytes\n' "$documents" "$bytes" >&2
DOCUMENTS_TEST_DATABASE_URL=$(python3 -c '
import os, sys, urllib.parse
password = os.environ.get("PGPASSWORD")
auth = urllib.parse.quote(os.environ["PGUSER"], safe="")
if password:
    auth += ":" + urllib.parse.quote(password, safe="")
host, port = os.environ["PGHOST"], os.environ["PGPORT"]
print("postgresql://%s@%s:%s/%s" % (auth, host, port, sys.argv[1]))
' "$source_database")
export DOCUMENTS_TEST_DATABASE_URL
DOCUMENTS_VOLUME_DOCUMENTS=$documents DOCUMENTS_VOLUME_BYTES=$bytes \
  cargo test --locked --quiet --manifest-path "$repo_root/Cargo.toml" \
  -p registry-documents --features postgres-test --test volume_fit -- \
  --ignored --exact --nocapture populate_bytea_storage_for_the_volume_fit_measurement \
  >"$work/populate.out"
unset DOCUMENTS_TEST_DATABASE_URL
populated=$(grep '^{"' "$work/populate.out" | tail -n 1)
[[ -n "$populated" ]] || {
  printf 'the populating test printed no report\n' >&2
  exit 1
}
schema=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["schema"])' "$populated")

printf 'dumping %s\n' "$source_database" >&2
psql -X -q -d "$source_database" -v ON_ERROR_STOP=1 -c CHECKPOINT
dump_started=$(now)
pg_dump --format=custom --no-owner --no-privileges --file="$work/source.dump" "$source_database"
dump_finished=$(now)
dump_bytes=$(python3 -c 'import os, sys; print(os.path.getsize(sys.argv[1]))' "$work/source.dump")

printf 'restoring into %s\n' "$restored_database" >&2
restore_started=$(now)
pg_restore --no-owner --no-privileges --exit-on-error --dbname="$restored_database" "$work/source.dump"
restore_finished=$(now)
psql -X -q -d "$restored_database" -v ON_ERROR_STOP=1 -c ANALYZE

check="SELECT count(*) || ':' || sum(octet_length(content)) || ':' || md5(string_agg(md5(content), '' ORDER BY version_id)) FROM \"$schema\".documents_contents"
source_check=$(scalar "$source_database" "$check")
restored_check=$(scalar "$restored_database" "$check")
[[ "$source_check" == "$restored_check" ]] || {
  printf 'the restored contents differ from the source\n' >&2
  exit 1
}
restored_bytes=$(scalar "$restored_database" "SELECT pg_database_size(current_database())")
server_version=$(scalar postgres "SHOW server_version")

python3 - "$populated" "$dump_bytes" "$dump_started" "$dump_finished" \
  "$restore_started" "$restore_finished" "$restored_bytes" "$server_version" <<'PY'
import json
import sys

report = json.loads(sys.argv[1])
dump_bytes = int(sys.argv[2])
dump_started, dump_finished, restore_started, restore_finished = map(float, sys.argv[3:7])
report.pop("schema")
payload = report["payloadBytes"]
documents = report["documents"]
report.update({
    "serverVersion": sys.argv[8],
    "dumpFormat": "custom, default compression",
    "dumpBytes": dump_bytes,
    "dumpSeconds": round(dump_finished - dump_started, 3),
    "restoreSeconds": round(restore_finished - restore_started, 3),
    "restoredDatabaseBytes": int(sys.argv[7]),
    "restoredContentsMatch": True,
    "databaseBytesPerDocument": round((report["databaseBytes"] - report["emptyDatabaseBytes"]) / documents),
    "overheadBytesPerDocument": round((report["databaseBytes"] - report["emptyDatabaseBytes"] - payload) / documents),
    "databaseToPayloadRatio": round((report["databaseBytes"] - report["emptyDatabaseBytes"]) / payload, 4),
    "dumpToPayloadRatio": round(dump_bytes / payload, 4),
})
report["populateSeconds"] = round(report["populateSeconds"], 3)
print(json.dumps(report, indent=2))
PY
