#!/usr/bin/env bash
set -euo pipefail

# Proves the native adopter path for one declared statistical dataset. The
# local issuer issues each credential through its real token endpoint with the
# retained private-key-JWT client key. Records and statistics then use only the
# public HTTP and bregctl surfaces.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
. "$repository_root/scripts/cargo-runtime-library-path.sh"

temporary_root=""
temporary_base=$(cd -- "${TMPDIR:-/tmp}" && pwd -P)
project=""
bregctl=${BREGCTL_BIN:-"$repository_root/target/debug/bregctl"}
breg=${BREG_BIN:-"$repository_root/target/debug/breg"}

fail() {
  printf 'statistics workflow failed: %s\n' "$1" >&2
  exit 1
}

checkpoint() {
  printf 'statistics workflow: %s\n' "$1" >&2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

cleanup() {
  local exit_code=$?
  if [[ -n "$project" && -d "$project" && -x "$bregctl" ]]; then
    "$bregctl" dev stop --remove --docker-bin "$(command -v docker 2>/dev/null || true)" \
      "$project" >/dev/null 2>&1 || true
  fi
  case "$temporary_root" in
    "$temporary_base"/breg-statistics-workflow.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *) printf 'statistics workflow kept unexpected temporary root: %s\n' "$temporary_root" >&2 ;;
  esac
  return "$exit_code"
}
trap cleanup EXIT HUP INT TERM

if [[ "$#" -ne 0 ]]; then
  printf '%s\n' 'usage: test-statistics-workflow.sh' >&2
  exit 2
fi

require_command docker
require_command python3
umask 077
temporary_root=$(mktemp -d "$temporary_base/breg-statistics-workflow.XXXXXX")
project="$temporary_root/facility"
cp -R "$repository_root/products/breg/acceptance/facility" "$project"

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

checkpoint "building the native binaries"
if [[ "${BREG_SKIP_BUILD:-0}" != "1" ]]; then
  registry_cargo_build "$repository_root" \
    --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-bregctl -p registry-breg --features registry-breg/runtime
else
  registry_prepare_cargo_runtime "$repository_root" \
    --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-bregctl -p registry-breg --features registry-breg/runtime
fi
[[ -x "$bregctl" && -x "$breg" ]] || fail "the native binaries are not executable"

read -r database_port issuer_port breg_port < <(python3 - <<'PY'
import socket
sockets = []
ports = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])
print(*ports)
for sock in sockets:
    sock.close()
PY
)

checkpoint "starting the facility project and its local issuer"
if ! "$bregctl" --format json dev start \
  --breg-bin "$breg" --docker-bin "$(command -v docker)" \
  --breg-port "$breg_port" --issuer-port "$issuer_port" --database-port "$database_port" \
  "$project" >"$temporary_root/dev.json"; then
  cat "$temporary_root/dev.json" >&2
  fail "bregctl dev start did not reach ready"
fi
breg_url=$(python3 - "$temporary_root/dev.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("ok") is not True or report.get("status") != "ready":
    raise SystemExit("bregctl dev did not reach ready")
for member in ("bregUrl", "tokenEndpoint", "clientAssertionAudience", "resource"):
    if not isinstance(report.get(member), str) or not report[member]:
        raise SystemExit(f"bregctl dev omitted {member}")
print(report["bregUrl"])
PY
)

checkpoint "acquiring private-key-JWT client credentials from the token endpoint"
for client in facility-operator statistics-publisher statistics-reader; do
  "$bregctl" --format json dev token "$client" "$project" >"$temporary_root/$client-token.json"
  python3 - "$temporary_root/$client-token.json" "$temporary_root/$client-token" <<'PY'
import json, os, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("ok") is not True or report.get("command") != "dev token":
    raise SystemExit("the dev issuer token request failed")
line = open(report["headerFile"], encoding="ascii").read().strip()
prefix = "Authorization: Bearer "
if not line.startswith(prefix) or len(line[len(prefix):].split(".")) != 3:
    raise SystemExit("the dev issuer did not return a compact bearer token")
with open(sys.argv[2], "w", encoding="ascii") as output:
    output.write(line[len(prefix):])
os.chmod(sys.argv[2], 0o600)
PY
done

checkpoint "seeding five countable January discharge reports through authenticated HTTP"
python3 - "$breg_url" "$temporary_root/facility-operator-token" <<'PY'
import json, sys, urllib.parse, urllib.request

origin, token_file = sys.argv[1:]
token = open(token_file, encoding="ascii").read().strip()

def create(route, key, data):
    request = urllib.request.Request(
        origin + route + "?accessProfile=facility-operator",
        data=json.dumps({"data": data}, separators=(",", ":"), sort_keys=True).encode(),
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Idempotency-Key": f"statistics-workflow-{key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 201:
            raise SystemExit(f"{route} returned {response.status}")
        document = json.load(response)
    identifier = document.get("data", {}).get("recordIdentifier")
    if not isinstance(identifier, str) or not identifier:
        raise SystemExit(f"{route} omitted its record identifier")
    return identifier

facility = create("/v1/records/facilities", "facility", {
    "facilityCode":"FACILITY-STATISTICS-001",
    "displayName":"Statistics workflow facility",
    "administrativeBoundary":"north-district",
})
permit = create("/v1/records/permits", "permit", {
    "permitNumber":"PERMIT-STATISTICS-001", "facility":facility,
    "permitType":"water-discharge", "validFrom":"2024-01-01",
    "administrativeBoundary":"north-district", "importSource":"statistics-workflow",
    "sourceRecordId":"permit-statistics-001",
})
for number in range(1, 6):
    installation = create("/v1/records/installations", f"installation-{number}", {
        "installationCode":f"INSTALLATION-STATISTICS-{number:03d}", "permit":permit,
        "administrativeBoundary":"north-district",
        "centroid":{"type":"Point","coordinates":[30.5,-9.5]},
        "areaValue":"1.0000", "areaUnit":"hectare", "importSource":"statistics-workflow",
        "sourceRecordId":f"installation-statistics-{number:03d}",
    })
    create("/v1/records/discharge-reports", f"report-{number}", {
        "installation":installation, "administrativeBoundary":"north-district",
        "substanceCode":"nitrogen", "periodStart":"2025-01-01", "periodEnd":"2025-02-01",
        "quantityValue":"1.000", "quantityUnit":"kilogram",
    })
PY

checkpoint "publishing the ended period with the public CLI"
if ! "$bregctl" --format json statistics publish \
  --breg-url "$breg_url" \
  --access-token-file "$temporary_root/statistics-publisher-token" \
  --dataset monthly-discharge-reports --period 2025-01 --status final \
  --profile statistics-publisher \
  --idempotency-key 8a2c2c35-354f-43d5-83a4-7cbe39a5f2f0 \
  >"$temporary_root/publish.json"; then
  cat "$temporary_root/publish.json" >&2
  fail "statistics publish did not complete"
fi
python3 - "$temporary_root/publish.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("ok") is not True or report.get("command") != "statistics publish":
    raise SystemExit("statistics publish did not complete")
if report.get("period") != "2025-01" or report.get("version") != 1 or report.get("status") != "final":
    raise SystemExit(f"statistics publish returned the wrong release: {report}")
PY

checkpoint "reading JSON, CSV, released series, and live authorization boundaries"
python3 - "$breg_url" "$temporary_root/statistics-reader-token" "$temporary_root/facility-operator-token" <<'PY'
import csv, io, json, sys, urllib.error, urllib.request

origin, reader_file, operator_file = sys.argv[1:]
reader = open(reader_file, encoding="ascii").read().strip()
operator = open(operator_file, encoding="ascii").read().strip()

def get(path, token, accept="application/json", expected=200):
    request = urllib.request.Request(origin + path, headers={
        "Accept": accept, "Authorization": f"Bearer {token}",
    })
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status, body, headers = response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        status, body, headers = error.code, error.read(), error.headers
    if status != expected:
        raise SystemExit(f"GET {path} returned {status}, expected {expected}: {body[:500]!r}")
    return body, headers

latest_path = "/v1/statistics/monthly-discharge-reports/releases/2025-01?status=final&accessProfile=statistics-reader"
body, headers = get(latest_path, reader)
document = json.loads(body)
if document.get("release", {}).get("version") != 1 or document.get("release", {}).get("status") != "final":
    raise SystemExit("the dedicated reader did not receive the final release")
if not any(cell.get("value") == 5 for cell in document.get("cells", [])):
    raise SystemExit("the disclosed release did not contain the expected rounded count")
if not headers.get("Repr-Digest"):
    raise SystemExit("the JSON release omitted Repr-Digest")

csv_body, csv_headers = get(latest_path, reader, "text/csv")
rows = list(csv.reader(io.StringIO(csv_body.decode("utf-8"))))
expected_header = ["period", "periodStart", "periodEnd", "administrative-boundary", "has-measured-quantity", "value", "status"]
if not rows or rows[0] != expected_header or not any(row[-2] == "5" for row in rows[1:]):
    raise SystemExit(f"the CSV release was not the same disclosed count: {rows[:3]}")
if not csv_headers.get("Repr-Digest"):
    raise SystemExit("the CSV release omitted Repr-Digest")

series_path = "/v1/statistics/monthly-discharge-reports/releases:series?from=2025-01&to=2025-01&status=final&accessProfile=statistics-reader"
series_body, _ = get(series_path, reader)
series = json.loads(series_body)
if len(series.get("periods", [])) != 1 or series["periods"][0].get("version", {}).get("version") != 1:
    raise SystemExit("the released-series response did not select version 1")

live_path = "/v1/statistics/monthly-discharge-reports:live?from=2025-01&to=2025-01&accessProfile=facility-operator"
live_body, _ = get(live_path, operator)
if json.loads(live_body).get("live", {}).get("accessProfile") != "facility-operator":
    raise SystemExit("the live profile did not receive a live document")

refused_path = "/v1/statistics/monthly-discharge-reports:live?accessProfile=statistics-reader"
refused_body, _ = get(refused_path, reader, expected=404)
if json.loads(refused_body).get("code") != "resource.not_found":
    raise SystemExit("the release-only reader was not concealed from live mode")
PY

checkpoint "withdrawing the release with the public CLI"
if ! "$bregctl" --format json statistics withdraw \
  --breg-url "$breg_url" \
  --access-token-file "$temporary_root/statistics-publisher-token" \
  --dataset monthly-discharge-reports --period 2025-01 --version 1 \
  --reason source-data-error --profile statistics-publisher \
  --idempotency-key 6ce29952-dd3e-495c-949e-60bbca473dae \
  >"$temporary_root/withdraw.json"; then
  cat "$temporary_root/withdraw.json" >&2
  fail "statistics withdraw did not complete"
fi
python3 - "$temporary_root/withdraw.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("ok") is not True or report.get("command") != "statistics withdraw":
    raise SystemExit("statistics withdraw did not complete")
if report.get("dataset") != "monthly-discharge-reports" or report.get("period") != "2025-01" or report.get("version") != 1:
    raise SystemExit(f"statistics withdraw returned the wrong release: {report}")
if report.get("withdrawal", {}).get("reason") != "source-data-error":
    raise SystemExit(f"statistics withdraw returned the wrong reason: {report}")
PY

checkpoint "proving the dedicated reader receives the stable withdrawn response"
python3 - "$breg_url" "$temporary_root/statistics-reader-token" <<'PY'
import json, sys, urllib.error, urllib.request

origin, token_file = sys.argv[1:]
token = open(token_file, encoding="ascii").read().strip()
path = "/v1/statistics/monthly-discharge-reports/releases/2025-01/versions/1?accessProfile=statistics-reader"
request = urllib.request.Request(origin + path, headers={
    "Accept": "application/json", "Authorization": f"Bearer {token}",
})
try:
    urllib.request.urlopen(request, timeout=20)
except urllib.error.HTTPError as error:
    if error.code != 410:
        raise SystemExit(f"withdrawn release returned {error.code}, expected 410")
    problem = json.load(error)
else:
    raise SystemExit("withdrawn release remained readable")
if problem.get("code") != "statistical_dataset.version_withdrawn" or problem.get("reasonCode") != "source-data-error":
    raise SystemExit(f"withdrawn release returned the wrong Problem: {problem}")
PY

checkpoint "completed"
