#!/bin/sh
# Opt-in network gate for the optional public-source continuation in the HTTP tutorial.
set -eu

if [ "${REGISTRYCTL_PUBLIC_SOURCE_LIVE:-0}" != "1" ]; then
  printf '%s\n' \
    'SKIP public-source live gate (set REGISTRYCTL_PUBLIC_SOURCE_LIVE=1 to opt in)'
  exit 0
fi

case "${REGISTRYCTL_BIN:-}" in
  /*) ;;
  *)
    printf '%s\n' \
      'REGISTRYCTL_BIN must be an absolute installed-binary path' >&2
    exit 1
    ;;
esac

for command in curl docker; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '%s\n' "$command is required for the public-source live gate" >&2
    exit 1
  fi
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SITE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OVERLAY="$SITE_ROOT/public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh"
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/registryctl-public-source.XXXXXX")
PROJECT="$WORK_ROOT/public-json-live-demo"
EVIDENCE_ROOT="${REGISTRYCTL_PUBLIC_SOURCE_EVIDENCE_DIR:-$WORK_ROOT/evidence}"
ACTIVE_ENVIRONMENT=

run_report() {
  report=$1
  shift
  if ! "$@" >"$report" 2>&1; then
    sed -n '1,80p' "$report" >&2
    return 1
  fi
}

cleanup() {
  if [ -n "$ACTIVE_ENVIRONMENT" ] && [ -d "$PROJECT" ]; then
    "$REGISTRYCTL_BIN" -C "$PROJECT" dev \
      --environment "$ACTIVE_ENVIRONMENT" down >/dev/null 2>&1 || true
  fi
  rm -r "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

if [ -n "${REGISTRYCTL_PUBLIC_SOURCE_EVIDENCE_DIR:-}" ]; then
  case "$EVIDENCE_ROOT" in
    /*) ;;
    *)
      printf '%s\n' \
        'REGISTRYCTL_PUBLIC_SOURCE_EVIDENCE_DIR must be absolute' >&2
      exit 1
      ;;
  esac
  if [ -e "$EVIDENCE_ROOT" ]; then
    printf '%s\n' \
      "public-source evidence directory must be absent: $EVIDENCE_ROOT" >&2
    exit 1
  fi
fi
mkdir -p "$EVIDENCE_ROOT"

run_report "$EVIDENCE_ROOT/init.txt" \
  "$REGISTRYCTL_BIN" init "$PROJECT" --template http
rm -r "$PROJECT/integrations/person-record"
(
  cd "$PROJECT"
  sh "$OVERLAY"
) >"$EVIDENCE_ROOT/overlay.txt" 2>&1

run_report "$EVIDENCE_ROOT/offline-test.txt" \
  "$REGISTRYCTL_BIN" -C "$PROJECT" test --environment local
run_report "$EVIDENCE_ROOT/public-demo-check.txt" \
  "$REGISTRYCTL_BIN" -C "$PROJECT" check \
  --environment public-demo --explain
run_report "$EVIDENCE_ROOT/public-demo-missing-check.txt" \
  "$REGISTRYCTL_BIN" -C "$PROJECT" check \
  --environment public-demo-missing --explain

success_status=$(curl --silent --show-error \
  --output "$EVIDENCE_ROOT/public-todo-4.json" \
  --write-out '%{http_code}' \
  https://jsonplaceholder.typicode.com/todos/4)
if [ "$success_status" != "200" ]; then
  printf '%s\n' "public success control returned HTTP $success_status, expected 200" >&2
  exit 1
fi
for expected in '"id": 4' '"completed": true'; do
  if ! grep -F "$expected" "$EVIDENCE_ROOT/public-todo-4.json" >/dev/null; then
    printf '%s\n' "public success control omitted $expected" >&2
    exit 1
  fi
done

missing_status=$(curl --silent --show-error \
  --output "$EVIDENCE_ROOT/public-todo-999999.json" \
  --write-out '%{http_code}' \
  https://jsonplaceholder.typicode.com/todos/999999)
if [ "$missing_status" != "404" ]; then
  printf '%s\n' "public negative control returned HTTP $missing_status, expected 404" >&2
  exit 1
fi

for environment in public-demo public-demo-missing; do
  ACTIVE_ENVIRONMENT=$environment
  run_report "$EVIDENCE_ROOT/$environment-start.txt" \
    "$REGISTRYCTL_BIN" -C "$PROJECT" dev \
    --environment "$environment" --detach
  run_report "$EVIDENCE_ROOT/$environment-smoke.txt" \
    "$REGISTRYCTL_BIN" -C "$PROJECT" dev \
    --environment "$environment" smoke
  grep -F 'Development smoke: passed.' \
    "$EVIDENCE_ROOT/$environment-smoke.txt" >/dev/null
  grep -F 'status=authorized; passed=true; token_counter_delta=unobserved; source_counter_delta=unobserved' \
    "$EVIDENCE_ROOT/$environment-smoke.txt" >/dev/null
  run_report "$EVIDENCE_ROOT/$environment-down.txt" \
    "$REGISTRYCTL_BIN" -C "$PROJECT" dev \
    --environment "$environment" down
  ACTIVE_ENVIRONMENT=
done

if [ -n "${REGISTRYCTL_PUBLIC_SOURCE_EVIDENCE_DIR:-}" ]; then
  printf '%s\n' \
    "PASS public-source live gate; evidence retained at $EVIDENCE_ROOT"
else
  printf '%s\n' 'PASS public-source live gate'
fi
