#!/usr/bin/env bash
# Shared by test-dev.sh and measure-throughput.sh: build or find messagingctl,
# write a starter package whose SMS provider is the example mock provider,
# start `messagingctl dev` on it, and always stop it and remove what it
# started. Source it; it defines functions and sets no shell options.

dev_repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
# shellcheck source-path=SCRIPTDIR/../../..
# shellcheck source=scripts/cargo-runtime-library-path.sh
. "$dev_repo_root/scripts/cargo-runtime-library-path.sh"

: "${dev_name:?set dev_name before sourcing dev-session.sh}"
dev_work=
dev_project=
dev_pid=
# Set by dev_start and read by the sourcing script.
# shellcheck disable=SC2034
{
  dev_api=
  dev_mailpit=
  dev_metrics=
}

dev_log() {
  printf '%s: %s\n' "$dev_name" "$1"
}

# Build messagingctl with the given Cargo profile flags unless
# MESSAGINGCTL_BIN names one, and create the work directory.
dev_prepare() {
  local tool
  for tool in docker curl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      printf '%s: %s is required\n' "$dev_name" "$tool" >&2
      exit 2
    fi
  done
  if [[ -n "${MESSAGINGCTL_BIN:-}" ]]; then
    messagingctl_bin=$MESSAGINGCTL_BIN
  else
    registry_cargo_build "$dev_repo_root" --locked --quiet -p registry-messagingctl "$@"
    local profile=debug
    if [[ " $* " == *" --release "* ]]; then
      profile=release
    fi
    messagingctl_bin="${CARGO_TARGET_DIR:-$dev_repo_root/target}/$profile/messagingctl"
  fi
  if [[ ! -x "$messagingctl_bin" ]]; then
    printf 'messagingctl is not executable at %s\n' "$messagingctl_bin" >&2
    exit 2
  fi
  dev_work=$(mktemp -d "${TMPDIR:-/tmp}/messaging-dev.XXXXXX")
  chmod 700 "$dev_work"
  dev_project="$dev_work/project"
  trap dev_cleanup EXIT HUP INT TERM

  "$messagingctl_bin" init "$dev_project" >/dev/null
  rm -r -- "$dev_project/providers/sms-gateway"
  mkdir -p "$dev_project/providers/sms-gateway"
  cp "$dev_repo_root/products/messaging/examples/providers/mock/provider.yaml" \
    "$dev_project/providers/sms-gateway/provider.yaml"
  cp -R "$dev_repo_root/products/messaging/examples/providers/mock/scripts" \
    "$dev_project/providers/sms-gateway/scripts"
}

# Read one dotted member of a JSON document on standard input.
dev_member() {
  python3 -c 'import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    value = value[key]
print(value)' "$1"
}

dev_free_port() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])'
}

# Start the session with any extra `dev` arguments and wait for its ready
# report. Sets dev_api, dev_mailpit, and dev_metrics.
# shellcheck disable=SC2034
dev_start() {
  local ready_seconds=${MESSAGING_DEV_READY_SECONDS:-600}
  local api_port metrics_port
  api_port=$(dev_free_port)
  metrics_port=$(dev_free_port)
  "$messagingctl_bin" dev "$dev_project" --port "$api_port" \
    --metrics-port "$metrics_port" --format json "$@" \
    >"$dev_work/dev.out" 2>"$dev_work/dev.err" &
  dev_pid=$!
  local deadline=$((SECONDS + ready_seconds))
  until grep -q '"state":"ready"' "$dev_work/dev.out" 2>/dev/null; do
    if ! kill -0 "$dev_pid" 2>/dev/null; then
      printf '%s: the session stopped before it was ready\n' "$dev_name" >&2
      cat "$dev_work/dev.out" >&2
      exit 1
    fi
    if ((SECONDS > deadline)); then
      printf '%s: the session was not ready in %s seconds\n' "$dev_name" "$ready_seconds" >&2
      exit 1
    fi
    sleep 1
  done
  local ready
  ready=$(head -n 1 "$dev_work/dev.out")
  dev_api=$(dev_member api <<<"$ready")
  dev_mailpit=$(dev_member mailpit <<<"$ready")
  dev_metrics=$(dev_member metrics <<<"$ready")
}

# Stop the session with SIGINT and require a clean stop that removed every
# container it started.
dev_stop() {
  kill -INT "$dev_pid"
  wait "$dev_pid"
  dev_pid=
  local stopped state removed owner left
  stopped=$(tail -n 1 "$dev_work/dev.out")
  state=$(dev_member state <<<"$stopped")
  removed=$(dev_member containersRemoved <<<"$stopped")
  if [[ "$state" != stopped || "$removed" != True ]]; then
    printf '%s: the session did not report a clean stop: %s\n' "$dev_name" "$stopped" >&2
    exit 1
  fi
  owner=$(dev_member owner <"$dev_project/.messaging/dev/session.json")
  left=$(docker ps --all --quiet --filter "label=org.registrystack.messagingctl.dev-owner=$owner")
  if [[ -n "$left" ]]; then
    printf '%s: the session left containers behind\n' "$dev_name" >&2
    exit 1
  fi
}

# Stop the session if it still runs, then remove any container its record
# names, so a failed run leaves nothing behind.
dev_cleanup() {
  local status=$?
  if [[ -n "$dev_pid" ]] && kill -0 "$dev_pid" 2>/dev/null; then
    kill -INT "$dev_pid" 2>/dev/null || :
    local _
    for _ in $(seq 1 60); do
      kill -0 "$dev_pid" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL "$dev_pid" 2>/dev/null || :
  fi
  local record="$dev_project/.messaging/dev/session.json"
  if [[ -n "$dev_project" && -f "$record" ]]; then
    python3 - "$record" <<'PY' | while IFS= read -r container; do docker rm --force --volumes "$container" >/dev/null 2>&1 || :; done
import json, sys
for container in json.load(open(sys.argv[1]))["containers"]:
    print(container)
PY
  fi
  if [[ $status -ne 0 && -f "$dev_work/dev.err" ]]; then
    printf '%s: session error output:\n' "$dev_name" >&2
    cat "$dev_work/dev.err" >&2
  fi
  case "$dev_work" in
  "${TMPDIR:-/tmp}"/messaging-dev.*) rm -rf -- "$dev_work" ;;
  '') ;;
  *) exit 1 ;;
  esac
}
