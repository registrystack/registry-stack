#!/usr/bin/env bash
# Shared by test-dev.sh and measure-throughput.sh: build or find messagingctl,
# write a starter package whose SMS provider is the example mock provider,
# start `rstack dev` on it, and always stop it and remove what it
# started. Source it; it defines functions and sets no shell options.

dev_repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
# shellcheck source-path=SCRIPTDIR/../../..
# shellcheck source=scripts/cargo-runtime-library-path.sh
. "$dev_repo_root/scripts/cargo-runtime-library-path.sh"

: "${dev_name:?set dev_name before sourcing dev-session.sh}"
dev_work=
dev_project=
dev_run=
dev_volume=
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
  local profile=debug
  if [[ " $* " == *" --release "* ]]; then
    profile=release
  fi
  local bin_dir="${CARGO_TARGET_DIR:-$dev_repo_root/target}/$profile"
  if [[ -z "${RSTACK_BIN:-}" || -z "${MESSAGINGCTL_BIN:-}" || -z "${MESSAGING_BIN:-}" ]]; then
    registry_cargo_build "$dev_repo_root" --locked --quiet \
      -p registry-rstack -p registry-messagingctl -p registry-messaging "$@"
  fi
  rstack_bin=${RSTACK_BIN:-"$bin_dir/rstack"}
  messagingctl_bin=${MESSAGINGCTL_BIN:-"$bin_dir/messagingctl"}
  export RSTACK_MESSAGINGCTL_BIN="$messagingctl_bin"
  export RSTACK_MESSAGING_BIN=${MESSAGING_BIN:-"$bin_dir/messaging"}
  for tool in "$rstack_bin" "$RSTACK_MESSAGINGCTL_BIN" "$RSTACK_MESSAGING_BIN"; do
    if [[ ! -x "$tool" ]]; then
      printf 'development executable is missing at %s\n' "$tool" >&2
      exit 2
    fi
  done
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
  # The script below does its own sends. Keep the starter's read-only scenario.
  python3 - "$dev_project/tests/scenarios.yaml" <<'SCENARIOS'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text().split("  - id: send-a-reminder-sms", 1)[0])
SCENARIOS
  export RSTACK_DEV_STATE_DIR="$dev_work/runs"
}

# Read one dotted member of a JSON document on standard input.
dev_member() {
  python3 -c 'import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    value = value[key]
print(value)' "$1"
}

dev_start() {
  local ready config metrics
  if ! ready=$("$rstack_bin" --format json dev start "$dev_project" 2>"$dev_work/dev.err"); then
    printf '%s\n' "$ready" >&2
    return 1
  fi
  dev_run=$(dev_member run_id <<<"$ready")
  dev_volume=$(dev_member database.volume <<<"$ready")
  dev_api=$(dev_member products.messaging <<<"$ready")
  dev_mailpit=$(dev_member sinks.mail-relay.url <<<"$ready")
  config=$(dev_member runtimeConfigs.messaging <<<"$ready")
  metrics=$(dev_member metricsListener.bind <"$config")
  dev_metrics="http://$metrics/metrics"
}

dev_header() {
  "$rstack_bin" --format json dev token "$dev_run" --as "$1" |
    python3 -c 'import json, sys
entry, = json.load(sys.stdin)["credentials"]
assert entry["product"] == "messaging"
print(entry["header_file"])'
}

dev_containers() {
  docker ps --all --quiet --filter "label=org.registrystack.rstack.dev-run=$dev_run"
}

dev_stop() {
  local stopped
  stopped=$("$rstack_bin" --format json dev stop "$dev_run")
  if [[ "$(dev_member status <<<"$stopped")" != stopped || -n "$(dev_containers)" ]]; then
    printf '%s: the run did not stop and release its containers\n' "$dev_name" >&2
    return 1
  fi
  dev_run=
  dev_remove_volume
}

dev_remove_volume() {
  case "$dev_volume" in
    rstack-development-project-*)
      docker volume rm "$dev_volume" >/dev/null
      dev_volume=
      ;;
    '') ;;
    *) return 1 ;;
  esac
}

dev_cleanup() {
  local status=${1:-$?}
  if [[ -n "$dev_run" ]]; then
    "$rstack_bin" --format json dev stop "$dev_run" >/dev/null 2>&1 ||
      "$rstack_bin" --format json dev stop "$dev_run" --recover >/dev/null 2>&1 || :
  fi
  dev_remove_volume || :
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
