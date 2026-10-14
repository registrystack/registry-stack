#!/usr/bin/env bash
set -euo pipefail

quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$quickstart_dir/.run"
action="${1:-list}"

case "$action" in
  create)
    shift
    if [[ $# -gt 2 ]]; then
      printf '%s\n' 'usage: products/breg/quickstart/query.sh create [NAME [EMAIL]]' >&2
      exit 2
    fi
    name="${1:-Quickstart contact}"
    email="${2:-contact@example.test}"
    python3 "$quickstart_dir/support/quickstart.py" request \
      --root "$run_dir" \
      --action create \
      --name "$name" \
      --email "$email"
    ;;
  get)
    shift
    if [[ $# -ne 1 ]]; then
      printf '%s\n' 'usage: products/breg/quickstart/query.sh get RECORD_ID' >&2
      exit 2
    fi
    python3 "$quickstart_dir/support/quickstart.py" request \
      --root "$run_dir" \
      --action get \
      --record-id "$1"
    ;;
  list)
    shift
    if [[ $# -ne 0 ]]; then
      printf '%s\n' 'usage: products/breg/quickstart/query.sh list' >&2
      exit 2
    fi
    python3 "$quickstart_dir/support/quickstart.py" request \
      --root "$run_dir" \
      --action list
    ;;
  all)
    shift
    if [[ $# -ne 0 ]]; then
      printf '%s\n' 'usage: products/breg/quickstart/query.sh all' >&2
      exit 2
    fi
    created_id=$(python3 "$quickstart_dir/support/quickstart.py" request \
      --root "$run_dir" \
      --action create \
      --name "Quickstart contact" \
      --email "contact@example.test")
    python3 "$quickstart_dir/support/quickstart.py" request \
      --root "$run_dir" \
      --action get \
      --record-id "$created_id"
    ;;
  *)
    printf '%s\n' 'usage: products/breg/quickstart/query.sh [list|all|create [NAME [EMAIL]]|get RECORD_ID]' >&2
    exit 2
    ;;
esac
