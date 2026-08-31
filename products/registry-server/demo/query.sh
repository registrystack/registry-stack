#!/usr/bin/env bash
set -euo pipefail

demo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$demo_dir/.run"
fixture_kind=household
suite=all

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      if [[ $# -lt 2 ]]; then
        printf '%s\n' 'usage: products/registry-server/demo/query.sh [--fixture household|asset-site] [all|operator|viewer|planner]' >&2
        exit 2
      fi
      fixture_kind="$2"
      shift 2
      ;;
    all|operator|viewer|planner)
      suite="$1"
      shift
      ;;
    *)
      printf '%s\n' 'usage: products/registry-server/demo/query.sh [--fixture household|asset-site] [all|operator|viewer|planner]' >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$run_dir" || -L "$run_dir" ]]; then
  printf '%s\n' 'Registry Server demo is not running. Start demo/run.sh first.' >&2
  exit 2
fi

case "$fixture_kind:$suite" in
  household:all|household:operator|household:viewer|asset-site:all|asset-site:operator|asset-site:planner) ;;
  *)
    printf '%s\n' 'the selected query suite is not available for that fixture.' >&2
    exit 2
    ;;
esac

python3 "$demo_dir/support/demo.py" query --root "$run_dir" --fixture-kind "$fixture_kind" --suite "$suite"
