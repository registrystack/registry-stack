#!/usr/bin/env bash
set -euo pipefail

demo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$demo_dir/.run"
fixture_kind=business-establishments
suite=all
usage='usage: products/breg/demo/query.sh [--fixture business-establishments|household|asset-site|asset-change-request|facility|inspection] [all|operator|viewer|planner|submitter|reviewer|supervisor|applier|inspector]'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      if [[ $# -lt 2 ]]; then
        printf '%s\n' "$usage" >&2
        exit 2
      fi
      fixture_kind="$2"
      shift 2
      ;;
    all|operator|viewer|planner|submitter|reviewer|supervisor|applier|inspector)
      suite="$1"
      shift
      ;;
    *)
      printf '%s\n' "$usage" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$run_dir" || -L "$run_dir" ]]; then
  printf '%s\n' 'Base Registry Engine demo is not running. Start demo/run.sh first.' >&2
  exit 2
fi

case "$fixture_kind:$suite" in
  business-establishments:all|business-establishments:operator|business-establishments:viewer|household:all|household:operator|household:viewer|asset-site:all|asset-site:operator|asset-site:planner|asset-change-request:all|asset-change-request:planner|asset-change-request:submitter|asset-change-request:reviewer|asset-change-request:supervisor|asset-change-request:applier|facility:all|facility:operator|inspection:all|inspection:inspector) ;;
  *)
    printf '%s\n' 'the selected query suite is not available for that fixture.' >&2
    exit 2
    ;;
esac

python3 "$demo_dir/support/demo.py" query --root "$run_dir" --fixture-kind "$fixture_kind" --suite "$suite"
