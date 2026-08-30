#!/usr/bin/env bash
set -euo pipefail

demo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$demo_dir/.run"
suite="${1:-all}"

if [[ "$suite" != all && "$suite" != operator && "$suite" != viewer ]] || [[ $# -gt 1 ]]; then
  printf '%s\n' 'usage: products/registry-server/demo/query.sh [all|operator|viewer]' >&2
  exit 2
fi

if [[ ! -d "$run_dir" || -L "$run_dir" ]]; then
  printf '%s\n' 'Registry Server demo is not running. Start demo/run.sh first.' >&2
  exit 2
fi

python3 "$demo_dir/support/demo.py" query --root "$run_dir" --suite "$suite"
