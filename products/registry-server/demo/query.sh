#!/usr/bin/env bash
set -euo pipefail

demo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$demo_dir/.run"

if [[ ! -d "$run_dir" || -L "$run_dir" ]]; then
  printf '%s\n' 'Registry Server demo is not running. Start demo/run.sh first.' >&2
  exit 2
fi

python3 "$demo_dir/support/demo.py" query --root "$run_dir"
