#!/usr/bin/env bash
set -euo pipefail

quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

bash -n "$quickstart_dir/run.sh"
bash -n "$quickstart_dir/query.sh"
python3 -m py_compile "$quickstart_dir/support/quickstart.py"
python3 "$quickstart_dir/support/quickstart.py" self-test --quickstart-dir "$quickstart_dir"

printf '%s\n' 'Registry Server generic quickstart self-test passed'
