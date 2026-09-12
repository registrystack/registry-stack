#!/usr/bin/env bash
set -euo pipefail
quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash -n "$quickstart_dir/run.sh" "$quickstart_dir/query.sh"
python3 -m py_compile "$quickstart_dir/support/quickstart.py"
rg -q 'bregctl" --format json dev start' "$quickstart_dir/run.sh"
rg -q 'dev token "\$client"' "$quickstart_dir/run.sh"
if rg -ni 'registry[ -]mint|registry-mint|clientAuthentication:|mint[_-](port|bin|origin)' "$quickstart_dir/run.sh" "$quickstart_dir/support/quickstart.py"; then
  echo 'quickstart still contains a retired issuer implementation' >&2; exit 1
fi
echo 'Base Registry Engine quickstart structural self-test passed.'
