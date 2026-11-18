#!/usr/bin/env bash
set -euo pipefail
quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash -n "$quickstart_dir/run.sh" "$quickstart_dir/query.sh"
python3 -m py_compile "$quickstart_dir/support/quickstart.py"
grep -Fq -- '--format json dev start' "$quickstart_dir/run.sh"
grep -Fq -- 'dev token "$run_id" --as "$person"' "$quickstart_dir/run.sh"
grep -Fq -- 'dev stop "$run_id"' "$quickstart_dir/run.sh"
if grep -En 'bregctl"? (--format json )?dev|--breg-port|--issuer-port|--database-port|dev-clients' "$quickstart_dir/run.sh" "$quickstart_dir/support/quickstart.py"; then
  echo 'quickstart still drives the retired bregctl dev lifecycle' >&2; exit 1
fi
if grep -Ein 'registry[ -]mint|registry-mint|clientAuthentication:|mint[_-](port|bin|origin)' "$quickstart_dir/run.sh" "$quickstart_dir/support/quickstart.py"; then
  echo 'quickstart still contains a retired issuer implementation' >&2; exit 1
fi
echo 'Base Registry Engine quickstart structural self-test passed.'
