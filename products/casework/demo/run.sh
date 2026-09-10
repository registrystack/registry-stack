#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: products/casework/demo/run.sh --app-kit-worktree PATH --evidence-dir PATH [--fixture checkpoint|full-mvp]

Run the first Casework technical checkpoint through the real App Kit host, BReg,
PostgreSQL, and Casework. The matching App Kit verifier builds and installs the
local candidate client, starts isolated demo services, executes the authenticated
journey, and writes verification evidence. Docker, Rust, Node.js, and Python 3
must be available. Use an App Kit checkout containing the checkpoint verifier.
The default checkpoint uses one review stage. The full-mvp fixture exercises
two review stages, routing, assignment, absence cover, and authored clocks.

The Stack source is the checkout containing this script. Neither checkout is
reset or fetched by this command. The evidence directory must be outside every
Git repository so local runtime evidence cannot enter a product commit.
HELP
}

app_kit=''
evidence=''
fixture='checkpoint'
while (($#)); do
  case "$1" in
    --app-kit-worktree|--evidence-dir|--fixture)
      if (($# < 2)) || [[ -z "$2" ]]; then
        usage >&2
        exit 2
      fi
      case "$1" in
        --app-kit-worktree) app_kit="$2" ;;
        --evidence-dir) evidence="$2" ;;
        --fixture) fixture="$2" ;;
      esac
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
if [[ -z "$app_kit" || -z "$evidence" ]]; then usage >&2; exit 2; fi
case "$fixture" in
  checkpoint|full-mvp) ;;
  *) printf 'Unknown fixture: %s\n' "$fixture" >&2; usage >&2; exit 2 ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
stack="$(cd -- "$script_dir/../../.." && pwd -P)"
app_kit="$(cd -- "$app_kit" && pwd -P)"
verifier="$app_kit/project/deployment/scripts/verify-casework-checkpoint.py"
if [[ ! -f "$verifier" ]]; then
  printf 'The selected App Kit checkout has no checkpoint verifier: %s\n' "$verifier" >&2
  exit 2
fi
python3 - "$stack" "$app_kit" "$evidence" <<'PY'
from pathlib import Path
import sys
stack, kit, evidence = (Path(value).resolve() for value in sys.argv[1:])
for candidate in (evidence, *evidence.parents):
    if (candidate / '.git').exists():
        sys.exit('Choose an evidence directory outside every Git repository.')
PY
exec python3 "$verifier" --stack-worktree "$stack" --evidence-dir "$evidence" --fixture "$fixture"
