#!/usr/bin/env bash
set -euo pipefail

target_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -B "$target_root/key_separation.py" "$target_root"
