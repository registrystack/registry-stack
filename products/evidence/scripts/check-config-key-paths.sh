#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)

cd "$repository_root"
python3 products/evidence/scripts/evidence_config_key_paths.py "$@"
