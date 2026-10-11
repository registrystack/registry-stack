#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)

cd "$repo_root"
python3 products/coordinator/scripts/check_dependency_direction.py
python3 -m unittest discover -s products/coordinator/scripts -p 'test_*.py'

# The committed configuration schemas and OpenAPI document are reproduced by
# their generators, never hand-edited; the checkpoint is the gate that runs
# the drift check.
products/coordinator/scripts/check-schemas.sh

printf 'Coordinator dependency boundary, product script tests, and generated documents passed.\n'
