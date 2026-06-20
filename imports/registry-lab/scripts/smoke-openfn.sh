#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Forwarding shim: the civil sidecar now runs the built-in http_json engine.
# This script delegates to smoke-civil.sh for backwards compatibility.
set -euo pipefail
exec "$(dirname -- "${BASH_SOURCE[0]}")/smoke-civil.sh" "$@"
