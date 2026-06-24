#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Forwarding shim: the DHIS2 sidecar now runs the built-in http_json engine.
# This script delegates to smoke-dhis2.sh for backwards compatibility.
set -euo pipefail
exec "$(dirname -- "${BASH_SOURCE[0]}")/smoke-dhis2.sh" "$@"
