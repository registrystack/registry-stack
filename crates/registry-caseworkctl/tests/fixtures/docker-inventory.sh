#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
fixture=$(dirname "$0")
if [ "$1" = "ps" ]; then
    if [ -f "$fixture/container-active" ]; then printf 'container\n'; fi
elif [ "$1" = "inspect" ]; then
    cat "$fixture/container.json"
elif [ "$1" = "volume" ] && [ "$2" = "create" ]; then
    touch "$fixture/volume-active"
    cat "$fixture/volume-name"
elif [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
    if [ -f "$fixture/volume-active" ]; then cat "$fixture/volume-name"; fi
elif [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
    cat "$fixture/volume.json"
elif [ "$1" = "create" ]; then
    if [ -f "$fixture/fail-create" ]; then
        printf 'injected container creation failure\n' >&2
        exit 42
    fi
    touch "$fixture/container-active"
    cat "$fixture/container-id"
else
    printf 'unexpected fake Docker command: %s\n' "$*" >&2
    exit 43
fi
