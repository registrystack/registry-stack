#!/usr/bin/env bash
set -euo pipefail

for mirror in \
  https://archive.ubuntu.com/ubuntu/ \
  https://mirrors.edge.kernel.org/ubuntu/ \
  https://mirror.math.princeton.edu/pub/ubuntu/; do
  host="${mirror#https://}"
  if timeout 5 getent ahosts "${host%%/*}" >/dev/null &&
    curl --proto '=https' --fail --silent --show-error --head --max-time 10 \
      "${mirror}dists/noble/InRelease" >/dev/null; then
    printf '%s\n' "$mirror"
    exit 0
  fi
done

printf '%s\n' 'No Ubuntu Noble archive mirror is reachable.' >&2
exit 1
