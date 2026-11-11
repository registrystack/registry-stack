#!/usr/bin/env bash
set -euo pipefail

has_noble_indexes() {
	local archive="$1" suite
	for suite in noble noble-updates noble-backports noble-security; do
		curl --proto '=https' --fail --silent --show-error --head --max-time 10 \
			"${archive}dists/$suite/InRelease" >/dev/null || return 1
	done
}

for mirror in \
	https://archive.ubuntu.com/ubuntu/ \
	https://mirrors.edge.kernel.org/ubuntu/ \
	https://mirror.math.princeton.edu/pub/ubuntu/; do
	host="${mirror#https://}"
	if timeout 5 getent ahosts "${host%%/*}" >/dev/null && has_noble_indexes "$mirror"; then
		printf '%s\n' "$mirror"
		exit 0
	fi
done

printf '%s\n' 'No Ubuntu Noble archive mirror is reachable.' >&2
exit 1
