#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" != 4 && "$#" != 6 ]]; then
	printf 'usage: %s VERSION TAG TARGET OUTPUT [--exclude-unit discovery]\n' "$0" >&2
	exit 2
fi
version="$1"
tag="$2"
target="$3"
output="$4"
exclude_discovery=0
if [[ "$#" == 6 ]]; then
	if [[ "$5" != --exclude-unit || "$6" != discovery ]]; then
		printf 'only --exclude-unit discovery is supported\n' >&2
		exit 2
	fi
	exclude_discovery=1
fi
repo_root="$(git rev-parse --show-toplevel)"
builds="$(python3 "${repo_root}/release/scripts/release_roster.py" additional-platform-builds "${version}")"
cargo_bin="${CARGO:-cargo}"
if [[ -z "${builds}" ]]; then
	exit 0
fi
if [[ "${target}" != aarch64-unknown-linux-gnu ]]; then
	printf 'additional Linux platform builder requires aarch64-unknown-linux-gnu\n' >&2
	exit 2
fi
mkdir -p "${output}"
while read -r package binary; do
	if [[ "${exclude_discovery}" -eq 1 && "${package}" == registry-discovery* ]]; then
		continue
	fi
	"${cargo_bin}" build --release --locked -p "${package}" --bin "${binary}" --target "${target}"
	destination="${output}/${binary}-${tag}-linux-arm64"
	cp "${CARGO_TARGET_DIR:-target}/${target}/release/${binary}" "${destination}"
	chmod 0755 "${destination}"
	expected="${binary} ${tag#v}"
	if [[ "${binary}" == registry-render ]]; then
		typst_pin="$(sed -n 's/^pub const TYPST_PIN: &str = "\([^"]*\)";$/\1/p' "${repo_root}/crates/registry-render/src/lib.rs")"
		test -n "${typst_pin}"
		expected+=" (typst ${typst_pin})"
	fi
	observed="$("${destination}" --version)"
	if [[ "${observed}" != "${expected}" ]]; then
		printf '%s reports "%s"; the release identity expects "%s"\n' "${binary}" "${observed}" "${expected}" >&2
		exit 1
	fi
done <<<"${builds}"
