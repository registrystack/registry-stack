#!/usr/bin/env bash
set -euo pipefail

repository="registrystack/registry-stack"
# Publication replaces this empty value in the release-pinned installer asset.
default_version=""
script_name="${BASH_SOURCE[0]##*/}"
filename_version=""
if [[ "${script_name}" =~ ^rstack-(v[0-9]+\.[0-9]+\.[0-9]+)-install\.sh$ ]]; then
	filename_version="${BASH_REMATCH[1]}"
fi
if [[ -n "${default_version}" && -n "${filename_version}" &&
	"${default_version}" != "${filename_version}" ]]; then
	printf 'Installer filename and embedded release disagree.\n' >&2
	exit 2
fi
default_version="${default_version:-${filename_version}}"

usage() {
	cat <<'EOF'
Install the release-pinned Registry Stack launcher and optional components.

Usage: bash rstack-install.sh [COMPONENT ... | --all] [options]
       bash rstack-install.sh --release vX.Y.Z [COMPONENT ... | --all]

Options:
  --release TAG       Exact release for an unpinned source installer.
  --bin-dir DIR       Public executable directory (default ~/.local/bin).
  --install-root DIR  Generation storage (default ~/.local/lib/registrystack).
  --asset-dir DIR     Already downloaded and verified release assets.
  --help              Show this help.

With no component selection, install only the launcher. The managed install
exposes only rstack on PATH. No shell profile or completion file is changed.
Downloaded SHA256SUMS checks establish integrity against the fetched manifest;
authenticate the published checksum bundle separately with release/VERIFY.md.
EOF
}

release="${RSTACK_RELEASE:-${default_version}}"
bin_dir="${HOME:?HOME is required}/.local/bin"
install_root="${HOME:?HOME is required}/.local/lib/registrystack"
asset_dir=""
selected=()
select_all=0
seen_release=0
seen_bin_dir=0
seen_install_root=0
seen_asset_dir=0
while [[ "$#" -gt 0 ]]; do
	case "$1" in
	--release | --bin-dir | --install-root | --asset-dir)
		option="$1"
		if [[ "$#" -lt 2 || -z "$2" ]]; then
			printf '%s needs a value.\n' "${option}" >&2
			exit 2
		fi
		case "${option}" in
		--release)
			[[ "${seen_release}" -eq 0 ]] || {
				printf '%s may be supplied once.\n' "${option}" >&2
				exit 2
			}
			seen_release=1
			release="$2"
			;;
		--bin-dir)
			[[ "${seen_bin_dir}" -eq 0 ]] || {
				printf '%s may be supplied once.\n' "${option}" >&2
				exit 2
			}
			seen_bin_dir=1
			bin_dir="$2"
			;;
		--install-root)
			[[ "${seen_install_root}" -eq 0 ]] || {
				printf '%s may be supplied once.\n' "${option}" >&2
				exit 2
			}
			seen_install_root=1
			install_root="$2"
			;;
		--asset-dir)
			[[ "${seen_asset_dir}" -eq 0 ]] || {
				printf '%s may be supplied once.\n' "${option}" >&2
				exit 2
			}
			seen_asset_dir=1
			asset_dir="$2"
			;;
		esac
		shift 2
		;;
	--all)
		[[ "${select_all}" -eq 0 ]] || {
			printf '%s may be supplied once.\n' "$1" >&2
			exit 2
		}
		select_all=1
		shift
		;;
	--help | -h)
		usage
		exit 0
		;;
	--)
		shift
		selected+=("$@")
		break
		;;
	-*)
		printf 'Unknown option: %s\n' "$1" >&2
		exit 2
		;;
	*)
		selected+=("$1")
		shift
		;;
	esac
done
if [[ "${select_all}" -eq 1 && "${#selected[@]}" -gt 0 ]]; then
	printf 'Choose component names or --all, not both.\n' >&2
	exit 2
fi
if [[ -z "${release}" || ! "${release}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	printf 'An exact --release vX.Y.Z is required for an unpinned installer.\n' >&2
	exit 2
fi
if [[ -n "${default_version}" && "${release}" != "${default_version}" ]]; then
	printf 'Published installer is pinned to %s; release override refused.\n' "${default_version}" >&2
	exit 2
fi
if [[ "${seen_release}" -eq 1 && -n "${RSTACK_RELEASE:-}" && "${RSTACK_RELEASE}" != "${release}" ]]; then
	printf -- '--release conflicts with RSTACK_RELEASE.\n' >&2
	exit 2
fi

case "$(uname -s):$(uname -m)" in
Linux:x86_64) platform=linux-amd64 ;;
Linux:aarch64 | Linux:arm64) platform=linux-arm64 ;;
Darwin:arm64) platform=macos-arm64 ;;
*)
	printf 'No rstack launcher is published for this platform.\n' >&2
	exit 2
	;;
esac

launcher_name="rstack-${release}-${platform}"
if [[ "${platform}" == macos-arm64 ]]; then
	launcher_name+=".tar.gz"
fi
manifest_name="registry-stack-${release}-release-manifest.json"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/rstack-bootstrap.XXXXXXXX")"
cleanup() {
	if [[ -d "${scratch}" && ! -L "${scratch}" ]]; then
		rm -r -- "${scratch}"
	fi
}
trap cleanup EXIT

fetch_asset() {
	local name="$1"
	if [[ -n "${asset_dir}" ]]; then
		if [[ ! -f "${asset_dir}/${name}" ]]; then
			printf 'Verified asset directory lacks %s.\n' "${name}" >&2
			exit 3
		fi
		cp "${asset_dir}/${name}" "${scratch}/${name}"
	else
		if ! command -v curl >/dev/null 2>&1; then
			printf 'Downloading release assets requires curl.\n' >&2
			exit 3
		fi
		curl --fail --silent --show-error --location --proto '=https' \
			--proto-redir '=https' --max-time 300 \
			--output "${scratch}/${name}" \
			"https://github.com/${repository}/releases/download/${release}/${name}"
	fi
}

sha256_file() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		printf 'A SHA-256 tool (shasum or sha256sum) is required.\n' >&2
		exit 3
	fi
}

expected_hash() {
	awk -v wanted="$1" '
		$2 == wanted {
			if (seen++ || length($1) != 64 || $1 !~ /^[0-9a-f]+$/) bad = 1
			value = $1
		}
		END { if (bad || seen != 1) exit 1; print value }
	' "${scratch}/SHA256SUMS"
}

fetch_asset SHA256SUMS
for name in "${manifest_name}" "${launcher_name}"; do
	fetch_asset "${name}"
	if ! expected="$(expected_hash "${name}")"; then
		printf 'SHA256SUMS has no unique digest for %s.\n' "${name}" >&2
		exit 3
	fi
	if [[ "$(sha256_file "${scratch}/${name}")" != "${expected}" ]]; then
		printf 'Release asset checksum mismatch: %s.\n' "${name}" >&2
		exit 3
	fi
done

launcher="${scratch}/${launcher_name}"
if [[ "${platform}" == macos-arm64 ]]; then
	mkdir "${scratch}/extracted"
	if ! entries="$(tar -tzf "${launcher}")" ||
		! listing="$(tar -tvzf "${launcher}")"; then
		printf 'Launcher archive cannot be inspected.\n' >&2
		exit 3
	fi
	entry_count=0
	has_launcher=0
	has_notices=0
	has_fips_module=0
	seen_entries=$'\n'
	while IFS= read -r entry; do
		case "${entry}" in
		"${launcher_name%.tar.gz}") has_launcher=1 ;;
		THIRD_PARTY_NOTICES) has_notices=1 ;;
		libaws_lc_fips_*.dylib) has_fips_module=1 ;;
		*)
			printf 'Launcher archive has an unsupported entry.\n' >&2
			exit 3
			;;
		esac
		if [[ "${seen_entries}" == *$'\n'"${entry}"$'\n'* ]]; then
			printf 'Launcher archive has a duplicate entry.\n' >&2
			exit 3
		fi
		seen_entries+="${entry}"$'\n'
		entry_count=$((entry_count + 1))
	done <<<"${entries}"
	if [[ "${has_launcher}" -ne 1 || "${has_notices}" -ne 1 ||
		"${has_fips_module}" -ne 1 ]]; then
		printf 'Launcher archive is incomplete.\n' >&2
		exit 3
	fi
	listed_count=0
	while IFS= read -r item; do
		if [[ "${item:0:1}" != "-" ]]; then
			printf 'Launcher archive contains a nonregular entry.\n' >&2
			exit 3
		fi
		listed_count=$((listed_count + 1))
	done <<<"${listing}"
	if [[ "${listed_count}" -ne "${entry_count}" ]]; then
		printf 'Launcher archive listing changed during inspection.\n' >&2
		exit 3
	fi
	tar -xzf "${launcher}" -C "${scratch}/extracted"
	launcher="${scratch}/extracted/${launcher_name%.tar.gz}"
	if [[ ! -f "${launcher}" || -L "${launcher}" ]]; then
		printf 'Launcher archive has no regular executable.\n' >&2
		exit 3
	fi
fi
chmod 0700 "${launcher}"
if [[ "$("${launcher}" --version)" != "rstack ${release#v}" ]]; then
	printf 'Launcher executable reports the wrong release.\n' >&2
	exit 3
fi

arguments=(bootstrap --release-manifest "${scratch}/${manifest_name}"
	--checksum-file "${scratch}/SHA256SUMS"
	--launcher-asset "${scratch}/${launcher_name}"
	--bin-dir "${bin_dir}" --install-root "${install_root}")
if [[ -n "${asset_dir}" ]]; then
	arguments+=(--asset-dir "${asset_dir}")
fi
if [[ "${select_all}" -eq 1 ]]; then
	arguments+=(--all)
else
	arguments+=("${selected[@]}")
fi
"${launcher}" "${arguments[@]}"
