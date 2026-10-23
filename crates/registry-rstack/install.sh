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
bin_dir=""
install_root=""
asset_dir=""
selected=()
select_all=0
component_delimiter=0
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
		component_delimiter=1
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
if [[ "${seen_bin_dir}" -eq 0 || "${seen_install_root}" -eq 0 ]]; then
	if [[ -z "${HOME:-}" ]]; then
		printf 'HOME is required for default installation paths; pass --bin-dir and --install-root.\n' >&2
		exit 2
	fi
	if [[ "${seen_bin_dir}" -eq 0 ]]; then
		bin_dir="${HOME}/.local/bin"
	fi
	if [[ "${seen_install_root}" -eq 0 ]]; then
		install_root="${HOME}/.local/lib/registrystack"
	fi
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

repo="${repository}"
version="${release}"
os_label="${platform%%-*}"
# BEGIN generated libc preflight
# Generated from release/glibc-floor.env by
# release/scripts/render-installer-libc-preflight.py. Do not edit by hand.
#
# The published Linux binaries are dynamically linked against GNU libc. On a
# musl system, or on a glibc older than the floor below, they cannot start, and
# the dynamic linker only says so at the first run, long after this installer
# would have reported success. Refuse here instead, before anything downloads.
if [ "$os_label" = "linux" ]; then
	libc_floor="2.34"
	# musl's ldd exits non-zero when asked for a version, and this installer runs
	# under pipefail, so its report is captured once here instead of being read
	# through a pipeline whose status would hide the match.
	libc_report=""
	if command -v ldd >/dev/null 2>&1; then
		libc_report="$(ldd --version 2>&1 || true)"
	fi
	# Only glibc's getconf answers GNU_LIBC_VERSION, so an answer names the libc
	# this system runs on, whatever else is installed beside it: a musl loader
	# kept for cross builds does not make a musl system. Without an answer, musl
	# is recognised by its ldd report or its loader. The report is matched by a
	# pattern rather than through grep, which can exit before the report is
	# fully written and, under pipefail, lose the match.
	detected_libc=""
	if command -v getconf >/dev/null 2>&1; then
		detected_libc="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}' || true)"
	fi
	musl_system=0
	if [ -z "$detected_libc" ]; then
		case "$libc_report" in
		*[Mm][Uu][Ss][Ll]*) musl_system=1 ;;
		esac
		if ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
			musl_system=1
		fi
	fi
	if [ "$musl_system" = 1 ]; then
		printf 'No musl build of Registry Stack is published for this platform.\n' >&2
		printf 'Every published Linux binary needs GNU libc %s or newer, so none of them can start here.\n' \
			"$libc_floor" >&2
		printf 'Install on a GNU libc distribution, or run the published container images.\n' >&2
		printf 'If you need musl builds, ask for them at https://github.com/%s/issues so the demand is recorded.\n' \
			"$repo" >&2
		exit 1
	fi
	if [ -z "$detected_libc" ]; then
		detected_libc="$(printf '%s\n' "$libc_report" | awk 'NR == 1 {print $NF}')"
	fi
	case "$detected_libc" in
	[0-9]*.[0-9]*) ;;
	*) detected_libc="" ;;
	esac
	if [ -z "$detected_libc" ]; then
		printf 'Could not read the GNU libc version of this system, so the %s floor is unchecked.\n' \
			"$libc_floor" >&2
	elif ! awk -v have="$detected_libc" -v floor="$libc_floor" '
		BEGIN {
			split(have, h, ".")
			split(floor, f, ".")
			exit !(h[1] > f[1] || (h[1] == f[1] && h[2] >= f[2]))
		}
	'; then
		printf 'This system has GNU libc %s. The published binaries of Registry Stack need %s or newer.\n' \
			"$detected_libc" "$libc_floor" >&2
		printf 'Nothing was installed: the binaries would fail to start with a dynamic linker error.\n' >&2
		printf 'Upgrade the distribution, or run the published container images.\n' >&2
		exit 1
	fi
fi

# END generated libc preflight
base_url="https://github.com/${repo}/releases/download/${version}"

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
			"${base_url}/${name}"
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
	seen_entries=$'\n'
	while IFS= read -r entry; do
		case "${entry}" in
		"${launcher_name%.tar.gz}") has_launcher=1 ;;
		THIRD_PARTY_NOTICES) has_notices=1 ;;
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
	if [[ "${has_launcher}" -ne 1 || "${has_notices}" -ne 1 ]]; then
		printf 'Launcher archive is incomplete.\n' >&2
		exit 3
	fi
	listed_count=0
	while IFS= read -r item; do
		mode="${item%% *}"
		name="${item##* }"
		if [[ "${mode:0:1}" != "-" ||
			("${name}" == "${launcher_name%.tar.gz}" && "${mode}" != "-rwxr-xr-x") ||
			("${name}" == THIRD_PARTY_NOTICES && "${mode}" != "-rw-r--r--") ]]; then
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
elif [[ "${#selected[@]}" -gt 0 ]]; then
	if [[ "${component_delimiter}" -eq 1 ]]; then
		arguments+=(--)
	fi
	arguments+=("${selected[@]}")
fi
"${launcher}" "${arguments[@]}"
