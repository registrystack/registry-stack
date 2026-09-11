#!/usr/bin/env bash
set -euo pipefail

repo="registrystack/registry-stack"
binaries=(casework caseworkctl mint)
# Publication packaging replaces this empty value with the asset's canonical tag.
default_version=""
script_name="${BASH_SOURCE[0]:-}"
script_name="${script_name##*/}"
filename_version=""
if [[ "$script_name" =~ ^casework-(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-install\.sh$ ]]; then
	filename_version="${BASH_REMATCH[1]}"
fi
if [ -n "$default_version" ] &&
	[ -n "$filename_version" ] &&
	[ "$default_version" != "$filename_version" ]; then
	echo "Refusing an installer whose embedded release does not match its filename." >&2
	exit 1
fi
default_version="${default_version:-$filename_version}"
version="${CASEWORK_VERSION:-$default_version}"
if [ -n "$default_version" ] &&
	[ -n "${CASEWORK_VERSION:-}" ] &&
	[ "$CASEWORK_VERSION" != "$default_version" ]; then
	echo "Refusing a release override that does not match the released installer asset." >&2
	exit 1
fi
install_dir="${CASEWORK_INSTALL_DIR:-$HOME/.local/bin}"
asset_dir="${CASEWORK_ASSET_DIR:-}"

usage() {
	cat <<EOF
Install the Registry Casework runtime, the caseworkctl adopter tooling, and
the mint token issuer that a local registry uses when no identity provider is
at hand. The mint binary is the one the Base Registry Engine and Evidence
toolset installers also ship; every installer installs the same release
asset.

After selecting a release whose manifest lists Casework:
  curl -fsSL https://github.com/${repo}/releases/download/<version>/casework-<version>-install.sh | bash

The installer verifies every downloaded release asset against the release's
SHA256SUMS before anything reaches the install directory, and installs the
three binaries together or not at all. It does not verify release authenticity. For
a higher-assurance installation, follow the release verification guide for the
pinned tag, then rerun with CASEWORK_ASSET_DIR set to the verified
directory:
  https://github.com/${repo}/blob/<version>/release/VERIFY.md

Environment:
  CASEWORK_VERSION      Registry Casework tag to install. A published installer
                    embeds its tag and refuses a different override.
  CASEWORK_INSTALL_DIR  Install directory. Defaults to ~/.local/bin.
  CASEWORK_ASSET_DIR    Read already-downloaded release assets from this directory
                    instead of downloading them.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
	usage
	exit 0
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Casework installer needs '$1'." >&2
		exit 1
	fi
}

if [ -z "$version" ]; then
	echo "No Registry Casework tag is pinned for this installer copy." >&2
	echo "Set CASEWORK_VERSION to a pinned vMAJOR.MINOR.PATCH tag, or run a" >&2
	echo "published casework-<tag>-install.sh asset." >&2
	exit 1
fi
if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	echo "Refusing a non-canonical Registry Casework tag." >&2
	echo "Use vMAJOR.MINOR.PATCH." >&2
	exit 1
fi

need uname
if [ -z "$asset_dir" ]; then
	need curl
fi

os="$(uname -s)"
arch="$(uname -m)"

case "$os/$arch" in
Linux/x86_64 | Linux/amd64)
	os_label="linux"
	arch_label="amd64"
	;;
Linux/arm64 | Linux/aarch64)
	os_label="linux"
	arch_label="arm64"
	;;
Darwin/arm64 | Darwin/aarch64)
	os_label="macos"
	arch_label="arm64"
	;;
*)
	printf 'No prebuilt Registry Casework asset is published for %s/%s.\n' "$os" "$arch" >&2
	printf 'Supported platforms: Linux amd64, Linux arm64, and macOS arm64.\n' >&2
	printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' \
		"$repo" "$version" >&2
	exit 1
	;;
esac

# BEGIN generated libc preflight
# Generated from release/glibc-floor.env by
# release/scripts/render-installer-libc-preflight.py. Do not edit by hand.
#
# The published Linux binaries are dynamically linked against GNU libc. On a
# musl system, or on a glibc older than the floor below, they cannot start, and
# the dynamic linker only says so at the first run, long after this installer
# would have reported success. Refuse here instead, before anything downloads.
if [ "$os_label" = "linux" ]; then
	libc_floor="2.35"
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
		printf 'No musl build of Registry Casework is published for this platform.\n' >&2
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
		printf 'This system has GNU libc %s. The published binaries of Registry Casework need %s or newer.\n' \
			"$detected_libc" "$libc_floor" >&2
		printf 'Nothing was installed: the binaries would fail to start with a dynamic linker error.\n' >&2
		printf 'Upgrade the distribution, or run the published container images.\n' >&2
		exit 1
	fi
fi

# END generated libc preflight
base_url="https://github.com/${repo}/releases/download/${version}"
verify_url="https://github.com/${repo}/blob/${version}/release/VERIFY.md"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t casework)"

cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
	local src="$1"
	local dest="$2"
	if [ -n "$asset_dir" ]; then
		local name="${src##*/}"
		if [ ! -f "$asset_dir/$name" ]; then
			return 1
		fi
		cp "$asset_dir/$name" "$dest"
	else
		curl -fsSL "$src" -o "$dest" 2>/dev/null
	fi
}

if [ -n "$asset_dir" ]; then
	printf 'Installing verified local Registry Casework %s assets for %s/%s...\n' \
		"$version" "$os_label" "$arch_label"
else
	printf 'Downloading Registry Casework %s for %s/%s...\n' \
		"$version" "$os_label" "$arch_label"
fi

for binary in "${binaries[@]}"; do
	asset="${binary}-${version}-${os_label}-${arch_label}"
	if ! download "$base_url/$asset" "$tmpdir/$asset"; then
		printf 'Could not read the published %s %s binary for %s/%s.\n' \
			"$binary" "$version" "$os_label" "$arch_label" >&2
		printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' \
			"$repo" "$version" >&2
		exit 1
	fi
done
if ! download "$base_url/SHA256SUMS" "$tmpdir/SHA256SUMS"; then
	echo "Could not download SHA256SUMS for checksum verification." >&2
	exit 1
fi

sha256_file() {
	local path="$1"
	local result
	if command -v shasum >/dev/null 2>&1; then
		result="$(shasum -a 256 "$path")"
	elif command -v sha256sum >/dev/null 2>&1; then
		result="$(sha256sum "$path")"
	else
		echo "Casework installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
		exit 1
	fi
	printf '%s\n' "${result%% *}"
}

verify_asset() {
	local name="$1"
	local expected_hash actual_hash
	expected_hash="$(awk -v asset="$name" '$2 == asset {print $1}' "$tmpdir/SHA256SUMS")"
	if [ -z "$expected_hash" ]; then
		echo "SHA256SUMS has no entry for $name" >&2
		exit 1
	fi
	actual_hash="$(sha256_file "$tmpdir/$name")"
	if [ "$actual_hash" != "$expected_hash" ]; then
		echo "Checksum verification failed for $name" >&2
		echo "Expected: $expected_hash" >&2
		echo "Actual:   $actual_hash" >&2
		exit 1
	fi
}

for binary in "${binaries[@]}"; do
	verify_asset "${binary}-${version}-${os_label}-${arch_label}"
done
printf 'Integrity checks passed: %s binaries matched SHA256SUMS.\n' "${#binaries[@]}"
cat <<EOF
Authenticity check not performed by this installer.
For a higher-assurance installation, follow the tag-frozen release verification
guide first, then rerun this installer with CASEWORK_ASSET_DIR set to
that verified directory:
  $verify_url

EOF

mkdir -p "$install_dir"
stage_dir="$(mktemp -d "$install_dir/.casework-toolset.XXXXXX")"
link_stage_dir="$(mktemp -d "$install_dir/.casework-links.XXXXXX")"
chmod 0755 "$stage_dir"
install_complete=0
transaction_active=0
link_stage_cleanup=1
cleanup_install() {
	set +e
	if [ "$transaction_active" -eq 1 ]; then
		rollback_adoptions
	fi
	if [ "$install_complete" -eq 0 ]; then
		rm -rf "$stage_dir"
	fi
	if [ "$link_stage_cleanup" -eq 1 ]; then
		rm -rf "$link_stage_dir"
	fi
}
trap 'cleanup_install; cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for binary in "${binaries[@]}"; do
	cp "$tmpdir/${binary}-${version}-${os_label}-${arch_label}" "$stage_dir/$binary"
	chmod 0755 "$stage_dir/$binary"
done

replace_path() {
	local source="$1"
	local destination="$2"
	if [ "$os_label" = "macos" ]; then
		mv -fh "$source" "$destination"
	else
		mv -Tf "$source" "$destination"
	fi
}

current_link="$install_dir/.casework-current"
if [ -e "$current_link" ] && [ ! -L "$current_link" ]; then
	echo "Refusing to replace a non-symbolic Registry Casework toolset pointer." >&2
	exit 1
fi

# A one-time migration keeps existing direct binaries behind the same pointer
# before their stable command links are installed. At every point every command
# therefore resolves to the prior toolset, the new toolset, or neither.
if [ ! -L "$current_link" ]; then
	previous_dir="$(mktemp -d "$install_dir/.casework-previous.XXXXXX")"
	chmod 0755 "$previous_dir"
	previous_count=0
	for binary in "${binaries[@]}"; do
		if [ -e "$install_dir/$binary" ] && [ ! -d "$install_dir/$binary" ]; then
			cp -p "$install_dir/$binary" "$previous_dir/$binary"
			previous_count=$((previous_count + 1))
		fi
	done
	if [ "$previous_count" -gt 0 ]; then
		ln -s "${previous_dir##*/}" "$link_stage_dir/current"
		replace_path "$link_stage_dir/current" "$current_link"
	else
		rm -rf "$previous_dir"
	fi
fi

had_current_link=0
if [ -L "$current_link" ]; then
	had_current_link=1
	ln -s "$(readlink "$current_link")" "$link_stage_dir/previous-current"
fi

for binary in "${binaries[@]}"; do
	if [ -d "$install_dir/$binary" ] && [ ! -L "$install_dir/$binary" ]; then
		echo "Refusing to replace a directory at $install_dir/$binary." >&2
		exit 1
	fi
	command_target=".casework-current/$binary"
	ln -s "$command_target" "$link_stage_dir/$binary"
	if [ -L "$install_dir/$binary" ] &&
		[ "$(readlink "$install_dir/$binary")" = "$command_target" ]; then
		# This command already belongs to Casework and changes version through
		# the pointer below. Leave it untouched if that pointer switch fails.
		rm "$link_stage_dir/$binary"
	elif [ -L "$install_dir/$binary" ]; then
		# Preserve the target text, including a dangling or relative link, so a
		# failed adoption restores the other installer's exact command path.
		ln -s "$(readlink "$install_dir/$binary")" "$link_stage_dir/previous-$binary"
	elif [ -e "$install_dir/$binary" ]; then
		# A regular command may be a local wrapper. Preserve its bytes and mode.
		cp -p "$install_dir/$binary" "$link_stage_dir/previous-$binary"
	fi
done

adopted_binaries=()
rollback_adoptions() {
	local rollback_failed=0 binary backup
	# Clear first so EXIT cleanup never replays a partial rollback whose backup
	# entries may already have been moved back into place.
	transaction_active=0
	for binary in "${adopted_binaries[@]}"; do
		backup="$link_stage_dir/previous-$binary"
		if [ -L "$backup" ] || [ -e "$backup" ]; then
			if ! replace_path "$backup" "$install_dir/$binary"; then
				rollback_failed=1
			fi
		elif ! rm -f "$install_dir/$binary"; then
			rollback_failed=1
		fi
	done
	if [ "$had_current_link" -eq 1 ]; then
		if ! replace_path "$link_stage_dir/previous-current" "$current_link"; then
			rollback_failed=1
		fi
	elif ! rm -f "$current_link"; then
		rollback_failed=1
	fi
	if [ "$rollback_failed" -eq 0 ]; then
		# The new toolset is unreachable again and may be removed by cleanup.
		install_complete=0
	else
		link_stage_cleanup=0
		echo "The failed install could not restore every previous command path; inspect $install_dir and the retained backups under $link_stage_dir." >&2
	fi
	return "$rollback_failed"
}

# Every stable command link the pointer already resolves changes version through
# this one atomic rename.
ln -s "${stage_dir##*/}" "$link_stage_dir/current"
install_complete=1
transaction_active=1
replace_path "$link_stage_dir/current" "$current_link"

# A command not already linked through Casework's pointer, such as a shared
# command owned by another product, is linked only now that the switch has made
# its target real. Installing that link earlier would mutate a working command
# even when the final pointer switch fails. Its staged link is still in place
# because the loop above left it there.
for binary in "${binaries[@]}"; do
	if [ -L "$link_stage_dir/$binary" ]; then
		# Record the attempt before moving: a failing mv may already have changed
		# its destination, so rollback must restore this path as well.
		adopted_binaries+=("$binary")
		if replace_path "$link_stage_dir/$binary" "$install_dir/$binary"; then
			:
		else
			adoption_status=$?
			rollback_adoptions || true
			exit "$adoption_status"
		fi
	fi
done
transaction_active=0

for binary in "${binaries[@]}"; do
	printf '%s installed to %s\n' "$binary" "$install_dir/$binary"
done
cat <<EOF

Try it:
  caseworkctl init --help
  caseworkctl check --help
  casework --help
  mint --help

EOF

case ":$PATH:" in
*":$install_dir:"*) ;;
*) echo "Add $install_dir to PATH to run Registry Casework from any shell." >&2 ;;
esac
