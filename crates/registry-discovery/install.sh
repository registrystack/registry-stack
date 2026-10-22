#!/usr/bin/env bash
set -euo pipefail

repo="registrystack/registry-stack"
binaries=(discovery discoveryctl)
# Candidate packaging replaces this empty value with the product asset marker.
default_version=""
script_name="${BASH_SOURCE[0]:-}"
script_name="${script_name##*/}"
filename_version=""
if [[ "$script_name" =~ ^discovery-(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-nightly\.[0-9]{8}\.[0-9a-f]{40})?)-install\.sh$ ]]; then
	filename_version="${BASH_REMATCH[1]}"
fi
if [[ -n "$default_version" && -n "$filename_version" && "$default_version" != "$filename_version" ]]; then
	printf 'Refusing an installer whose embedded release does not match its filename.\n' >&2
	exit 1
fi
default_version="${default_version:-$filename_version}"
install_dir="${DISCOVERY_INSTALL_DIR:-$HOME/.local/bin}"
asset_dir="${DISCOVERY_ASSET_DIR:-}"
requested_version=""

usage() {
	cat <<EOF
Install the Registry Discovery runtime and discoveryctl for Linux amd64.

Usage:
  discovery-install.sh --version vMAJOR.MINOR.PATCH

A published installer is already pinned to its product release. The source
installer requires --version or DISCOVERY_VERSION and never infers a version
from the latest Registry Stack release.

The installer verifies both binaries against SHA256SUMS, starts them to verify
their embedded product version, and switches the pair through one toolset
pointer. It does not verify release authenticity. For a higher-assurance
installation, verify the release first, then rerun with DISCOVERY_ASSET_DIR set
to that verified directory.

Environment:
  DISCOVERY_VERSION      Registry Discovery asset marker, vMAJOR.MINOR.PATCH.
  DISCOVERY_INSTALL_DIR  Install directory. Defaults to ~/.local/bin.
  DISCOVERY_ASSET_DIR    Read already-downloaded product release assets from
                         this directory instead of downloading them.
EOF
}

while [[ "$#" -gt 0 ]]; do
	case "$1" in
	--version)
		if [[ "$#" -lt 2 ]]; then
			printf '%s\n' '--version needs vMAJOR.MINOR.PATCH.' >&2
			exit 2
		fi
		if [[ -n "$requested_version" ]]; then
			printf '%s\n' '--version may be supplied only once.' >&2
			exit 2
		fi
		requested_version="$2"
		shift 2
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		printf 'Unknown option: %s\n' "$1" >&2
		usage >&2
		exit 2
		;;
	esac
done

version_override="${DISCOVERY_VERSION:-}"
if [[ -n "$requested_version" && -n "$version_override" && "$requested_version" != "$version_override" ]]; then
	printf '%s\n' 'Refusing conflicting --version and DISCOVERY_VERSION selections.' >&2
	exit 1
fi
selected_version="${requested_version:-$version_override}"
if [[ -n "$default_version" && -n "$selected_version" && "$default_version" != "$selected_version" ]]; then
	printf '%s\n' 'Refusing a version override that does not match the released installer asset.' >&2
	exit 1
fi
version="${default_version:-$selected_version}"
if [[ -z "$version" ]]; then
	printf '%s\n' 'No Registry Discovery version was selected. Pass --version vMAJOR.MINOR.PATCH or set DISCOVERY_VERSION.' >&2
	exit 2
fi
if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-nightly\.[0-9]{8}\.[0-9a-f]{40})?$ ]]; then
	printf '%s\n' 'Refusing a non-canonical Registry Discovery version or nightly marker.' >&2
	exit 1
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf "Registry Discovery installer needs '%s'.\n" "$1" >&2
		exit 1
	fi
}

need uname
os="$(uname -s)"
arch="$(uname -m)"
if [[ "$os/$arch" != "Linux/x86_64" && "$os/$arch" != "Linux/amd64" ]]; then
	printf 'No prebuilt Registry Discovery toolset is published for %s/%s.\n' "$os" "$arch" >&2
	printf '%s\n' 'The installer supports Linux amd64 only.' >&2
	exit 1
fi
os_label="linux"
if [[ -z "$asset_dir" ]]; then
	need curl
fi

sha256_file() {
	local path="$1"
	local result
	if command -v shasum >/dev/null 2>&1; then
		result="$(shasum -a 256 "$path")"
	elif command -v sha256sum >/dev/null 2>&1; then
		result="$(sha256sum "$path")"
	else
		printf "%s\n" "Registry Discovery installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
		exit 1
	fi
	printf '%s\n' "${result%% *}"
}

nightly_suffix=""
if [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-(nightly\.[0-9]{8}\.[0-9a-f]{40})$ ]]; then
	nightly_suffix="${BASH_REMATCH[1]}"
	release_tag="$version"
	verification_guide="release/NIGHTLY.md"
else
	release_tag="discovery/$version"
	verification_guide="release/VERIFY.md"
fi
release_tag_url="${release_tag//\//%2F}"
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
		printf 'No musl build of Registry Discovery is published for this platform.\n' >&2
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
		printf 'This system has GNU libc %s. The published binaries of Registry Discovery need %s or newer.\n' \
			"$detected_libc" "$libc_floor" >&2
		printf 'Nothing was installed: the binaries would fail to start with a dynamic linker error.\n' >&2
		printf 'Upgrade the distribution, or run the published container images.\n' >&2
		exit 1
	fi
fi

# END generated libc preflight
base_url="https://github.com/${repo}/releases/download/${release_tag_url}"
verify_url="https://github.com/${repo}/blob/${release_tag_url}/${verification_guide}"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t discovery)"

cleanup_downloads() {
	if [[ -d "$tmpdir" ]]; then
		rm -r -- "$tmpdir"
	fi
}
trap cleanup_downloads EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

asset_name() {
	printf '%s-%s-linux-amd64\n' "$1" "$version"
}

download() {
	local src="$1"
	local dest="$2"
	if [[ -n "$asset_dir" ]]; then
		local name="${src##*/}"
		if [[ ! -f "$asset_dir/$name" ]]; then
			return 1
		fi
		cp "$asset_dir/$name" "$dest"
	else
		curl -fsSL "$src" -o "$dest" 2>/dev/null
	fi
}

if [[ -n "$asset_dir" ]]; then
	printf 'Installing verified local Registry Discovery %s assets for Linux/amd64...\n' "$version"
else
	printf 'Downloading Registry Discovery %s for Linux/amd64...\n' "$version"
fi

embedded_product_version=""
for binary in "${binaries[@]}"; do
	asset="$(asset_name "$binary")"
	if ! download "$base_url/$asset" "$tmpdir/$asset"; then
		printf 'Could not read the published %s %s binary for Linux/amd64.\n' "$binary" "$version" >&2
		printf 'Check the product release at https://github.com/%s/releases/tag/%s\n' "$repo" "$release_tag_url" >&2
		exit 1
	fi
done
if ! download "$base_url/SHA256SUMS" "$tmpdir/SHA256SUMS"; then
	printf '%s\n' 'Could not read SHA256SUMS for checksum verification.' >&2
	exit 1
fi

verify_asset() {
	local name="$1"
	local expected_hash actual_hash
	expected_hash="$(awk -v asset="$name" '
		$2 == asset { value = $1; count++ }
		END { if (count != 1) exit 1; print value }
	' "$tmpdir/SHA256SUMS" || true)"
	if [[ ! "$expected_hash" =~ ^[0-9a-f]{64}$ ]]; then
		printf 'SHA256SUMS has no unique canonical entry for %s.\n' "$name" >&2
		exit 1
	fi
	actual_hash="$(sha256_file "$tmpdir/$name")"
	if [[ "$actual_hash" != "$expected_hash" ]]; then
		printf 'Checksum verification failed for %s.\n' "$name" >&2
		exit 1
	fi
}

for binary in "${binaries[@]}"; do
	verify_asset "$(asset_name "$binary")"
done
printf '%s\n' 'Integrity checks passed: both binaries matched SHA256SUMS.'

mkdir -p "$install_dir"
stage_dir="$(mktemp -d "$install_dir/.discovery-toolset.XXXXXX")"
link_stage_dir="$(mktemp -d "$install_dir/.discovery-links.XXXXXX")"
chmod 0755 "$stage_dir" "$link_stage_dir"
install_complete=0
transaction_active=0
link_stage_cleanup=1

replace_path() {
	local source="$1"
	local destination="$2"
	if mv --version >/dev/null 2>&1; then
		mv -Tf "$source" "$destination"
	else
		mv -fh "$source" "$destination"
	fi
}

adopted_binaries=()
had_current_link=0
current_link="$install_dir/.discovery-current"

rollback_adoptions() {
	local rollback_failed=0 binary backup
	transaction_active=0
	for binary in "${adopted_binaries[@]}"; do
		backup="$link_stage_dir/previous-$binary"
		if [[ -L "$backup" || -e "$backup" ]]; then
			if ! replace_path "$backup" "$install_dir/$binary"; then
				rollback_failed=1
			fi
		elif ! rm -f -- "$install_dir/$binary"; then
			rollback_failed=1
		fi
	done
	if [[ "$had_current_link" -eq 1 ]]; then
		if ! replace_path "$link_stage_dir/previous-current" "$current_link"; then
			rollback_failed=1
		fi
	elif ! rm -f -- "$current_link"; then
		rollback_failed=1
	fi
	if [[ "$rollback_failed" -eq 0 ]]; then
		install_complete=0
	else
		link_stage_cleanup=0
		printf 'The failed install could not restore every previous command path; inspect %s and the retained backups under %s.\n' \
			"$install_dir" "$link_stage_dir" >&2
	fi
	return "$rollback_failed"
}

cleanup_install() {
	set +e
	if [[ "$transaction_active" -eq 1 ]]; then
		rollback_adoptions
	fi
	if [[ "$install_complete" -eq 0 && -d "$stage_dir" ]]; then
		rm -r -- "$stage_dir"
	fi
	if [[ "$link_stage_cleanup" -eq 1 && -d "$link_stage_dir" ]]; then
		rm -r -- "$link_stage_dir"
	fi
}
trap 'cleanup_install; cleanup_downloads' EXIT

for binary in "${binaries[@]}"; do
	cp "$tmpdir/$(asset_name "$binary")" "$stage_dir/$binary"
	chmod 0755 "$stage_dir/$binary"
	observed_version="$(env -i "$stage_dir/$binary" --version </dev/null)" || {
		printf 'The staged %s binary did not start; the installed toolset is unchanged.\n' "$binary" >&2
		exit 1
	}
	observed_product_version="${observed_version#"$binary "}"
	if [[ "$observed_product_version" == "$observed_version" ]]; then
		printf 'The staged %s binary has an unexpected embedded version; the installed toolset is unchanged.\n' "$binary" >&2
		exit 1
	fi
	if [[ -n "$nightly_suffix" ]]; then
		if [[ ! "$observed_product_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-nightly\.[0-9]{8}\.[0-9a-f]{40}$ ]] || [[ "${observed_product_version#*-}" != "$nightly_suffix" ]]; then
			printf 'The staged %s binary has an unexpected embedded nightly identity; the installed toolset is unchanged.\n' "$binary" >&2
			exit 1
		fi
		if [[ -n "$embedded_product_version" && "$observed_product_version" != "$embedded_product_version" ]]; then
			printf '%s\n' 'The staged Registry Discovery binaries report different product versions; the installed toolset is unchanged.' >&2
			exit 1
		fi
		embedded_product_version="$observed_product_version"
	elif [[ "$observed_product_version" != "${version#v}" ]]; then
		printf 'The staged %s binary has an unexpected embedded version; the installed toolset is unchanged.\n' "$binary" >&2
		exit 1
	fi
done

if [[ -e "$current_link" && ! -L "$current_link" ]]; then
	printf '%s\n' 'Refusing to replace a non-symbolic Registry Discovery toolset pointer.' >&2
	exit 1
fi

if [[ -L "$current_link" ]]; then
	had_current_link=1
	ln -s "$(readlink "$current_link")" "$link_stage_dir/previous-current"
fi

if [[ ! -L "$current_link" ]]; then
	previous_dir="$(mktemp -d "$install_dir/.discovery-previous.XXXXXX")"
	chmod 0755 "$previous_dir"
	previous_count=0
	for binary in "${binaries[@]}"; do
		if [[ -e "$install_dir/$binary" && ! -d "$install_dir/$binary" ]]; then
			cp -p "$install_dir/$binary" "$previous_dir/$binary"
			previous_count=$((previous_count + 1))
		fi
	done
	if [[ "$previous_count" -gt 0 ]]; then
		ln -s "${previous_dir##*/}" "$link_stage_dir/current"
		replace_path "$link_stage_dir/current" "$current_link"
	else
		rm -r -- "$previous_dir"
	fi
fi

for binary in "${binaries[@]}"; do
	if [[ -d "$install_dir/$binary" && ! -L "$install_dir/$binary" ]]; then
		printf 'Refusing to replace a directory at %s.\n' "$install_dir/$binary" >&2
		exit 1
	fi
	command_target=".discovery-current/$binary"
	ln -s "$command_target" "$link_stage_dir/$binary"
	if [[ -L "$install_dir/$binary" && "$(readlink "$install_dir/$binary")" == "$command_target" ]]; then
		rm -- "$link_stage_dir/$binary"
	elif [[ -L "$install_dir/$binary" ]]; then
		ln -s "$(readlink "$install_dir/$binary")" "$link_stage_dir/previous-$binary"
	elif [[ -e "$install_dir/$binary" ]]; then
		cp -p "$install_dir/$binary" "$link_stage_dir/previous-$binary"
	fi
done

ln -s "${stage_dir##*/}" "$link_stage_dir/current"
install_complete=1
transaction_active=1

for binary in "${binaries[@]}"; do
	if [[ -L "$link_stage_dir/$binary" ]]; then
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
if replace_path "$link_stage_dir/current" "$current_link"; then
	:
else
	pointer_status=$?
	rollback_adoptions || true
	exit "$pointer_status"
fi
transaction_active=0

printf 'Registry Discovery toolset %s installed to %s.\n' "$version" "$install_dir"
printf 'Both commands (%s) resolve through %s.\n' "${binaries[*]}" "$current_link"
cat <<EOF

Authenticity check not performed by this installer.
For higher assurance, verify the product release before installing:
  $verify_url

Try it:
  discovery --version
  discoveryctl --version

EOF

case ":$PATH:" in
*":$install_dir:"*) ;;
*) printf 'Add %s to PATH to run Registry Discovery from any shell.\n' "$install_dir" >&2 ;;
esac
