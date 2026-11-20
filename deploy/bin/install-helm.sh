#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" ]]; then
	printf 'Usage: %s <absolute tool directory>\n' "$0"
	exit 0
fi
if [[ $# != 1 || "$1" != /* ]]; then
	printf 'Give an absolute tool directory. Use --help for usage.\n' >&2
	exit 2
fi

version=v4.3.1
case "$(uname -s)/$(uname -m)" in
Linux/x86_64)
	platform=linux-amd64
	checksum=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
	;;
Darwin/arm64)
	platform=darwin-arm64
	checksum=6b4e61c8cd27d99e5a801e63ff25dd5c70b36875c2cd659d3e9ce6b76fc23198
	;;
*)
	printf 'The reference Helm pin supports Linux amd64 and macOS arm64.\n' >&2
	exit 1
	;;
esac

destination="$1"
if [[ -e "$destination/helm" || -L "$destination/helm" ]]; then
	if [[ -x "$destination/helm" && "$("$destination/helm" version --template '{{.Version}}')" == "$version" ]]; then
		printf 'Helm %s is available at %s/helm\n' "$version" "$destination"
		exit 0
	fi
	printf 'Review the existing %s/helm before replacing it.\n' "$destination" >&2
	exit 1
fi

stage=$(mktemp -d)
trap 'rm -f "$stage/helm.tar.gz" "$stage/helm"; rmdir "$stage"' EXIT
archive="helm-$version-$platform.tar.gz"
curl --fail --silent --show-error --location --retry 2 --max-time 90 \
	--output "$stage/helm.tar.gz" "https://get.helm.sh/$archive"
if command -v sha256sum >/dev/null; then
	printf '%s  %s\n' "$checksum" "$stage/helm.tar.gz" | sha256sum -c - >/dev/null
else
	printf '%s  %s\n' "$checksum" "$stage/helm.tar.gz" | shasum -a 256 -c - >/dev/null
fi
tar -xzf "$stage/helm.tar.gz" -O "$platform/helm" >"$stage/helm"
install -d "$destination"
install -m 0755 "$stage/helm" "$destination/helm"
"$destination/helm" version --short
