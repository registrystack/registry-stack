#!/usr/bin/env bash
set -euo pipefail

usage() {
	printf 'Usage: sudo bash %s --install [private-api-dns-name]\n' "$0"
	printf '       sudo bash %s --join https://private-api-host:6443 /absolute/token-file [private-api-dns-name]\n' "$0"
}

require_supported_ubuntu() {
	local distribution="$1"
	local version="$2"

	if [[ "$distribution" == ubuntu && ("$version" == 24.04 || "$version" == 26.04) ]]; then
		return 0
	fi
	printf 'The fresh-server bootstrap is for Ubuntu 24.04 or 26.04. Use the existing Kubernetes procedure here.\n' >&2
	return 1
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
	return 0
fi

mode="${1:-}"
if [[ "$mode" == "--help" ]]; then
	usage
	exit 0
fi
case "$mode" in
--install)
	if [[ $# -gt 2 ]]; then
		usage >&2
		exit 2
	fi
	api_name="${2:-}"
	;;
--join)
	if [[ $# -lt 3 || $# -gt 4 ]]; then
		usage >&2
		exit 2
	fi
	server_url="$2"
	token_file="$3"
	api_name="${4:-}"
	;;
*)
	usage >&2
	exit 2
	;;
esac
if [[ $EUID != 0 || "$(uname -s)/$(uname -m)" != Linux/x86_64 ]]; then
	printf 'Run this bootstrap as root on a fresh Ubuntu 24.04 or 26.04 amd64 server.\n' >&2
	exit 1
fi
# shellcheck source=/dev/null
source /etc/os-release
if ! require_supported_ubuntu "$ID" "$VERSION_ID"; then
	exit 1
fi

if [[ -n "$api_name" && ! "$api_name" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; then
	printf 'Use a lowercase DNS name for the private Kubernetes API address.\n' >&2
	exit 2
fi
if [[ "$mode" == --join ]]; then
	if [[ ! "$server_url" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?:6443$ ]]; then
		printf 'Use the private K3s API URL on HTTPS port 6443.\n' >&2
		exit 2
	fi
	if [[ ! "$token_file" =~ ^/[A-Za-z0-9._/-]+$ || ! -f "$token_file" || ! -s "$token_file" || -L "$token_file" ]]; then
		printf 'Use an absolute path to the root-owned server token file.\n' >&2
		exit 2
	fi
	token_permissions=$(stat -c '%u:%a' "$token_file")
	if [[ "$token_permissions" != 0:400 && "$token_permissions" != 0:600 ]]; then
		printf 'The K3s server token must be owned by root and readable only by root.\n' >&2
		exit 2
	fi
fi
for tool in curl sha256sum systemctl install; do
	if ! command -v "$tool" >/dev/null; then
		printf 'Install the Ubuntu package providing %s and retry.\n' "$tool" >&2
		exit 1
	fi
done

version='v1.37.2+k3s1'
binary_sha=265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda
installer_sha=ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b
binary=/usr/local/bin/k3s
config=/etc/rancher/k3s/config.yaml
bootstrap_record=/var/lib/registry-stack/bootstrap

expected_config() {
	if [[ "$mode" == --install ]]; then
		printf '%s\n' 'cluster-init: true'
	else
		printf 'server: "%s"\ntoken-file: "%s"\n' "$server_url" "$token_file"
	fi
	printf '%s\n' 'secrets-encryption: true' 'write-kubeconfig-mode: "0600"'
	if [[ -n "$api_name" ]]; then
		printf 'tls-san:\n  - "%s"\n' "$api_name"
	fi
}

if [[ ! -f "$bootstrap_record/version" ]]; then
	if [[ -e "$binary" || -L "$binary" || -e "$config" || -L "$config" || -e /var/lib/rancher/k3s/server ]] ||
		systemctl cat k3s.service >/dev/null 2>&1 || systemctl cat k3s-agent.service >/dev/null 2>&1; then
		printf 'K3s state already exists. Use the existing Kubernetes procedure.\n' >&2
		exit 1
	fi
	install -d -m 0700 "$bootstrap_record"
	expected_config >"$bootstrap_record/config.yaml"
	printf '%s\n' "$version" >"$bootstrap_record/version"
fi
if [[ "$(<"$bootstrap_record/version")" != "$version" ]] || ! expected_config | cmp -s - "$bootstrap_record/config.yaml"; then
	printf 'Bootstrap inputs differ from the recorded version or API address. Review the existing installation.\n' >&2
	exit 1
fi
if [[ -e "$config" || -L "$config" ]]; then
	if [[ -L "$config" ]] || ! cmp -s "$config" "$bootstrap_record/config.yaml"; then
		printf 'Review the existing K3s configuration before proceeding.\n' >&2
		exit 1
	fi
fi

if ! systemctl is-active --quiet k3s.service; then
	stage=$(mktemp -d)
	trap 'rm -f "$stage/k3s" "$stage/install.sh"; rmdir "$stage"' EXIT
	curl --fail --silent --show-error --location --retry 2 --max-time 180 \
		--output "$stage/k3s" "https://github.com/k3s-io/k3s/releases/download/$version/k3s"
	curl --fail --silent --show-error --location --retry 2 --max-time 60 \
		--output "$stage/install.sh" "https://raw.githubusercontent.com/k3s-io/k3s/$version/install.sh"
	printf '%s  %s\n' "$binary_sha" "$stage/k3s" "$installer_sha" "$stage/install.sh" | sha256sum --check
	if [[ ! -e "$binary" ]]; then
		install -m 0755 "$stage/k3s" "$binary"
	fi
	printf '%s  %s\n' "$binary_sha" "$binary" | sha256sum --check
	install -d -m 0755 /etc/rancher/k3s
	if [[ ! -e "$config" ]]; then
		install -m 0600 "$bootstrap_record/config.yaml" "$config"
	fi
	INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_VERSION="$version" sh "$stage/install.sh" server
fi

printf '%s  %s\n' "$binary_sha" "$binary" | sha256sum --check
node_name=$(hostname -s)
"$binary" kubectl wait "node/$node_name" --for=create --timeout=300s
"$binary" kubectl wait "node/$node_name" --for=condition=Ready --timeout=300s
printf 'K3s is ready. Check the Traefik deployment in kube-system before routing HTTPS.\n'
