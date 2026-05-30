#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
ssl_dir="${demo_dir}/config/postgres/ssl"
key_path="${ssl_dir}/server.key"
cert_path="${ssl_dir}/server.crt"

mkdir -p "${ssl_dir}"

if [[ -s "${key_path}" && -s "${cert_path}" ]]; then
  chmod 644 "${key_path}"
  chmod 644 "${cert_path}"
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate Postgres demo TLS files" >&2
  exit 1
fi

openssl req \
  -new \
  -x509 \
  -days 3650 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "${key_path}" \
  -out "${cert_path}" \
  >/dev/null 2>&1

chmod 644 "${key_path}"
chmod 644 "${cert_path}"
