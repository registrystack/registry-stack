#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
ssl_dir="${demo_dir}/config/postgres/ssl"
key_path="${ssl_dir}/server.key"
cert_path="${ssl_dir}/server.crt"

mkdir -p "${ssl_dir}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate Postgres demo TLS files" >&2
  exit 1
fi

if [[ "${REGISTRY_LAB_POSTGRES_SSL_FORCE:-0}" != "1" && -s "${key_path}" && -s "${cert_path}" ]]; then
  if openssl x509 -in "${cert_path}" -noout -checkend 86400 >/dev/null 2>&1 \
    && openssl x509 -in "${cert_path}" -noout -text | grep -q "Certificate Sign"; then
    chmod 600 "${key_path}"
    chmod 644 "${cert_path}"
    exit 0
  fi
fi

openssl req \
  -new \
  -x509 \
  -days "${REGISTRY_LAB_POSTGRES_SSL_DAYS:-397}" \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "keyUsage=digitalSignature,keyEncipherment,keyCertSign" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "${key_path}" \
  -out "${cert_path}" \
  >/dev/null 2>&1

chmod 600 "${key_path}"
chmod 644 "${cert_path}"
