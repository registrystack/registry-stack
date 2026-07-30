#!/usr/bin/env bash
set -euo pipefail

readonly COMPOSE_MINIMUM_VERSION="2.35.0"
readonly COMPOSE_LINUX_X86_64_SHA256="dba1915cf2f282527f5df0cd7a94b9503047ed200317801853abe8f22c8cd493"
readonly COMPOSE_LINUX_AARCH64_SHA256="a08457d837d5d4ed7c079f0721dc51ef3f21ce2d9654a6abd44944b74d975cd2"
readonly COMPOSE_DARWIN_AARCH64_SHA256="ba47fee03b234c5b41a0e872fc08b6820c26bb65869ac76a35e40516969f55d4"

mode="${1:-both}"
if [[ "${mode}" != "both" && "${mode}" != "--current-only" && "${mode}" != "--minimum-only" ]]; then
  echo "usage: $0 [--current-only|--minimum-only]" >&2
  exit 2
fi

if [[ "${mode}" != "--minimum-only" ]]; then
  python3 release/scripts/check_adopter_compose_contract.py --label current
fi

if [[ "${mode}" == "--current-only" ]]; then
  exit 0
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    artifact="linux-x86_64"
    expected_sha256="${COMPOSE_LINUX_X86_64_SHA256}"
    ;;
  Linux-aarch64|Linux-arm64)
    artifact="linux-aarch64"
    expected_sha256="${COMPOSE_LINUX_AARCH64_SHA256}"
    ;;
  Darwin-arm64)
    artifact="darwin-aarch64"
    expected_sha256="${COMPOSE_DARWIN_AARCH64_SHA256}"
    ;;
  *)
    echo "minimum Compose probe is unsupported on $(uname -s)-$(uname -m)" >&2
    exit 2
    ;;
esac

temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "${temporary_directory}"' EXIT
compose_binary="${temporary_directory}/docker-compose"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --output "${compose_binary}" \
  "https://github.com/docker/compose/releases/download/v${COMPOSE_MINIMUM_VERSION}/docker-compose-${artifact}"

python3 - "${compose_binary}" "${expected_sha256}" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
actual = hashlib.sha256(path.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit(
        f"Compose binary checksum mismatch: expected {expected}, got {actual}"
    )
PY

chmod 0700 "${compose_binary}"
python3 release/scripts/check_adopter_compose_contract.py \
  --compose-binary "${compose_binary}" \
  --label "minimum-${COMPOSE_MINIMUM_VERSION}"
