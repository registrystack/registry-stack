#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

mkdir -p target/security

run_optional() {
  local name="$1"
  shift
  if command -v "$name" >/dev/null 2>&1; then
    "$@"
  else
    echo "security check advisory: $name is not installed; skipped" >&2
  fi
}

python3 scripts/check_security_assurance.py

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --redact --no-banner --no-git --config .gitleaks.toml
else
  echo "security check advisory: gitleaks is not installed; skipped" >&2
fi

run_optional actionlint actionlint
if command -v zizmor >/dev/null 2>&1; then
  zizmor --no-exit-codes .
elif command -v uvx >/dev/null 2>&1; then
  uvx zizmor --no-exit-codes .
else
  echo "security check advisory: zizmor is not installed; skipped" >&2
fi

if command -v hadolint >/dev/null 2>&1; then
  hadolint --ignore DL3022 Dockerfile Dockerfile.openfn-sidecar
else
  echo "security check advisory: hadolint is not installed; skipped" >&2
fi

if command -v semgrep >/dev/null 2>&1; then
  semgrep --config .semgrep.yml --error --no-git-ignore \
    --exclude target --exclude .git --exclude .venv --exclude node_modules .
elif command -v uvx >/dev/null 2>&1; then
  uvx semgrep --config .semgrep.yml --error --no-git-ignore \
    --exclude target --exclude .git --exclude .venv --exclude node_modules .
else
  echo "security check advisory: semgrep is not installed; skipped" >&2
fi

cat > target/security/security-assurance-report.md <<'EOF'
# Registry Notary Security Assurance Report

- Exposure manifest: checked by `scripts/check_security_assurance.py`.
- OpenAPI: generated output compared with `openapi/registry-notary.openapi.json`.
- Secret scan: gitleaks ran when available.
- GitHub Actions: actionlint and zizmor ran when available.
- Container static checks: Dockerfile secret-copy checks ran; hadolint ran when available.
- Semgrep: repo-local policy ran when available.
- Skipped checks: see command output for unavailable local tools.
EOF

echo "security checks completed"
