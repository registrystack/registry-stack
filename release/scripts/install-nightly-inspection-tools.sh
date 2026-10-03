#!/usr/bin/env bash
set -euo pipefail

# Keep these versions and checksums aligned with release-candidate.yml. The
# workflow structure test proves that both channels inspect with the same tools.
tool_root="${RUNNER_TEMP:?}/nightly-inspection-tools"
mkdir -p "${tool_root}" "${HOME}/.local/bin"
install_tool() {
  local name="$1" url="$2" checksum="$3"
  curl -fsSL --retry 3 "${url}" -o "${tool_root}/${name}.tar.gz"
  printf '%s  %s\n' "${checksum}" "${tool_root}/${name}.tar.gz" | sha256sum --check --strict
  tar -xzf "${tool_root}/${name}.tar.gz" -C "${HOME}/.local/bin" "${name}"
}
install_tool syft https://github.com/anchore/syft/releases/download/v1.45.1/syft_1.45.1_linux_amd64.tar.gz 20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716
install_tool grype https://github.com/anchore/grype/releases/download/v0.114.0/grype_0.114.0_linux_amd64.tar.gz edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343
install_tool crane https://github.com/google/go-containerregistry/releases/download/v0.21.2/go-containerregistry_Linux_x86_64.tar.gz 897e7c342db072ba76531246fc18fbf3e8e298688b6ecf98916770984b263866
install_tool oras https://github.com/oras-project/oras/releases/download/v1.3.2/oras_1.3.2_linux_amd64.tar.gz 9229ccc6d17bb282039ad4a69abb16dcb887a5bce567c075d731d9b3c7ad8eaf
printf '%s\n' "${HOME}/.local/bin" >> "${GITHUB_PATH:?}"
