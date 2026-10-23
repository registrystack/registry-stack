#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" != 3 ]]; then
  echo "usage: $0 <base-version> <nightly-tag> <source-sha>" >&2
  exit 2
fi
version="$1"
tag="$2"
source_sha="$3"
python3 - "${version}" "${tag}" "${source_sha}" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path('release/scripts').resolve()))
from nightly_release import identity
if identity(sys.argv[2]) != (sys.argv[1], sys.argv[3]):
    raise SystemExit('nightly identity does not match the selected source')
PY
test "$(git rev-parse HEAD)" = "${source_sha}"
test "$(uname -m)" = aarch64
unset REGISTRY_RELEASE_TAG
export REGISTRY_NIGHTLY_TAG="${tag}"
export AWS_LC_FIPS_SYS_STATIC=1
target=aarch64-unknown-linux-gnu
rustup toolchain install 1.95.0 --profile minimal --target "${target}"
# Select the already installed toolchain directly. This prevents rustup from
# trying to reconcile the workspace's developer-only rustfmt and Clippy
# components on the first Cargo call on hosted ARM runners, where those
# component shims may already exist.
export RUSTUP_TOOLCHAIN=1.95.0

# The runner's glibc is newer than the release floor. Compile and link through
# the same pinned Zig toolchain as the canonical Linux recipe, so the floor is
# set by release/glibc-floor.env and never by the runner image. The directory
# is the same on every run, which keeps Cargo's fingerprints of the compiler
# paths valid for the restored build cache.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=zig-glibc-toolchain.sh
. release/scripts/zig-glibc-toolchain.sh
install_zig_glibc_toolchain "${RUNNER_TEMP:?RUNNER_TEMP is required}/zig-glibc-toolchain"

# Match the numbered-release arm64 recipe and feature isolation.
cargo build --release --locked -p registry-evidence \
  -p registry-evidencectl -p registry-evidence-oid4vci --target "${target}"
cargo build --release --locked -p registry-breg --bin breg --features runtime --target "${target}"
cargo build --release --locked -p registry-bregctl --target "${target}"
cargo build --release --locked -p registry-casework --bin casework --target "${target}"
cargo build --release --locked -p registry-caseworkctl --target "${target}"
cargo build --release --locked -p registry-schedulingctl --bin schedulingctl --target "${target}"
if [[ "$(python3 release/scripts/release_roster.py rstack-in-release "${version}")" == true ]]; then
  cargo build --release --locked -p registry-rstack --bin rstack --target "${target}"
fi
if [[ "$(python3 release/scripts/release_roster.py breg-services-in-release "${version}")" == true ]]; then
  cargo build --release --locked -p registry-breg-mcp --bin breg-mcp --target "${target}"
  cargo build --release --locked -p registry-breg-review --bin breg-review --target "${target}"
fi
mkdir platform
bash release/scripts/build-additional-platform-binaries.sh "${version}" "${tag}" "${target}" platform
python3 - "${version}" "${tag}" "${target}" <<'PY'
import shutil
import subprocess
import sys
import re
from pathlib import Path
sys.path.insert(0, str(Path('release/scripts').resolve()))
from release_candidate import _release_payload_inventory
version, tag, target = sys.argv[1:]
for asset, kind in _release_payload_inventory(version).items():
    if kind != 'binary' or not asset.endswith('-linux-arm64'):
        continue
    binary = asset.split(f'-v{version}-', 1)[0]
    destination = Path('platform') / asset.replace(f'v{version}', tag)
    shutil.copy2(Path('target') / target / 'release' / binary, destination)
    destination.chmod(0o755)
    observed = subprocess.check_output([str(destination), '--version'], text=True).strip()
    expected = f'{binary} {tag[1:]}'
    if binary == 'registry-render':
        pin = re.search(r'pub const TYPST_PIN: &str = "([^"]+)"', Path('crates/registry-render/src/lib.rs').read_text())
        if pin is None:
            raise SystemExit('Registry Render Typst pin is missing')
        expected += f' (typst {pin[1]})'
    if observed != expected:
        raise SystemExit(f'wrong nightly identity for {binary}')
PY
release/scripts/check-glibc-floor.sh platform/*
