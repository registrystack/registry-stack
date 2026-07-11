#!/usr/bin/env bash
set -euo pipefail

required_version="0.19.8"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$script_dir/.." && pwd)"
workspace_dir="$(cd -- "$repo_dir/../.." && pwd)"
tool_root="$repo_dir/target/codex-tools"
tool_bin="$tool_root/bin/cargo-deny"

installed_version=""
if [[ -x "$tool_bin" ]]; then
  installed_version="$("$tool_bin" --version | awk '{print $2}')"
fi

if [[ "$installed_version" != "$required_version" ]]; then
  cargo install cargo-deny \
    --version "$required_version" \
    --locked \
    --root "$tool_root"
fi

cd "$workspace_dir"
exec "$tool_bin" --all-features check "$@"
