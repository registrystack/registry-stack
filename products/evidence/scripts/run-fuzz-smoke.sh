#!/usr/bin/env bash
set -uo pipefail

if (( $# == 0 )); then
  printf '%s\n' 'usage: run-fuzz-smoke.sh TARGET [TARGET ...]' >&2
  exit 2
fi

seen=' '
for target in "$@"; do
  case "$target" in
    authoring_openapi | authoring_project | verifier_flattened_jws | verifier_sd_jwt_vc) ;;
    *)
      printf 'unknown evidence fuzz target: %s\n' "$target" >&2
      exit 2
      ;;
  esac

  case "$seen" in
    *" $target "*)
      printf 'duplicate evidence fuzz target: %s\n' "$target" >&2
      exit 2
      ;;
  esac
  seen="${seen}${target} "
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
product_dir="$(cd "${script_dir}/.." && pwd)"
cd "$product_dir" || exit 1

failed_targets=()
for target in "$@"; do
  if ! mkdir -p "fuzz/artifacts/${target}"; then
    printf 'could not create artifact directory for evidence fuzz target: %s\n' "$target" >&2
    failed_targets+=("$target")
    continue
  fi

  if cargo +nightly fuzz run --fuzz-dir fuzz --target x86_64-unknown-linux-gnu "$target" -- \
    -max_total_time=60 \
    -rss_limit_mb=1024 \
    -artifact_prefix="fuzz/artifacts/${target}/" \
    -print_final_stats=1
  then
    printf 'evidence fuzz target passed: %s\n' "$target"
  else
    status=$?
    printf 'evidence fuzz target failed: %s (exit %d)\n' "$target" "$status" >&2
    failed_targets+=("$target")
  fi
done

if (( ${#failed_targets[@]} > 0 )); then
  printf 'evidence fuzz smoke failed for:' >&2
  printf ' %s' "${failed_targets[@]}" >&2
  printf '\n' >&2
  exit 1
fi
