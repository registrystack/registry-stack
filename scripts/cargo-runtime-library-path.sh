#!/bin/sh
# Prepare direct Cargo-built binary execution on macOS. AWS-LC FIPS is a
# dynamic library there, while Cargo only supplies its build directory to
# processes Cargo launches itself.

registry_cargo_build() {
  registry_stack_root=$1
  shift

  if [ "$(uname -s)" != Darwin ]; then
    cargo build "$@"
    return
  fi

  registry_cargo_messages=$(mktemp "${TMPDIR:-/tmp}/registry-cargo-messages.XXXXXX") || return 1
  if cargo build "$@" --message-format=json-render-diagnostics >"$registry_cargo_messages"; then
    :
  else
    registry_cargo_status=$?
    python3 "$registry_stack_root/scripts/cargo_runtime_library_path.py" \
      --render-diagnostics "$registry_cargo_messages" >&2 || :
    rm -f -- "$registry_cargo_messages"
    return "$registry_cargo_status"
  fi
  registry_fips_library_path=$(
    python3 "$registry_stack_root/scripts/cargo_runtime_library_path.py" \
      "$registry_cargo_messages"
  ) || {
    registry_cargo_status=$?
    rm -f -- "$registry_cargo_messages"
    return "$registry_cargo_status"
  }
  rm -f -- "$registry_cargo_messages"

  case "$registry_fips_library_path" in
    *:*)
      echo "AWS-LC FIPS runtime directory cannot contain a colon: $registry_fips_library_path" >&2
      return 1
      ;;
  esac
  DYLD_FALLBACK_LIBRARY_PATH="$registry_fips_library_path${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
  export DYLD_FALLBACK_LIBRARY_PATH
}

registry_prepare_cargo_runtime() {
  if [ "$(uname -s)" != Darwin ]; then
    return 0
  fi
  registry_cargo_build "$@"
}
