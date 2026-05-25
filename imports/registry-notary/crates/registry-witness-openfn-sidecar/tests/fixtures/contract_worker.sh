#!/bin/sh
set -eu

if [ "${1:-}" = "--version" ] || [ "${2:-}" = "--version" ]; then
  printf '%s\n' 'cli_build_tool=1.36.0 runtime=1.36.0 @openfn/language-http@7.2.0:7.2.0=/fixture'
  exit 0
fi

attempt_log="${1:?attempt log path is required}"

repeat_x() {
  count="$1"
  i=0
  while [ "$i" -lt "$count" ]; do
    printf x
    i=$((i + 1))
  done
}

while IFS= read -r line; do
  printf '%s\n' "$line" >> "$attempt_log"
  case "$line" in
    *person-123*)
      printf '%s\n' '{"data":[{"national_id":"person-123","birth_date":"1990-01-01","ignored_extra":"must not appear in sidecar response"}]}'
      ;;
    *person-456*)
      printf '%s\n' '{"data":[{"national_id":"person-456","birth_date":"1985-05-05","ignored_extra":"must not appear in sidecar response"}]}'
      ;;
    *smoke-person*)
      printf '%s\n' '{"data":[{"national_id":"smoke-person"}]}'
      ;;
    *missing-person*)
      printf '%s\n' '{"data":[]}'
      ;;
    *ambiguous-person*)
      printf '%s\n' '{"data":[{"national_id":"ambiguous-person","birth_date":"1990-01-01"},{"national_id":"ambiguous-person","birth_date":"1992-02-02"},{"national_id":"ambiguous-person","birth_date":"1999-09-09"}]}'
      ;;
    *slow-person*)
      sleep 0.25
      printf '%s\n' '{"data":[{"national_id":"slow-person","birth_date":"1970-07-07"}]}'
      ;;
    *invalid-output*)
      printf '%s\n' 'this is not json'
      ;;
    *truncated-output*)
      printf '%s' '{"data":['
      exit 0
      ;;
    *timeout-person*)
      sleep 10
      printf '%s\n' '{"data":[]}'
      ;;
    *oversized-output*)
      printf '%s' '{"data":[{"national_id":"oversized-output","birth_date":"2000-01-01","blob":"'
      repeat_x 8192
      printf '%s\n' '"}]}'
      ;;
    *worker-failure*)
      printf '%s\n' 'fixture worker failure' >&2
      exit 42
      ;;
    *retry-sentinel*)
      printf '%s\n' 'retry sentinel failure' >&2
      exit 42
      ;;
    *stderr-leak*)
      printf '%s\n' "$line" >&2
      exit 42
      ;;
    *target-auth*)
      printf '%s\n' '{"error":{"code":"target_auth"}}'
      ;;
    *target-rate-limit*)
      printf '%s\n' '{"error":{"code":"target_rate_limit","retry_after_seconds":5}}'
      ;;
    *)
      printf '%s\n' '{"data":[]}'
      ;;
  esac
done
