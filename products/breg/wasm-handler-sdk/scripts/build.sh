#!/usr/bin/env bash
# Build the BREG WASM handler-template module (wasm32-unknown-unknown, size
# profile), optionally pre-initialize it, record every produced module's size
# and sha256 to artifacts/module-sizes.tsv, and enforce the module-size
# ceilings: the build fails, exit 1, when a module exceeds its ceiling.
#
# Module-size ceilings (recorded product requirement, Jeremi, 2026-09-18: the
# build records the produced module's size as a build artifact and fails over
# the configured ceiling, complementing admission-time enforcement): 2 MiB for
# ordinary modules, 5 MiB for pre-initialized library modules. Both sit under
# the 5 MiB structural ceiling the compiler enforces at admission; the
# operator's wasmExecution.maxModuleBytes bounds execution between them.
#
# Usage: scripts/build.sh [--preinit] [--skip-proof]
#   --preinit     also produce the pre-initialized variant via breg-wasm-preinit
#   --skip-proof  do not run the admission proof over the produced artifacts
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CARGO_INCREMENTAL=0
TARGET=wasm32-unknown-unknown
PROFILE=release-wasm
CRATE=breg-wasm-handler-template
MODULE=breg_wasm_handler_template.wasm
PREINIT_MODULE=breg_wasm_handler_template.preinit.wasm

preinit=0
run_proof=1
for arg in "$@"; do
	case "$arg" in
	--preinit) preinit=1 ;;
	--skip-proof) run_proof=0 ;;
	*)
		printf 'usage: %s [--preinit] [--skip-proof]\n' "$0" >&2
		exit 2
		;;
	esac
done

mkdir -p artifacts
cargo build -p "$CRATE" --profile "$PROFILE" --target "$TARGET"
cp "target/$TARGET/$PROFILE/$MODULE" "artifacts/$MODULE"

if ((preinit)); then
	cargo run --quiet -p breg-wasm-preinit --release -- \
		"artifacts/$MODULE" "artifacts/$PREINIT_MODULE"
fi

ORDINARY_CEILING=$((2 * 1024 * 1024))
PREINIT_CEILING=$((5 * 1024 * 1024))
sizes=artifacts/module-sizes.tsv
printf 'artifact\tbytes\tceiling\tverdict\tsha256\n' >"$sizes"
record_size() {
	local f="$1" ceiling="$2" bytes hash verdict
	bytes="$(wc -c <"$f" | tr -d ' ')"
	hash="$(shasum -a 256 "$f" | cut -d' ' -f1)"
	if ((bytes > ceiling)); then
		verdict=over
	else
		verdict=within
	fi
	printf '%s\t%s\t%s\t%s\t%s\n' "$(basename "$f")" "$bytes" "$ceiling" "$verdict" "$hash" >>"$sizes"
	if [[ "$verdict" == over ]]; then
		printf 'FAIL %s exceeds the %s-byte ceiling (%s bytes)\n' \
			"$(basename "$f")" "$ceiling" "$bytes" >&2
		exit 1
	fi
}
record_size "artifacts/$MODULE" "$ORDINARY_CEILING"
if ((preinit)); then
	record_size "artifacts/$PREINIT_MODULE" "$PREINIT_CEILING"
fi

printf 'module sizes recorded in %s\n' "$sizes"
while IFS=$'\t' read -r artifact bytes ceiling verdict hash; do
	[[ "$artifact" == artifact ]] && continue
	printf '%-42s %12s  %10s  %s\n' "$artifact" "$bytes" "$ceiling" "$hash ($verdict)"
done <"$sizes"

if ((run_proof)); then
	cargo test -p breg-wasm-admission-proof
fi
