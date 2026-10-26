#!/usr/bin/env bash
set -euo pipefail

catalog_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
scratch_parent=${TMPDIR:-/tmp}
scratch_parent=${scratch_parent%/}
work_root=$(mktemp -d "$scratch_parent/registry-evidence-source-recipes.XXXXXX")
evidencectl_bin=${EVIDENCECTL_BIN:-evidencectl}

cleanup() {
	case "$work_root" in
	"$scratch_parent"/registry-evidence-source-recipes.*)
		rm -R -- "$work_root"
		;;
	*)
		printf 'Refusing to remove unexpected fixture workspace: %s\n' "$work_root" >&2
		return 1
		;;
	esac
}
trap cleanup EXIT

if ! command -v "$evidencectl_bin" >/dev/null 2>&1; then
	printf 'Evidence fixture validation requires evidencectl. Set EVIDENCECTL_BIN to the matching binary.\n' >&2
	exit 1
fi

for recipe_name in dhis2-tracker opencrvs-event-search; do
	recipe_dir="$catalog_dir/$recipe_name"
	project_dir="$work_root/$recipe_name"
	seed_file="$recipe_dir/fixture-validation/evidence.yaml"
	definition_file="$recipe_dir/fixture-validation/assertion-definitions.yaml"

	marker_count=$(awk '/^# SOURCE_RECIPE_ASSERTION_DEFINITIONS$/ { count += 1 } END { print count + 0 }' "$seed_file")
	if [[ "$marker_count" -ne 1 ]]; then
		printf 'Recipe %s requires exactly one assertion-definition insertion marker, found %s.\n' "$recipe_name" "$marker_count" >&2
		exit 1
	fi
	if [[ ! -f "$definition_file" ]] || ! awk 'NF && $0 !~ /^[[:space:]]*#/ { found = 1 } END { exit(found ? 0 : 1) }' "$definition_file"; then
		printf 'Recipe %s requires a non-empty synthetic assertion-definition fragment.\n' "$recipe_name" >&2
		exit 1
	fi

	cp -R "$recipe_dir/fixture-validation" "$project_dir"

	"$evidencectl_bin" source import "$recipe_dir" --project "$project_dir" >/dev/null
	awk -v definition_file="$project_dir/assertion-definitions.yaml" '
    /^# SOURCE_RECIPE_ASSERTION_DEFINITIONS$/ {
      while ((getline line < definition_file) > 0) print line
      close(definition_file)
      next
    }
    { print }
  ' "$project_dir/evidence.yaml" >"$project_dir/evidence.complete.yaml"
	mv "$project_dir/evidence.complete.yaml" "$project_dir/evidence.yaml"

	"$evidencectl_bin" check "$project_dir" --target "$project_dir/local-target.yaml"
	"$evidencectl_bin" test "$project_dir" --target "$project_dir/local-target.yaml"
done

printf 'Evidence source recipe fixtures passed. No live provider was contacted.\n'
