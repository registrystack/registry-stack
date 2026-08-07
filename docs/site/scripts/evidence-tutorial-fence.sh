#!/usr/bin/env bash
#
# Read a documented fence out of a tutorial, and apply a documented
# before/after pair to a file the reader edits.
#
# The Evidence tutorial gate replays each reader journey inside a clean Debian
# userland that holds a shell, coreutils and the toolset under test, and
# nothing else. These two operations are the gate's own scaffolding, standing
# in for a reader who edits by hand, so they are written against that same
# floor: an interpreter the container does not carry fails mid-journey, where
# the transcript makes it look like a tutorial defect.
#
# Fence semantics match the site's authoring helper: a level-2 heading opens a
# section, a fence is counted per heading and language, the opening fence's
# indentation is stripped from its body, and blank lines at the body's edges
# are presentation rather than content.
#
# Usage:
#   evidence-tutorial-fence.sh write-fence <tutorial> <heading> <language> \
#       <occurrence> <out-file>
#   evidence-tutorial-fence.sh replace-block <target> <before-file> <after-file>

set -euo pipefail

usage() {
	printf 'usage: %s write-fence <tutorial> <heading> <language> <occurrence> <out-file>\n' \
		"${BASH_SOURCE[0]}" >&2
	printf '       %s replace-block <target> <before-file> <after-file>\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 2
}

write_fence() {
	(($# == 5)) || usage
	local tutorial="$1" heading="$2" language="$3" occurrence="$4" out="$5"

	if [[ ! -f "$tutorial" ]]; then
		printf 'tutorial not found: %s\n' "$tutorial" >&2
		exit 1
	fi
	if [[ ! "$occurrence" =~ ^[0-9]+$ ]] || ((occurrence < 1)); then
		printf 'fence occurrence must be a positive integer: %s\n' "$occurrence" >&2
		exit 2
	fi

	awk -v want_heading="$heading" -v want_language="$language" \
		-v want_occurrence="$occurrence" '
		found { next }
		in_fence == 0 {
			if ($0 ~ /^##[ \t]+/) {
				heading = $0
				sub(/^##[ \t]+/, "", heading)
				sub(/[ \t]+$/, "", heading)
				have_heading = 1
				next
			}
			if (have_heading && $0 ~ /^[ \t]*```[A-Za-z0-9_-]+[ \t]*$/) {
				indent = $0
				sub(/```[A-Za-z0-9_-]+[ \t]*$/, "", indent)
				language = $0
				sub(/^[ \t]*```/, "", language)
				sub(/[ \t]*$/, "", language)
				in_fence = 1
				n = 0
			}
			next
		}
		{
			closer = $0
			gsub(/^[ \t]+/, "", closer)
			gsub(/[ \t]+$/, "", closer)
			if (closer == "```") {
				key = heading SUBSEP language
				seen[key] += 1
				if (heading == want_heading && language == want_language &&
					seen[key] == want_occurrence + 0) {
					first = 1
					last = n
					while (first <= last && buffer[first] == "") first++
					while (last >= first && buffer[last] == "") last--
					for (i = first; i <= last; i++) print buffer[i]
					found = 1
				}
				in_fence = 0
				next
			}
			content = $0
			if (indent != "" && index(content, indent) == 1) {
				content = substr(content, length(indent) + 1)
			}
			buffer[++n] = content
		}
		END {
			if (!found) {
				printf "missing %s fence %s under \"%s\"\n", \
					want_language, want_occurrence, want_heading > "/dev/stderr"
				exit 1
			}
		}
	' "$tutorial" >"$out"
}

replace_block() {
	(($# == 3)) || usage
	local target="$1" before="$2" after="$3"

	local path
	for path in "$target" "$before" "$after"; do
		if [[ ! -f "$path" ]]; then
			printf 'file not found: %s\n' "$path" >&2
			exit 1
		fi
	done

	local rewritten="$target.rewritten"
	awk -v beforefile="$before" -v afterfile="$after" -v targetfile="$target" '
		# Every file is read whole, because the edit is a literal block
		# substitution: nothing here interprets the target as markup.
		function slurp(path,   text, count, line) {
			text = ""
			count = 0
			while ((getline line < path) > 0) {
				text = (count++ ? text "\n" line : line)
			}
			close(path)
			return text
		}
		BEGIN {
			before = slurp(beforefile)
			after = slurp(afterfile)
			target = slurp(targetfile)

			if (before == "") {
				print "the documented before block is empty" > "/dev/stderr"
				exit 1
			}
			if (before == after) {
				print "fence-pair replacement must change the target" > "/dev/stderr"
				exit 1
			}

			count = 0
			offset = 0
			first = 0
			while ((at = index(substr(target, offset + 1), before)) > 0) {
				count += 1
				if (count == 1) first = offset + at
				offset = offset + at + length(before) - 1
			}
			if (count != 1) {
				printf "expected one exact block in the edit target, found %d\n", \
					count > "/dev/stderr"
				exit 1
			}

			printf "%s\n", substr(target, 1, first - 1) after \
				substr(target, first + length(before))
		}
	' >"$rewritten"
	mv "$rewritten" "$target"
}

(($# > 0)) || usage
command="$1"
shift
case "$command" in
write-fence) write_fence "$@" ;;
replace-block) replace_block "$@" ;;
*)
	printf 'unknown command: %s\n' "$command" >&2
	usage
	;;
esac
