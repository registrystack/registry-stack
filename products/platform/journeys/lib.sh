#!/usr/bin/env bash
# Shared helpers for the acceptance journeys in this folder. A journey script
# sources this file and calls journey_init before anything else:
#
#   source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
#   journey_init own-provider --value-option issuer -- "$@"
#
# README.md documents the commands, the two modes and the table formats. This
# file holds the rules every journey shares.
#
# Exit status: 0 when every cell is what the mode requires, 1 when a product
# outcome is wrong (acceptance mode: a cell did not pass; ratchet mode: a cell
# differs from the table), 2 for usage or a missing prerequisite, 3 for a
# harness failure (a container that did not start, an occupied name, a
# timeout, a journey script error, a cleanup that failed, a secret found in
# saved output). A harness failure is never recorded as a product outcome.
#
# Binaries come from --bin-dir, else from a build into the exported
# CARGO_TARGET_DIR through scripts/cargo-runtime-library-path.sh. The
# repository target/ directory is never used. On macOS the AWS-LC FIPS library
# directory is exported as DYLD_FALLBACK_LIBRARY_PATH inside this shell and
# product binaries are started directly by bash. A protected launcher in
# between (/usr/bin/env, /usr/bin/time, the system Python, uv) drops every
# DYLD_* variable and the binary aborts on the missing library, so none is
# used: step deadlines are kept by a bash watchdog, not by a wrapper command.
#
# Containers are plain `docker run` on the default bridge network. A name is
# <prefix>-<journey>-<run>-<role>, is written to <out>/containers.txt the
# moment Docker creates it (seen through --cidfile, or for an interrupted
# docker run by looking up that exact name), and cleanup removes exactly the
# names in that file. Ports are published on 127.0.0.1 only. No
# network is created, no Compose file is used, nothing is pruned, no label
# filter selects what to remove, and a name that already exists is never
# adopted.
#
# Secrets are generated into <out>/secrets/ with mode 0600 and reach
# containers by env file and products by file path. Tokens stay in shell
# variables and reach curl through process substitution, so they are never on
# an argument list or on disk. Command output is captured into <out>/.raw/
# (mode 0700), passed through journey_redact into its saved place and the raw
# copy deleted. Before the run ends the saved output is scanned for every
# secret value, private key block and compact JWT.
#
# Cleanup runs from one EXIT trap on normal exit, on error and on interrupt:
# cleanup hooks, then host processes, then containers, then raw output, then
# the secret scan, then secrets. A cleanup failure is printed and turns exit
# status 0 or 1 into 3: a run that left something behind is a harness failure
# whatever the products did.
#
# Functions named journey_* are the interface for journey scripts. Functions
# named journey__* and variables named _journey_* or _jc_* are internal. A
# function that hands back a value sets a variable the caller names; the
# JOURNEY_* variables set after a step (JOURNEY_STEP_STATUS, _STDOUT, _STDERR,
# JOURNEY_HTTP_STATUS, _PROBLEM_CODE, _HEADERS, _CAPTURE_FAILED and
# JOURNEY_PROCESS_STATUS) are read by the journey scripts.
#
# shellcheck disable=SC2016 # jq and perl programs name their own $variables inside single quotes
# shellcheck disable=SC2034 # the JOURNEY_* outputs above are read by the scripts that source this file
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	printf 'lib.sh is sourced by a journey script; it does nothing on its own.\n' >&2
	exit 2
fi

JOURNEY_LIB_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
JOURNEY_ROOT="$(CDPATH='' cd -- "$JOURNEY_LIB_DIR/../../.." && pwd -P)"
JOURNEY_TABLES_DIR="${JOURNEY_TABLES_DIR:-$JOURNEY_LIB_DIR}"
JOURNEY_ASSISTS_FILE="${JOURNEY_ASSISTS_FILE:-$JOURNEY_LIB_DIR/lib-assists.sh}"
JOURNEY_STEP_TIMEOUT="${JOURNEY_STEP_TIMEOUT:-300}"
JOURNEY_KILL_GRACE="${JOURNEY_KILL_GRACE:-10}"
JOURNEY_CONTAINER_PREFIX="${JOURNEY_CONTAINER_PREFIX:-rsj}"
JOURNEY_PORT_BASE="${JOURNEY_PORT_BASE:-}"

_journey_re_id='^[a-z0-9]+(-[a-z0-9]+)*$'
_journey_re_step='^[a-z0-9]+([.-][a-z0-9]+)*$'
_journey_re_var='^[A-Za-z_][A-Za-z0-9_]*$'
_journey_re_env='^[A-Z_][A-Z0-9_]*$'
_journey_re_uint='^[0-9]+$'
_journey_re_posint='^[1-9][0-9]*$'
_journey_re_digest='^[^[:space:]@]+@sha256:[0-9a-f]{64}$'
_journey_re_code_journey='^journey\.([a-z]+)\.([a-z0-9]+(-[a-z0-9]+)*)$'
_journey_re_code_http='^http\.[1-5][0-9][0-9]\.([a-z]+(-[a-z]+)*)$'
_journey_re_code_product='^product(\.[a-z0-9]+(-[a-z0-9]+)*)+$'
_journey_re_container='^[a-z0-9][a-z0-9.-]*$'
_journey_re_header='^[A-Za-z0-9-]+: [^[:cntrl:]]*$'
_journey_re_credential_header='^([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]|[Cc][Oo][Oo][Kk][Ii][Ee]):'
_journey_nl=$'\n'

_journey_finished=0
_journey_cleaned=0
_journey_harness_message=''
_journey_exit_status=''
_journey_secret_scan='not-run'
_journey_cleanup_failures=''
_journey_address_class=''
_journey_image_lines=''
_journey_leftovers=''
_journey_taken_over=''
_journey_binaries_source=''
_journey_raw_counter=0
_journey_port_count=0
_journey_foreground_pid=''
_journey_watchdog_pid=''
_journey_run_timed_out=0
_journey_done_cells=''
_journey_value_options=()
_journey_extra_names=()
_journey_extra_values=()
_journey_cleanup_hooks=()
_journey_raw_files=()
_journey_secret_files=()
_journey_secret_labels=()
_journey_secret_dirs=()
_journey_secret_values=()
_journey_secret_value_labels=()
_journey_process_keys=()
_journey_process_pids=()
_journey_process_bases=()
_journey_process_raws=()
_journey_pending_container=''
_journey_pending_cidfile=''
_journey_products_json=''
_journey_concepts_json=''
_journey_concept_ids=''
_journey_expected_json=''
_journey_model_json=''
_journey_steps=''
_journey_last_step=''
_jc_open=0
_jc_product=''
JOURNEY_BIN_DIR=''
JOURNEY_PRODUCTS=()
JOURNEY_SELECTED=()

# ---------------------------------------------------------------------------
# Messages and failures

journey__say() {
	printf 'journey: %s\n' "$*" >&2
}

# Usage or a missing prerequisite: exit 2. During cleanup nothing exits: the
# failure is recorded as a cleanup failure and cleanup carries on.
journey_usage_error() {
	if [[ $_journey_cleaned -eq 1 ]]; then
		journey__cleanup_problem "$*"
		return 1
	fi
	journey__say "$*"
	exit 2
}

# A failure of the harness, never of a product: exit 3.
journey_harness_failure() {
	if [[ $_journey_cleaned -eq 1 ]]; then
		journey__cleanup_problem "$*"
		return 1
	fi
	journey__say "harness failure: $*"
	_journey_harness_message="$*"
	exit 3
}

journey__script_error() {
	journey_harness_failure "journey script error: $*"
}

# A function that sets or reads a variable the caller names keeps its own
# locals under _jr_ (journey_http under _jh_), so a caller's name must not
# start with _jr_: printf -v would set the function's local instead.
journey__check_var() {
	[[ "${1:-}" =~ $_journey_re_var && "${1:-}" != _jr_* ]] ||
		journey__script_error "'${1:-}' is not a variable name the library can set (names starting with _jr_ are its own)"
}

journey__check_id() {
	[[ "${2:-}" =~ $_journey_re_id ]] || journey__script_error "$1 '${2:-}' must be lowercase words joined by hyphens"
}

journey__in_list() {
	[[ $'\n'"$2"$'\n' == *$'\n'"$1"$'\n'* ]]
}

journey__plain_text() {
	[[ "$2" != *$'\t'* && "$2" != *$'\n'* ]] || journey__script_error "$1 must not contain a tab or a line break"
}

# ---------------------------------------------------------------------------
# Small tools: clock, sums, JSON and YAML readers

journey__now() {
	local _jr_value
	_jr_value="$(perl -MTime::HiRes=time -e 'printf "%.3f\n", time')" || journey_harness_failure "the clock (perl Time::HiRes) failed"
	printf -v "$1" '%s' "$_jr_value"
}

journey__elapsed() {
	local _jr_value
	_jr_value="$(perl -e 'printf "%.3f\n", $ARGV[1] - $ARGV[0]' "$1" "$2")" || journey_harness_failure "cannot subtract times"
	printf -v "$3" '%s' "$_jr_value"
}

journey__sum() {
	local _jr_value
	_jr_value="$(perl -e 'printf "%.3f\n", $ARGV[0] + $ARGV[1]' "$1" "$2")" || journey_harness_failure "cannot add times"
	printf -v "$3" '%s' "$_jr_value"
}

# journey__jq_into VAR JSON FILTER [jq options...]
journey__jq_into() {
	local _jr_target=$1 _jr_json=$2 _jr_filter=$3 _jr_out
	shift 3
	_jr_out="$(jq -r "$@" "$_jr_filter" <<<"$_jr_json")" || journey_harness_failure "jq could not evaluate $_jr_filter"
	printf -v "$_jr_target" '%s' "$_jr_out"
}

# Read a YAML table into JSON with the YAML reader in core Perl. That reader
# covers block mappings and sequences; a flow sequence of plain words (`[a, b]`)
# arrives as a string and is split here, and null, true, false and integers
# become JSON values. Anything outside that subset is refused, never guessed.
# The Perl programs in this file are single-quoted strings rather than here
# documents inside $(...), which bash 3.2 cannot parse.
_journey_perl_yaml_json='
use strict;
use warnings;
use CPAN::Meta::YAML;
use JSON::PP;
my ($path) = @ARGV;
open my $fh, "<:encoding(UTF-8)", $path or die "cannot read $path: $!\n";
local $/;
my $text = <$fh>;
close $fh;
my $docs = CPAN::Meta::YAML->read_string($text)
  or die "cannot read $path: " . CPAN::Meta::YAML->errstr . "\n";
sub value {
    my ($v) = @_;
    return undef unless defined $v;
    if ($v =~ /^\[(.*)\]$/s) {
        my $inner = $1;
        die "$path: unsupported flow sequence $v\n" if $inner =~ /[\[\]{}"\x27]/;
        return [] if $inner =~ /^\s*$/;
        return [ map { my $item = $_; $item =~ s/^\s+|\s+$//g; $item } split /,/, $inner ];
    }
    die "$path: unsupported flow mapping $v\n" if $v =~ /^\{/;
    return undef if $v eq "null" || $v eq "~";
    return JSON::PP::true if $v eq "true";
    return JSON::PP::false if $v eq "false";
    return 0 + $v if $v =~ /^-?(0|[1-9][0-9]*)$/;
    return $v;
}
sub walk {
    my ($node) = @_;
    return { map { $_ => walk($node->{$_}) } keys %$node } if ref $node eq "HASH";
    return [ map { walk($_) } @$node ] if ref $node eq "ARRAY";
    return value($node);
}
print JSON::PP->new->canonical->encode(walk($docs->[0])), "\n";
'

journey__yaml_json() {
	local _jr_json
	[[ -f "$1" ]] || journey_usage_error "the journey table $1 does not exist"
	_jr_json="$(perl -e "$_journey_perl_yaml_json" "$1")" || journey_usage_error "cannot read the journey table $1"
	printf -v "$2" '%s' "$_jr_json"
}

# The reader-time model is the readerTimeModel block of the pass rule: one
# integer per line. The rest of that file uses YAML the core reader cannot
# parse, so only that block is read, and every constant must be present.
_journey_perl_reader_model='
use strict;
use warnings;
use JSON::PP;
my ($path) = @ARGV;
open my $fh, "<", $path or die "cannot read $path: $!\n";
my ($inside, %model) = (0);
while (my $line = <$fh>) {
    chomp $line;
    if ($line =~ /^readerTimeModel:\s*(#.*)?$/) { $inside = 1; next }
    next unless $inside;
    last if $line =~ /^\S/;
    next if $line =~ /^\s*(#.*)?$/;
    $line =~ /^\s+([A-Za-z]+):\s*([0-9]+)\s*(#.*)?$/
      or die "$path: readerTimeModel holds a line that is not a name and an integer: $line\n";
    $model{$1} = 0 + $2;
}
for my $name (qw(typingCharactersPerMinute readingWordsPerMinute secondsPerHandWrittenLine
                 secondsPerConceptFirstMet minutesPerRefusalMet minutesPerAssistUsed)) {
    die "$path: readerTimeModel has no $name\n" unless exists $model{$name};
    die "$path: readerTimeModel $name must be positive\n" unless $model{$name} > 0;
}
print JSON::PP->new->canonical->encode(\%model), "\n";
'

journey__reader_model() {
	local _jr_json
	[[ -f "$1" ]] || journey_usage_error "the pass rule $1 does not exist"
	_jr_json="$(perl -e "$_journey_perl_reader_model" "$1")" || journey_usage_error "cannot read the reader-time model in $1"
	_journey_model_json=$_jr_json
}

journey__require_schema() {
	jq -e --arg schema "$2" '.schema == $schema' <<<"$1" >/dev/null ||
		journey_usage_error "$3 does not declare schema $2"
}

# ---------------------------------------------------------------------------
# Start of a run

journey__print_usage() {
	local extra='' name
	for name in ${_journey_value_options[@]+"${_journey_value_options[@]}"}; do
		extra="$extra [--$name VALUE]"
	done
	cat <<USAGE
usage: ${0##*/} [--product ID]... | [--all]$extra
         [--bin-dir DIR] [--out DIR] [--expected FILE [--strict]] [--keep]
         [--assist LIST] [--timed]

  --product ID     run one product; repeat for several. --all, the default,
                   runs every product in products.yaml
  --bin-dir DIR    take product binaries from DIR. Without it they are built
                   into the exported CARGO_TARGET_DIR; the repository target/
                   directory is never used
  --out DIR        save the run under DIR, which must be absent or empty.
                   Default: a fresh directory under TMPDIR
  --expected FILE  ratchet mode: succeed when every cell equals the table
  --strict         with --expected, also fail when a listed failure no
                   longer fails
  --keep           leave the run's containers and secrets for a later run
                   (promote --from)
  --assist LIST    comma-separated assists from lib-assists.sh. Each use is
                   counted as a pass-rule violation. Not with --expected
  --timed          refuse image pulls during the run, so its machine time is
                   usable as a baseline

Environment: JOURNEY_CONTAINER_PREFIX (default rsj), JOURNEY_PORT_BASE
(fixed host ports counted up from it; default: Docker picks free ports),
JOURNEY_STEP_TIMEOUT (seconds, default 300).

Exit status: 0 every cell as the mode requires, 1 a product outcome is wrong,
2 usage or a missing prerequisite, 3 a harness failure.
USAGE
}

journey__declared_option() {
	local name
	for name in ${_journey_value_options[@]+"${_journey_value_options[@]}"}; do
		[[ "$name" != "$1" ]] || return 0
	done
	return 1
}

journey__parse_arguments() {
	local option value inline all=0 seen=' '
	JOURNEY_SELECTED=()
	JOURNEY_STRICT=0
	JOURNEY_KEEP=0
	JOURNEY_TIMED=0
	JOURNEY_ASSISTS=''
	_journey_bin_dir_option=''
	_journey_out_option=''
	_journey_expected_option=''
	while [[ $# -gt 0 ]]; do
		option=$1
		shift
		inline=0
		value=''
		if [[ "$option" == --*=* ]]; then
			value=${option#*=}
			option=${option%%=*}
			inline=1
		fi
		case "$option" in
		-h | --help)
			[[ $inline -eq 0 ]] || journey_usage_error "$option takes no value"
			journey__print_usage
			exit 0
			;;
		--all | --strict | --keep | --timed)
			[[ $inline -eq 0 ]] || journey_usage_error "$option takes no value"
			case "$option" in
			--all) all=1 ;;
			--strict) JOURNEY_STRICT=1 ;;
			--keep) JOURNEY_KEEP=1 ;;
			--timed) JOURNEY_TIMED=1 ;;
			esac
			continue
			;;
		--product | --bin-dir | --out | --expected | --assist) ;;
		--*)
			journey__declared_option "${option#--}" || journey_usage_error "unknown option $option (run with --help)"
			;;
		*)
			journey_usage_error "unexpected argument $option (run with --help)"
			;;
		esac
		if [[ $inline -eq 0 ]]; then
			[[ $# -gt 0 ]] || journey_usage_error "$option needs a value"
			value=$1
			shift
		fi
		[[ -n "$value" ]] || journey_usage_error "$option needs a non-empty value"
		if [[ "$option" == --product ]]; then
			JOURNEY_SELECTED+=("$value")
			continue
		fi
		[[ "$seen" != *" $option "* ]] || journey_usage_error "$option is given twice"
		seen="$seen$option "
		case "$option" in
		--bin-dir) _journey_bin_dir_option=$value ;;
		--out) _journey_out_option=$value ;;
		--expected) _journey_expected_option=$value ;;
		--assist) JOURNEY_ASSISTS=$value ;;
		*)
			_journey_extra_names+=("${option#--}")
			_journey_extra_values+=("$value")
			;;
		esac
	done
	if [[ $all -eq 1 && ${#JOURNEY_SELECTED[@]} -gt 0 ]]; then
		journey_usage_error "--all and --product exclude each other"
	fi
	if [[ $JOURNEY_STRICT -eq 1 && -z "$_journey_expected_option" ]]; then
		journey_usage_error "--strict needs --expected FILE"
	fi
	if [[ -n "$JOURNEY_ASSISTS" && -n "$_journey_expected_option" ]]; then
		journey_usage_error "--assist and --expected exclude each other: the table holds unassisted outcomes"
	fi
	JOURNEY_MODE=acceptance
	if [[ -n "$_journey_expected_option" ]]; then
		JOURNEY_MODE=ratchet
	fi
}

journey__check_prerequisites() {
	local tool
	for tool in jq perl curl; do
		command -v "$tool" >/dev/null 2>&1 || journey_usage_error "this journey needs $tool on PATH"
	done
	perl -MCPAN::Meta::YAML -MJSON::PP -MTime::HiRes -MFile::Find -e 1 ||
		journey_usage_error "this journey needs perl with its core modules CPAN::Meta::YAML, JSON::PP, Time::HiRes and File::Find"
}

journey__load_tables() {
	local expected="$JOURNEY_TABLES_DIR/expected-failures.yaml"
	journey__yaml_json "$JOURNEY_TABLES_DIR/products.yaml" _journey_products_json
	journey__require_schema "$_journey_products_json" registry.journey-products/v1 "$JOURNEY_TABLES_DIR/products.yaml"
	journey__yaml_json "$JOURNEY_TABLES_DIR/concepts.yaml" _journey_concepts_json
	journey__jq_into _journey_concept_ids "$_journey_concepts_json" '.concepts[].id'
	journey__reader_model "$JOURNEY_TABLES_DIR/first-hour-pass-rule.yaml"
	if [[ -n "$_journey_expected_option" ]]; then
		[[ -f "$_journey_expected_option" ]] || journey_usage_error "--expected $_journey_expected_option is not a file"
		expected="$(CDPATH='' cd -- "$(dirname -- "$_journey_expected_option")" && pwd -P)/${_journey_expected_option##*/}" ||
			journey_usage_error "cannot resolve --expected $_journey_expected_option"
	fi
	JOURNEY_EXPECTED_FILE=$expected
	journey__yaml_json "$expected" _journey_expected_json
	journey__require_schema "$_journey_expected_json" registry.journey-expected-failures/v1 "$expected"
	journey__jq_into _journey_steps "$_journey_expected_json" '(.journeys[$journey].steps // []) | .[]' --arg journey "$JOURNEY_NAME"
	[[ -n "$_journey_steps" ]] || journey_usage_error "journey $JOURNEY_NAME has no steps in $expected"
	_journey_last_step=${_journey_steps##*"$_journey_nl"}
}

journey__select_products() {
	local ids id selected
	journey__jq_into ids "$_journey_products_json" '.products[].id'
	JOURNEY_PRODUCTS=()
	if [[ ${#JOURNEY_SELECTED[@]} -eq 0 ]]; then
		while IFS= read -r id; do
			[[ -z "$id" ]] || JOURNEY_PRODUCTS+=("$id")
		done <<<"$ids"
		return 0
	fi
	for selected in "${JOURNEY_SELECTED[@]}"; do
		journey__in_list "$selected" "$ids" || journey_usage_error "unknown product $selected; products.yaml lists: ${ids//$_journey_nl/ }"
	done
	while IFS= read -r id; do
		for selected in "${JOURNEY_SELECTED[@]}"; do
			if [[ "$selected" == "$id" ]]; then
				JOURNEY_PRODUCTS+=("$id")
				break
			fi
		done
	done <<<"$ids"
}

# Assists live in lib-assists.sh, the one file allowed to do what the pass
# rule forbids. It is sourced only when --assist names at least one assist.
journey__load_assists() {
	local name rest
	[[ -n "$JOURNEY_ASSISTS" ]] || return 0
	[[ -f "$JOURNEY_ASSISTS_FILE" ]] || journey_usage_error "--assist needs $JOURNEY_ASSISTS_FILE, which does not exist"
	# shellcheck source=/dev/null
	source "$JOURNEY_ASSISTS_FILE"
	rest="$JOURNEY_ASSISTS,"
	while [[ -n "$rest" ]]; do
		name=${rest%%,*}
		rest=${rest#*,}
		[[ "$name" =~ $_journey_re_id ]] || journey_usage_error "--assist names '$name', which is not an assist name"
		[[ "$(type -t "journey_assist_${name//-/_}")" == function ]] ||
			journey_usage_error "--assist names $name, but $JOURNEY_ASSISTS_FILE defines no journey_assist_${name//-/_}"
	done
}

journey__check_settings() {
	[[ "$JOURNEY_CONTAINER_PREFIX" =~ $_journey_re_id ]] ||
		journey_usage_error "JOURNEY_CONTAINER_PREFIX must be lowercase words joined by hyphens"
	if [[ -n "$JOURNEY_PORT_BASE" ]]; then
		if [[ ! "$JOURNEY_PORT_BASE" =~ $_journey_re_uint ]] || ((JOURNEY_PORT_BASE < 1024 || JOURNEY_PORT_BASE > 65000)); then
			journey_usage_error "JOURNEY_PORT_BASE must be a port number from 1024 to 65000"
		fi
	fi
	[[ "$JOURNEY_STEP_TIMEOUT" =~ $_journey_re_posint ]] || journey_usage_error "JOURNEY_STEP_TIMEOUT must be a whole number of seconds"
	[[ "$JOURNEY_KILL_GRACE" =~ $_journey_re_posint ]] || journey_usage_error "JOURNEY_KILL_GRACE must be a whole number of seconds"
}

journey__path_crosses_symlink() {
	local rest=${1#/} current='' part
	while [[ -n "$rest" ]]; do
		part=${rest%%/*}
		if [[ "$rest" == */* ]]; then
			rest=${rest#*/}
		else
			rest=''
		fi
		[[ -n "$part" ]] || continue
		current="$current/$part"
		if [[ -L "$current" ]]; then
			return 0
		fi
	done
	return 1
}

journey__directory_is_empty() {
	(
		shopt -s nullglob dotglob
		set -- "$1"/*
		[[ $# -eq 0 ]]
	)
}

journey__create_run_directory() {
	local requested=$_journey_out_option root physical
	if [[ -z "$requested" ]]; then
		root="$(CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P)" || journey_usage_error "cannot resolve the temporary directory ${TMPDIR:-/tmp}"
		requested="$root/$JOURNEY_CONTAINER_PREFIX-$JOURNEY_NAME-$JOURNEY_RUN_ID"
		mkdir -m 700 -- "$requested" || journey_usage_error "cannot create the run directory $requested"
	elif [[ -e "$requested" || -L "$requested" ]]; then
		[[ -d "$requested" ]] || journey_usage_error "--out $requested exists and is not a directory"
		journey__directory_is_empty "$requested" ||
			journey_usage_error "--out $requested is not empty; name an absent or empty directory so this run's cleanup lists only its own containers"
	else
		mkdir -p -- "$requested" || journey_usage_error "cannot create --out $requested"
	fi
	physical="$(CDPATH='' cd -- "$requested" && pwd -P)" || journey_usage_error "cannot resolve --out $requested"
	if journey__path_crosses_symlink "$physical"; then
		journey_usage_error "the run directory $physical still crosses a symbolic link; runtime files under it would be refused"
	fi
	# macOS chmod takes no "--"; the path is absolute, so it cannot read as an option.
	chmod 700 "$physical" || journey_usage_error "cannot set mode 0700 on $physical"
	JOURNEY_OUT=$physical
	mkdir -m 700 -- "$JOURNEY_OUT/.raw" "$JOURNEY_OUT/secrets" || journey_usage_error "cannot create the private folders under $JOURNEY_OUT"
	mkdir -- "$JOURNEY_OUT/containers" "$JOURNEY_OUT/work" || journey_usage_error "cannot create the folders under $JOURNEY_OUT"
	_journey_secret_dirs+=("$JOURNEY_OUT/secrets")
	: >"$JOURNEY_OUT/containers.txt"
	printf 'product\tstep\toutcome\tcode\tseconds\n' >"$JOURNEY_OUT/cells.tsv"
}

journey__record_environment() {
	local status_text
	_journey_git_head=''
	_journey_git_dirty=''
	_journey_git_note=''
	if _journey_git_head="$(git --no-optional-locks -C "$JOURNEY_ROOT" rev-parse HEAD 2>/dev/null)"; then
		if status_text="$(git --no-optional-locks -C "$JOURNEY_ROOT" status --porcelain)"; then
			_journey_git_dirty=false
			[[ -z "$status_text" ]] || _journey_git_dirty=true
		else
			_journey_git_note='git status failed'
		fi
	else
		_journey_git_head=''
		_journey_git_note='not a git checkout, or git is not on PATH'
	fi
	_journey_os="$(uname -s)" || journey_harness_failure "uname -s failed"
	_journey_arch="$(uname -m)" || journey_harness_failure "uname -m failed"
	_journey_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || journey_harness_failure "date failed"
}

journey__write_run_json() {
	local file="$JOURNEY_OUT/run.json" ended=''
	if [[ "${1:-}" == end ]]; then
		ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || return 1
	fi
	jq -n \
		--arg journey "$JOURNEY_NAME" \
		--arg run "$JOURNEY_RUN_ID" \
		--arg mode "$JOURNEY_MODE" \
		--argjson strict "$JOURNEY_STRICT" \
		--argjson keep "$JOURNEY_KEEP" \
		--argjson timed "$JOURNEY_TIMED" \
		--arg assists "$JOURNEY_ASSISTS" \
		--arg table "${JOURNEY_EXPECTED_FILE:-}" \
		--arg products "$(printf '%s\n' ${JOURNEY_PRODUCTS[@]+"${JOURNEY_PRODUCTS[@]}"})" \
		--arg head "$_journey_git_head" \
		--arg dirty "$_journey_git_dirty" \
		--arg gitNote "$_journey_git_note" \
		--arg os "$_journey_os" \
		--arg arch "$_journey_arch" \
		--arg addressClass "$_journey_address_class" \
		--arg prefix "$JOURNEY_CONTAINER_PREFIX" \
		--arg portBase "$JOURNEY_PORT_BASE" \
		--arg binSource "$_journey_binaries_source" \
		--arg binDir "$JOURNEY_BIN_DIR" \
		--arg runtimeLibrary "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" \
		--arg images "$_journey_image_lines" \
		--arg startedAt "$_journey_started_at" \
		--arg endedAt "$ended" \
		--arg exitStatus "$_journey_exit_status" \
		--arg harness "$_journey_harness_message" \
		--arg cleanupFailures "$_journey_cleanup_failures" \
		--arg leftovers "$_journey_leftovers" \
		--arg takenOver "$_journey_taken_over" \
		--arg secretScan "$_journey_secret_scan" \
		'def opt: if . == "" then null else . end;
		 def lines: split("\n") | map(select(length > 0));
		 {
		   schema: "registry.journey-run/v1",
		   journey: $journey, runId: $run, mode: $mode,
		   strict: ($strict == 1), keep: ($keep == 1), timed: ($timed == 1),
		   assists: ($assists | split(",") | map(select(length > 0))),
		   table: ($table | opt),
		   products: ($products | lines),
		   git: {head: ($head | opt), dirty: (if $dirty == "" then null else ($dirty == "true") end), note: ($gitNote | opt)},
		   system: {os: $os, arch: $arch},
		   addressClass: ($addressClass | opt),
		   containerPrefix: $prefix,
		   portBase: (if $portBase == "" then null else ($portBase | tonumber) end),
		   binaries: {source: ($binSource | opt), directory: ($binDir | opt), runtimeLibraryPath: ($runtimeLibrary | opt)},
		   images: [($images | lines)[] | split("\t") | {role: .[0], container: .[1], image: .[2]}],
		   takenOver: ($takenOver | opt),
		   startedAt: $startedAt,
		   endedAt: ($endedAt | opt),
		   exitStatus: (if $exitStatus == "" then null else ($exitStatus | tonumber) end),
		   harnessFailure: ($harness | opt),
		   cleanup: {failures: ($cleanupFailures | lines)},
		   leftovers: ($leftovers | lines),
		   secretScan: $secretScan
		 }' >"$file.tmp" || return 1
	mv -f -- "$file.tmp" "$file" || return 1
}

journey__install_traps() {
	trap journey__on_exit EXIT
	trap 'exit 129' HUP
	trap 'exit 130' INT
	trap 'exit 143' TERM
}

# journey_init JOURNEY [--value-option NAME]... -- "$@"
# Parses the shared options (see --help) and the journey's own value options,
# checks prerequisites, reads the tables, creates the run directory, installs
# the cleanup trap and writes run.json.
journey_init() {
	local random
	[[ $# -gt 0 ]] || journey__script_error "journey_init needs the journey name"
	JOURNEY_NAME=$1
	shift
	journey__check_id journey "$JOURNEY_NAME"
	while [[ $# -gt 0 && "$1" != -- ]]; do
		case "$1" in
		--value-option)
			[[ $# -ge 2 ]] || journey__script_error "--value-option needs a name"
			journey__check_id option "$2"
			_journey_value_options+=("$2")
			shift 2
			;;
		*) journey__script_error "journey_init: unknown declaration $1; end the declarations with --" ;;
		esac
	done
	[[ $# -gt 0 ]] || journey__script_error "journey_init: put -- before the command-line arguments"
	shift
	journey__parse_arguments "$@"
	journey__check_prerequisites
	journey__load_tables
	journey__select_products
	journey__load_assists
	journey__check_settings
	random="$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')" || journey_harness_failure "cannot read /dev/urandom"
	JOURNEY_RUN_ID="$(date -u +%Y%m%d%H%M%S)-$random" || journey_harness_failure "date failed"
	journey__record_environment
	journey__create_run_directory
	journey__install_traps
	journey__write_run_json || journey_harness_failure "cannot write $JOURNEY_OUT/run.json"
	journey__say "run $JOURNEY_RUN_ID, $JOURNEY_MODE mode, output in $JOURNEY_OUT"
}

# journey_option_value NAME VAR: the value of a journey's own --NAME option,
# or empty when it was not given.
journey_option_value() {
	local _jr_name=${1:-} _jr_target=${2:-} _jr_index
	journey__check_var "$_jr_target"
	journey__declared_option "$_jr_name" || journey__script_error "option --$_jr_name was not declared to journey_init"
	printf -v "$_jr_target" '%s' ''
	for ((_jr_index = 0; _jr_index < ${#_journey_extra_names[@]}; _jr_index++)); do
		if [[ "${_journey_extra_names[$_jr_index]}" == "$_jr_name" ]]; then
			printf -v "$_jr_target" '%s' "${_journey_extra_values[$_jr_index]}"
		fi
	done
}

# journey_product_field PRODUCT FIELD VAR: a field of the product's row in
# products.yaml. A list arrives as words joined by spaces, null as empty.
journey_product_field() {
	local _jr_product=${1:-} _jr_field=${2:-} _jr_target=${3:-} _jpf_value
	journey__check_var "$_jr_target"
	journey__jq_into _jpf_value "$_journey_products_json" \
		'[.products[] | select(.id == $product)] | if length != 1 then error("no single row") else .[0][$field] end
		 | if type == "array" then join(" ") elif . == null then "" else tostring end' \
		--arg product "$_jr_product" --arg field "$_jr_field"
	printf -v "$_jr_target" '%s' "$_jpf_value"
}

# journey_require_docker: exit 2 unless the docker CLI is on PATH and
# `docker version` reaches a running daemon.
journey_require_docker() {
	command -v docker >/dev/null 2>&1 || journey_usage_error "this journey needs the docker CLI on PATH"
	docker version --format '{{.Server.Version}}' >/dev/null ||
		journey_usage_error "this journey needs a running Docker daemon; docker version could not reach one"
}

# journey_at_cleanup FUNCTION: run FUNCTION first during cleanup (last
# registered runs first). Its failure is reported as a cleanup failure.
journey_at_cleanup() {
	[[ "$(type -t "${1:-}")" == function ]] || journey__script_error "journey_at_cleanup needs a function name"
	_journey_cleanup_hooks+=("$1")
}

# journey_set_address_class loopback|bridge: record in run.json whether the
# products reached the journey's containers through ports published on
# 127.0.0.1 or at a container address on the default bridge network.
journey_set_address_class() {
	case "${1:-}" in
	loopback | bridge) _journey_address_class=$1 ;;
	*) journey__script_error "the address class is loopback or bridge, not '${1:-}'" ;;
	esac
}

# ---------------------------------------------------------------------------
# Binaries

journey__runtime_library_from_bin_dir() {
	local directory='' candidate
	[[ "$(uname -s)" == Darwin ]] || return 0
	if [[ -n "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
		[[ -d "$REGISTRY_CARGO_RUNTIME_LIBRARY_PATH" ]] ||
			journey_usage_error "REGISTRY_CARGO_RUNTIME_LIBRARY_PATH names no directory: $REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"
		directory="$(CDPATH='' cd -- "$REGISTRY_CARGO_RUNTIME_LIBRARY_PATH" && pwd -P)" ||
			journey_usage_error "cannot resolve REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"
	else
		for candidate in "$JOURNEY_BIN_DIR"/build/aws-lc-fips-sys-*/out/build/artifacts; do
			if [[ -d "$candidate" ]]; then
				directory="$(CDPATH='' cd -- "$candidate" && pwd -P)" || journey_usage_error "cannot resolve $candidate"
				break
			fi
		done
	fi
	if [[ -z "$directory" ]]; then
		journey__say "warning: no AWS-LC FIPS library directory under $JOURNEY_BIN_DIR/build and REGISTRY_CARGO_RUNTIME_LIBRARY_PATH is unset; a binary that links the library dynamically will abort when it starts"
		return 0
	fi
	[[ "$directory" != *:* ]] || journey_usage_error "the AWS-LC FIPS runtime directory cannot contain a colon: $directory"
	REGISTRY_CARGO_RUNTIME_LIBRARY_PATH=$directory
	export REGISTRY_CARGO_RUNTIME_LIBRARY_PATH
	DYLD_FALLBACK_LIBRARY_PATH="$directory${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
	export DYLD_FALLBACK_LIBRARY_PATH
}

# journey_resolve_binaries [--package P]... [--feature F]... PRODUCT...
# With --bin-dir, use that directory as it is. Otherwise build the products'
# cargoPackages and cargoFeatures (plus any extra package or feature) with
# --locked into the exported CARGO_TARGET_DIR. Sets JOURNEY_BIN_DIR.
journey_resolve_binaries() {
	local -a products=() arguments=()
	local product value word target packages='' features='' joined=''
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--package | --feature)
			[[ $# -ge 2 && "$2" =~ ^[A-Za-z0-9_/-]+$ ]] || journey__script_error "$1 needs a package or feature name"
			if [[ "$1" == --package ]]; then packages+="$2"$'\n'; else features+="$2"$'\n'; fi
			shift 2
			;;
		-*) journey__script_error "journey_resolve_binaries: unknown option $1" ;;
		*)
			journey__in_list "$1" "$(printf '%s\n' "${JOURNEY_PRODUCTS[@]}")" || journey__script_error "product $1 is not selected for this run"
			products+=("$1")
			shift
			;;
		esac
	done
	if [[ -n "$_journey_bin_dir_option" ]]; then
		[[ -d "$_journey_bin_dir_option" ]] || journey_usage_error "--bin-dir $_journey_bin_dir_option is not a directory"
		JOURNEY_BIN_DIR="$(CDPATH='' cd -- "$_journey_bin_dir_option" && pwd -P)" || journey_usage_error "cannot resolve --bin-dir"
		_journey_binaries_source=bin-dir
		journey__runtime_library_from_bin_dir
		journey__write_run_json || journey_harness_failure "cannot write run.json"
		return 0
	fi
	[[ $JOURNEY_TIMED -eq 0 ]] ||
		journey_usage_error "--timed needs --bin-dir: a baseline run in which a build happened is discarded"
	[[ -n "${CARGO_TARGET_DIR:-}" ]] ||
		journey_usage_error "no product binaries: pass --bin-dir DIR or export CARGO_TARGET_DIR to build into; the repository target/ directory is never used"
	target=$CARGO_TARGET_DIR
	[[ "$target" == /* ]] || target="$PWD/$target"
	if [[ "$target" == "$JOURNEY_ROOT/target" || "$target" == "$JOURNEY_ROOT/target/"* ]]; then
		journey_usage_error "CARGO_TARGET_DIR points at the repository target/ directory, which a journey never uses: a stale binary there once checked green against the wrong reader"
	fi
	command -v cargo >/dev/null 2>&1 || journey_usage_error "CARGO_TARGET_DIR is set but cargo is not on PATH"
	for product in ${products[@]+"${products[@]}"}; do
		journey_product_field "$product" cargoPackages value
		for word in $value; do packages+="$word"$'\n'; done
		journey_product_field "$product" cargoFeatures value
		for word in $value; do features+="$word"$'\n'; done
	done
	[[ -n "$packages" ]] || journey__script_error "journey_resolve_binaries has no package to build"
	arguments=(--locked --manifest-path "$JOURNEY_ROOT/Cargo.toml")
	value=''
	while IFS= read -r word; do
		if [[ -z "$word" ]] || journey__in_list "$word" "$value"; then
			continue
		fi
		value+="$word"$'\n'
		arguments+=(-p "$word")
	done <<<"$packages"
	value=''
	while IFS= read -r word; do
		if [[ -z "$word" ]] || journey__in_list "$word" "$value"; then
			continue
		fi
		value+="$word"$'\n'
		joined="${joined:+$joined,}$word"
	done <<<"$features"
	[[ -z "$joined" ]] || arguments+=(--features "$joined")
	arguments+=(--bins)
	# The repository's helper: registry_cargo_build builds through cargo and, on
	# macOS, exports the FIPS library directory it reads from cargo's messages.
	# shellcheck source=/dev/null
	source "$JOURNEY_ROOT/scripts/cargo-runtime-library-path.sh"
	export CARGO_TARGET_DIR="$target"
	registry_cargo_build "$JOURNEY_ROOT" "${arguments[@]}" ||
		journey_usage_error "the build of the journey binaries failed; fix it or pass --bin-dir"
	JOURNEY_BIN_DIR="$target/debug"
	_journey_binaries_source=build
	journey__write_run_json || journey_harness_failure "cannot write run.json"
}

# journey_bin NAME VAR: the path of an executable in JOURNEY_BIN_DIR.
journey_bin() {
	local _jr_name=${1:-} _jr_target=${2:-}
	journey__check_var "$_jr_target"
	[[ -n "$JOURNEY_BIN_DIR" ]] || journey__script_error "call journey_resolve_binaries before journey_bin"
	[[ -n "$_jr_name" && "$_jr_name" != */* ]] || journey__script_error "journey_bin needs a binary name"
	[[ -x "$JOURNEY_BIN_DIR/$_jr_name" && -f "$JOURNEY_BIN_DIR/$_jr_name" ]] ||
		journey_usage_error "no executable $_jr_name in $JOURNEY_BIN_DIR"
	printf -v "$_jr_target" '%s' "$JOURNEY_BIN_DIR/$_jr_name"
}

# ---------------------------------------------------------------------------
# Raw output, secrets and redaction

journey__raw_path() {
	_journey_raw_counter=$((_journey_raw_counter + 1))
	local _jr_path="$JOURNEY_OUT/.raw/$_journey_raw_counter.$2"
	_journey_raw_files+=("$_jr_path")
	printf -v "$1" '%s' "$_jr_path"
}

journey__discard() {
	if [[ -e "$1" ]]; then
		rm -- "$1" || journey_harness_failure "cannot delete $1"
	fi
}

journey__own_secret_file() {
	_journey_secret_files+=("$1")
	_journey_secret_labels+=("$2")
}

# Every secret as one "label<TAB>value" line: the files this run generated or
# took over, and the values registered from shell variables.
journey__secret_lines() {
	local index value
	for ((index = 0; index < ${#_journey_secret_files[@]}; index++)); do
		[[ -n "${_journey_secret_labels[$index]}" && -f "${_journey_secret_files[$index]}" ]] || continue
		value="$(<"${_journey_secret_files[$index]}")"
		[[ -z "$value" ]] || printf '%s\t%s\n' "${_journey_secret_labels[$index]}" "$value"
	done
	for ((index = 0; index < ${#_journey_secret_values[@]}; index++)); do
		printf '%s\t%s\n' "${_journey_secret_value_labels[$index]}" "${_journey_secret_values[$index]}"
	done
}

# journey_secret_new NAME [BYTES]: generate BYTES (default 24) random bytes as
# hexadecimal into <out>/secrets/NAME, mode 0600. Nothing is printed.
journey_secret_new() {
	local name=${1:-} bytes=${2:-24} path
	journey__check_id "secret name" "$name"
	if [[ ! "$bytes" =~ $_journey_re_posint ]] || ((bytes < 16)); then
		journey__script_error "a secret needs at least 16 random bytes"
	fi
	path="$JOURNEY_OUT/secrets/$name"
	[[ ! -e "$path" ]] || journey__script_error "secret $name already exists"
	(
		umask 077
		od -An -N"$bytes" -tx1 /dev/urandom | tr -d ' \n' >"$path"
	) || journey_harness_failure "cannot generate secret $name"
	chmod 600 "$path" || journey_harness_failure "cannot set mode 0600 on secret $name"
	[[ -s "$path" ]] || journey_harness_failure "secret $name came out empty"
	journey__own_secret_file "$path" "$name"
}

# journey_secret_path NAME VAR
journey_secret_path() {
	local _jr_name=${1:-} _jr_target=${2:-}
	journey__check_var "$_jr_target"
	journey__check_id "secret name" "$_jr_name"
	[[ -f "$JOURNEY_OUT/secrets/$_jr_name" ]] || journey__script_error "no secret named $_jr_name"
	printf -v "$_jr_target" '%s' "$JOURNEY_OUT/secrets/$_jr_name"
}

# journey_secret_env_file NAME VAR ENV=SECRET...: write an env file of mode
# 0600 that sets each ENV to the value of a generated secret, for
# `docker run --env-file`. VAR receives its path.
journey_secret_env_file() {
	local _jr_name=${1:-} _jr_target=${2:-} _jr_path _jr_pair _jr_env _jr_secret _jr_value
	journey__check_id "env file name" "$_jr_name"
	journey__check_var "$_jr_target"
	shift 2
	_jr_path="$JOURNEY_OUT/secrets/$_jr_name.env"
	[[ ! -e "$_jr_path" ]] || journey__script_error "env file $_jr_name already exists"
	(
		umask 077
		: >"$_jr_path"
	) || journey_harness_failure "cannot create env file $_jr_name"
	journey__own_secret_file "$_jr_path" ''
	for _jr_pair in "$@"; do
		_jr_env=${_jr_pair%%=*}
		_jr_secret=${_jr_pair#*=}
		[[ "$_jr_pair" == *=* && "$_jr_env" =~ $_journey_re_env ]] || journey__script_error "an env file entry is ENV=secret-name, not $_jr_pair"
		journey__check_id "secret name" "$_jr_secret"
		[[ -f "$JOURNEY_OUT/secrets/$_jr_secret" ]] || journey__script_error "no secret named $_jr_secret"
		_jr_value="$(<"$JOURNEY_OUT/secrets/$_jr_secret")"
		printf '%s=%s\n' "$_jr_env" "$_jr_value" >>"$_jr_path" || journey_harness_failure "cannot write env file $_jr_name"
	done
	printf -v "$_jr_target" '%s' "$_jr_path"
}

# journey_secret_register LABEL VARIABLE: treat the value of a shell variable
# (a token, a captured credential) as a secret for redaction and the final
# scan. The value is read by name and never passed as an argument.
journey_secret_register() {
	local _jr_label=${1:-} _jr_variable=${2:-} _jr_value
	journey__check_id "secret label" "$_jr_label"
	journey__check_var "$_jr_variable"
	_jr_value=${!_jr_variable-}
	((${#_jr_value} >= 8)) || journey__script_error "the value of $_jr_variable is shorter than 8 characters; it cannot be redacted without hiding ordinary text"
	[[ "$_jr_value" != *$'\n'* && "$_jr_value" != *$'\t'* ]] || journey__script_error "the value of $_jr_variable holds a line break or a tab"
	_journey_secret_values+=("$_jr_value")
	_journey_secret_value_labels+=("$_jr_label")
}

# journey_redact IN OUT: copy IN to OUT with every secret value, private key
# block, compact JWT, Authorization and Cookie header value, bearer or basic
# credential, URL password and common credential member of a JSON object
# replaced by a [redacted...] marker.
journey_redact() {
	[[ -f "${1:-}" ]] || journey__script_error "journey_redact needs an input file"
	[[ -n "${2:-}" ]] || journey__script_error "journey_redact needs an output file"
	perl - "$1" "$2" 3< <(journey__secret_lines) <<'PERL'
use strict;
use warnings;
my ($in, $out) = @ARGV;
open my $list, '<&=', 3 or die "cannot read the secret list: $!\n";
my @pairs;
while (my $line = <$list>) {
    chomp $line;
    my ($label, $value) = split /\t/, $line, 2;
    push @pairs, [$label, $value] if defined $value && length $value;
}
@pairs = sort { length($b->[1]) <=> length($a->[1]) } @pairs;
open my $fh, '<:raw', $in or die "cannot read $in: $!\n";
local $/;
my $text = <$fh>;
close $fh;
$text = '' unless defined $text;
for my $pair (@pairs) {
    my $value = quotemeta $pair->[1];
    $text =~ s/$value/[redacted:$pair->[0]]/g;
}
$text =~ s/-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?-----END \1PRIVATE KEY-----/[redacted:private-key]/gs;
$text =~ s/\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/[redacted:jwt]/g;
$text =~ s/^([<>*\s]*(?:proxy-)?authorization\s*:).*$/$1 [redacted]/gmi;
$text =~ s/^([<>*\s]*(?:set-)?cookie\s*:).*$/$1 [redacted]/gmi;
$text =~ s/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]+/$1 [redacted]/g;
$text =~ s{(://[^/\s:@]+:)[^@\s/]+@}{$1\[redacted]@}g;
$text =~ s/("(?:access_token|refresh_token|id_token|client_secret|password|secret|token)"\s*:\s*)"(?:[^"\\]|\\.)*"/$1"[redacted]"/g;
open my $o, '>:raw', $out or die "cannot write $out: $!\n";
print {$o} $text;
close $o or die "cannot write $out: $!\n";
PERL
}

journey__redact_into() {
	journey_redact "$1" "$2" || journey_harness_failure "cannot redact $1 into $2"
	journey__discard "$1"
}

# ---------------------------------------------------------------------------
# Processes and deadlines

journey__process_alive() {
	local state
	state="$(ps -o stat= -p "$1" 2>/dev/null)" || return 1
	state=${state//[[:space:]]/}
	[[ -n "$state" && "$state" != Z* ]]
}

# Runs in the background: after TERM_AFTER seconds send TERM to PID, after a
# further KILL_AFTER seconds send KILL, and note each in MARKER. A TERM to the
# watchdog itself ends it at once.
journey__watchdog() {
	local pid=$1 term_after=$2 kill_after=$3 marker=$4 sleeper=''
	# shellcheck disable=SC2317,SC2329 # run by the TERM trap
	journey__watchdog_stop() {
		if [[ -n "$sleeper" ]]; then
			kill -TERM "$sleeper" 2>/dev/null || :
		fi
		exit 0
	}
	trap journey__watchdog_stop TERM
	sleep "$term_after" &
	sleeper=$!
	wait "$sleeper" || :
	sleeper=''
	journey__process_alive "$pid" || exit 0
	printf 'term\n' >>"$marker"
	kill -TERM "$pid" 2>/dev/null || exit 0
	sleep "$kill_after" &
	sleeper=$!
	wait "$sleeper" || :
	sleeper=''
	journey__process_alive "$pid" || exit 0
	printf 'kill\n' >>"$marker"
	kill -KILL "$pid" 2>/dev/null || :
	exit 0
}

journey__end_watchdog() {
	# The watchdog may have finished on its own; its exit status carries
	# nothing, the marker file does.
	kill -TERM "$1" 2>/dev/null || :
	wait "$1" || :
}

# journey__terminate PID GRACE: TERM, then KILL after GRACE seconds. Sets
# _journey_terminate_status and _journey_terminate_killed.
journey__terminate() {
	local pid=$1 grace=$2 marker watchdog status=0
	journey__raw_path marker "terminate.$pid"
	# The process may have exited already; wait below collects its status.
	kill -TERM "$pid" 2>/dev/null || :
	journey__watchdog "$pid" "$grace" 1 "$marker" </dev/null >/dev/null 2>&1 &
	watchdog=$!
	wait "$pid" || status=$?
	journey__end_watchdog "$watchdog"
	_journey_terminate_status=$status
	_journey_terminate_killed=0
	if [[ -f "$marker" ]]; then
		[[ "$(<"$marker")" != *kill* ]] || _journey_terminate_killed=1
		# Cleanup also calls this function, so a failed delete is reported
		# here and left for the final sweep of .raw rather than ending the run.
		rm -- "$marker" || journey__say "cannot delete $marker"
	fi
}

# journey__run_command DEADLINE CWD STDIN STDOUT STDERR COMMAND...: run a
# command (a binary, or a shell function such as journey_poll) directly from a
# subshell of this shell, so no launcher sits between bash and the binary.
journey__run_command() {
	local deadline=$1 cwd=$2 input=$3 output=$4 errors=$5 marker pid watchdog status=0
	shift 5
	journey__raw_path marker deadline
	(
		if [[ -n "$cwd" ]]; then
			cd -- "$cwd" || exit 126
		fi
		if [[ "$(type -t "$1")" == function ]]; then
			"$@"
			exit
		fi
		exec "$@"
	) <"$input" >"$output" 2>"$errors" &
	pid=$!
	_journey_foreground_pid=$pid
	journey__watchdog "$pid" "$deadline" "$JOURNEY_KILL_GRACE" "$marker" </dev/null >/dev/null 2>&1 &
	watchdog=$!
	_journey_watchdog_pid=$watchdog
	wait "$pid" || status=$?
	_journey_foreground_pid=''
	journey__end_watchdog "$watchdog"
	_journey_watchdog_pid=''
	_journey_run_timed_out=0
	if [[ -f "$marker" ]]; then
		_journey_run_timed_out=1
		journey__discard "$marker"
	fi
	return "$status"
}

# journey_poll SECONDS -- COMMAND...: run COMMAND once a second until it
# succeeds. Returns 1 when SECONDS pass first. Meant as a step command.
journey_poll() {
	local seconds=${1:-} deadline
	[[ "$seconds" =~ $_journey_re_posint ]] || journey__script_error "journey_poll needs a number of seconds"
	shift
	[[ "${1:-}" != -- ]] || shift
	[[ $# -gt 0 ]] || journey__script_error "journey_poll needs a command"
	deadline=$((SECONDS + seconds))
	while :; do
		if "$@"; then
			return 0
		fi
		if ((SECONDS >= deadline)); then
			printf 'journey_poll: %s did not succeed within %s seconds\n' "$1" "$seconds" >&2
			return 1
		fi
		sleep 1
	done
}

# ---------------------------------------------------------------------------
# Containers

# journey_container_name ROLE VAR
journey_container_name() {
	local _jr_role=${1:-} _jr_target=${2:-}
	journey__check_id "container role" "$_jr_role"
	journey__check_var "$_jr_target"
	printf -v "$_jr_target" '%s' "$JOURNEY_CONTAINER_PREFIX-$JOURNEY_NAME-$JOURNEY_RUN_ID-$_jr_role"
}

# journey__container_state NAME: 0 when a container of that name exists, 1
# when Docker says there is none, 2 (with Docker's message printed) when
# Docker could not answer.
journey__container_state() {
	local errors status=0
	errors="$(docker inspect --type container "$1" 2>&1 >/dev/null)" || status=$?
	[[ $status -ne 0 ]] || return 0
	if [[ "$errors" == *[Nn]o\ such* ]]; then
		return 1
	fi
	journey__say "docker inspect $1 failed: $errors"
	return 2
}

journey__record_container() {
	printf '%s\n' "$1" >>"$JOURNEY_OUT/containers.txt" || journey_harness_failure "cannot record container $1 in containers.txt"
}

# A container whose docker run was interrupted is recorded when its cidfile
# shows Docker created it. Docker writes the cidfile only after the container
# exists, so without one the exact name is looked up: it carries this run's id
# and was checked absent before docker run, so only this run can have made it.
journey__adopt_pending_container() {
	local name=$_journey_pending_container cidfile=$_journey_pending_cidfile status=0 failed=0
	_journey_pending_container=''
	_journey_pending_cidfile=''
	[[ -n "$name" ]] || return 0
	if [[ -e "$cidfile" ]]; then
		if ! rm -- "$cidfile"; then
			journey__cleanup_problem "cannot delete $cidfile"
			failed=1
		fi
	else
		journey__container_state "$name" || status=$?
		case "$status" in
		0) journey__say "docker run of $name was interrupted after Docker created it" ;;
		1) return 0 ;;
		*)
			journey__cleanup_problem "cannot tell whether the interrupted docker run created $name; remove it by that name if it exists"
			return 1
			;;
		esac
	fi
	if ! printf '%s\n' "$name" >>"$JOURNEY_OUT/containers.txt"; then
		journey__cleanup_problem "cannot record container $name; remove it by that name"
		failed=1
	fi
	return "$failed"
}

# journey_container_run ROLE [--port PORT]... [--secret-env ENV=SECRET]...
#   [docker run options]... -- IMAGE@sha256:DIGEST [ARGUMENTS]...
# Starts a detached container named by journey_container_name on the default
# bridge network, publishing each PORT on 127.0.0.1 only. Refused options:
# any network, publish, privileged, name, detach, cidfile, pull, rm or mount
# option, and a named volume (cleanup removes anonymous volumes only).
journey_container_run() {
	local role=${1:-} name image cidfile raw_out raw_err status=0 port host spec volume_source
	local -a options=() publish=() envs=()
	journey__check_id "container role" "$role"
	shift
	while [[ $# -gt 0 && "$1" != -- ]]; do
		case "$1" in
		--port)
			[[ $# -ge 2 && "$2" =~ ^[0-9]+(/(tcp|udp))?$ ]] || journey__script_error "--port needs a container port such as 5432 or 5432/tcp"
			port=$2
			if [[ -n "$JOURNEY_PORT_BASE" ]]; then
				host=$((JOURNEY_PORT_BASE + _journey_port_count))
				_journey_port_count=$((_journey_port_count + 1))
				publish+=(--publish "127.0.0.1:$host:$port")
			else
				publish+=(--publish "127.0.0.1::$port")
			fi
			shift 2
			;;
		--secret-env)
			[[ $# -ge 2 ]] || journey__script_error "--secret-env needs ENV=secret-name"
			envs+=("$2")
			shift 2
			;;
		--network | --network=* | --net | --net=* | -p | -p?* | --publish | --publish=* | -P | --publish-all | \
			--privileged | --name | --name=* | -d | --detach | --cidfile | --cidfile=* | --pull | --pull=* | \
			--rm | --mount | --mount=*)
			journey__script_error "journey_container_run refuses $1: the library owns networking, ports, names, cleanup and pulls"
			;;
		-v | --volume)
			[[ $# -ge 2 ]] || journey__script_error "$1 needs a value"
			volume_source=${2%%:*}
			[[ "$volume_source" == /* ]] || journey__script_error "volume $2 is a named volume, which cleanup would leave behind; use a bind mount from an absolute path"
			options+=("$1" "$2")
			shift 2
			;;
		-v?* | --volume=*)
			journey__script_error "write the volume option $1 as two words (-v SOURCE:TARGET)"
			;;
		*)
			options+=("$1")
			shift
			;;
		esac
	done
	[[ "${1:-}" == -- ]] || journey__script_error "journey_container_run: put -- before the image"
	shift
	image=${1:-}
	[[ "$image" =~ $_journey_re_digest ]] || journey__script_error "image '$image' is not pinned by digest (NAME:TAG@sha256:...)"
	shift
	journey_container_name "$role" name
	status=0
	journey__container_state "$name" || status=$?
	case "$status" in
	0) journey_harness_failure "a container named $name already exists; the journey never adopts one, and it was left untouched" ;;
	1) status=0 ;;
	*) journey_harness_failure "cannot tell whether container $name exists" ;;
	esac
	if [[ ${#envs[@]} -gt 0 ]]; then
		journey_secret_env_file "container-$role" spec "${envs[@]}"
		options+=(--env-file "$spec")
	fi
	if [[ $JOURNEY_TIMED -eq 1 ]]; then
		options+=(--pull never)
	fi
	journey__raw_path cidfile "$name.cid"
	journey__raw_path raw_out "$role.run.stdout"
	journey__raw_path raw_err "$role.run.stderr"
	_journey_pending_container=$name
	_journey_pending_cidfile=$cidfile
	docker run --detach --name "$name" --cidfile "$cidfile" \
		--label "registry.journey.run=$JOURNEY_RUN_ID" \
		${publish[@]+"${publish[@]}"} ${options[@]+"${options[@]}"} \
		"$image" "$@" <"/dev/null" >"$raw_out" 2>"$raw_err" || status=$?
	if [[ -e "$cidfile" ]]; then
		journey__record_container "$name"
		journey__discard "$cidfile"
	fi
	_journey_pending_container=''
	_journey_pending_cidfile=''
	_journey_image_lines+="$role"$'\t'"$name"$'\t'"$image"$'\n'
	journey__redact_into "$raw_err" "$JOURNEY_OUT/containers/$role.run.stderr"
	journey__discard "$raw_out"
	journey__write_run_json || journey_harness_failure "cannot write run.json"
	if [[ $status -ne 0 ]]; then
		journey_harness_failure "docker run for container $name failed (exit status $status); see $JOURNEY_OUT/containers/$role.run.stderr"
	fi
}

# journey_container_port ROLE PORT VAR: the host port Docker published PORT
# on. Anything but a 127.0.0.1 address is refused.
journey_container_port() {
	local _jr_role=${1:-} _jr_port=${2:-} _jr_target=${3:-} _jcn_name _jr_answer _jr_line _jr_host=''
	journey__check_var "$_jr_target"
	[[ "$_jr_port" =~ ^[0-9]+(/(tcp|udp))?$ ]] || journey__script_error "journey_container_port needs a container port"
	[[ "$_jr_port" == */* ]] || _jr_port="$_jr_port/tcp"
	journey_container_name "$_jr_role" _jcn_name
	_jr_answer="$(docker port "$_jcn_name" "$_jr_port")" || journey_harness_failure "docker port $_jcn_name $_jr_port failed"
	while IFS= read -r _jr_line; do
		_jr_line=${_jr_line//[[:space:]]/}
		if [[ "$_jr_line" =~ ^127\.0\.0\.1:([0-9]+)$ ]] && [[ "${BASH_REMATCH[1]}" != 0 ]]; then
			_jr_host=${BASH_REMATCH[1]}
			break
		fi
	done <<<"$_jr_answer"
	[[ -n "$_jr_host" ]] || journey_harness_failure "Docker did not publish $_jr_port of $_jcn_name on 127.0.0.1 (it answered: ${_jr_answer//$_journey_nl/ }); refusing to use it"
	printf -v "$_jr_target" '%s' "$_jr_host"
}

# journey_container_address ROLE VAR: the container's address on the default
# bridge network.
journey_container_address() {
	local _jr_role=${1:-} _jr_target=${2:-} _jcn_name _jr_address
	journey__check_var "$_jr_target"
	journey_container_name "$_jr_role" _jcn_name
	_jr_address="$(docker inspect --format '{{.NetworkSettings.IPAddress}}' "$_jcn_name")" ||
		journey_harness_failure "docker inspect could not read the address of $_jcn_name"
	[[ "$_jr_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
		journey_harness_failure "container $_jcn_name has no bridge address (docker inspect answered '$_jr_address')"
	printf -v "$_jr_target" '%s' "$_jr_address"
}

# journey_container_logs ROLE: save the container's log, redacted, under
# <out>/containers/.
journey_container_logs() {
	local role=${1:-} name raw_out raw_err status=0
	journey_container_name "$role" name
	journey__raw_path raw_out "$role.log.stdout"
	journey__raw_path raw_err "$role.log.stderr"
	docker logs "$name" </dev/null >"$raw_out" 2>"$raw_err" || status=$?
	journey__redact_into "$raw_out" "$JOURNEY_OUT/containers/$role.log.stdout"
	journey__redact_into "$raw_err" "$JOURNEY_OUT/containers/$role.log.stderr"
	[[ $status -eq 0 ]] || journey__say "docker logs $name failed (exit status $status)"
	return "$status"
}

# journey_container_wait ROLE SECONDS -- PROBE...: wait until PROBE succeeds.
# A container that stops, or is not ready in time, is a harness failure; its
# log is saved first. Probe output is not saved: this is setup, not a step.
journey_container_wait() {
	local role=${1:-} seconds=${2:-} name running deadline
	[[ "$seconds" =~ $_journey_re_posint ]] || journey__script_error "journey_container_wait needs a number of seconds"
	shift 2
	[[ "${1:-}" == -- ]] || journey__script_error "journey_container_wait: put -- before the probe"
	shift
	[[ $# -gt 0 ]] || journey__script_error "journey_container_wait needs a probe command"
	journey_container_name "$role" name
	deadline=$((SECONDS + seconds))
	while :; do
		running="$(docker inspect --format '{{.State.Running}}' "$name")" ||
			journey_harness_failure "docker inspect could not read the state of $name"
		if [[ "$running" != true ]]; then
			journey_container_logs "$role" || :
			journey_harness_failure "container $name stopped before it was ready; its log is under $JOURNEY_OUT/containers/"
		fi
		if "$@" </dev/null >/dev/null 2>&1; then
			return 0
		fi
		if ((SECONDS >= deadline)); then
			journey_container_logs "$role" || :
			journey_harness_failure "container $name was not ready within $seconds seconds; its log is under $JOURNEY_OUT/containers/"
		fi
		sleep 1
	done
}

# journey_check_absent NAME...: report any container that still exists after a
# product's own cleanup (for example `rstack dev stop`). A leftover is named,
# recorded in run.json and never removed. Returns 1 when one exists.
journey_check_absent() {
	local name state status=0
	for name in "$@"; do
		state=0
		journey__container_state "$name" || state=$?
		case "$state" in
		0)
			journey__say "leftover container $name still exists; it was not created by this journey, so it is reported and not removed"
			_journey_leftovers+="$name"$'\n'
			status=1
			;;
		1) ;;
		*) status=1 ;;
		esac
	done
	return "$status"
}

# journey_take_over_run DIR: make this run responsible for the containers and
# secrets of an earlier run of the same prefix that ended with --keep, so this
# run's cleanup removes them and its redaction knows the secrets.
journey_take_over_run() {
	local directory=${1:-} prefix run journey name file
	[[ -d "$directory" ]] || journey_usage_error "$directory is not a run directory"
	directory="$(CDPATH='' cd -- "$directory" && pwd -P)" || journey_usage_error "cannot resolve $directory"
	[[ -f "$directory/run.json" && -f "$directory/kept" && -f "$directory/containers.txt" ]] ||
		journey_usage_error "$directory is not a run that ended with --keep"
	prefix="$(jq -r '.containerPrefix' "$directory/run.json")" || journey_usage_error "cannot read $directory/run.json"
	run="$(jq -r '.runId' "$directory/run.json")" || journey_usage_error "cannot read $directory/run.json"
	journey="$(jq -r '.journey' "$directory/run.json")" || journey_usage_error "cannot read $directory/run.json"
	[[ "$prefix" == "$JOURNEY_CONTAINER_PREFIX" ]] ||
		journey_usage_error "$directory used container prefix $prefix, this run uses $JOURNEY_CONTAINER_PREFIX"
	while IFS= read -r name || [[ -n "$name" ]]; do
		[[ -n "$name" ]] || continue
		[[ "$name" == "$prefix-$journey-$run-"* && "$name" =~ $_journey_re_container ]] ||
			journey_usage_error "$directory/containers.txt lists $name, which that run did not name"
		journey__record_container "$name"
	done <"$directory/containers.txt"
	if [[ -d "$directory/secrets" ]]; then
		for file in "$directory/secrets"/*; do
			[[ -f "$file" ]] || continue
			case "${file##*/}" in
			*.env | cookies-*) journey__own_secret_file "$file" '' ;;
			*) journey__own_secret_file "$file" "${file##*/}" ;;
			esac
		done
		_journey_secret_dirs+=("$directory/secrets")
	fi
	_journey_taken_over=$directory
	journey__write_run_json || journey_harness_failure "cannot write run.json"
}

# ---------------------------------------------------------------------------
# Cells and steps

# journey_workdir PRODUCT VAR: <out>/work/PRODUCT, created on first use. Files
# a reader writes go here; it is kept for promote and not scanned as output.
journey_workdir() {
	local _jr_product=${1:-} _jr_target=${2:-}
	journey__check_id product "$_jr_product"
	journey__check_var "$_jr_target"
	mkdir -p -- "$JOURNEY_OUT/work/$_jr_product" || journey_harness_failure "cannot create $JOURNEY_OUT/work/$_jr_product"
	printf -v "$_jr_target" '%s' "$JOURNEY_OUT/work/$_jr_product"
}

# journey_cell_begin PRODUCT: start the cell of PRODUCT in this journey.
journey_cell_begin() {
	local product=${1:-}
	[[ $_jc_open -eq 0 ]] || journey__script_error "the cell of $_jc_product is still open; call journey_cell_end first"
	journey__in_list "$product" "$(printf '%s\n' "${JOURNEY_PRODUCTS[@]}")" || journey__script_error "product $product is not selected for this run"
	! journey__in_list "$product" "$_journey_done_cells" || journey__script_error "the cell of $product was already run"
	mkdir -- "$JOURNEY_OUT/$product" || journey_harness_failure "cannot create $JOURNEY_OUT/$product"
	_jc_open=1
	_jc_product=$product
	_jc_failed=0
	_jc_fail_step=''
	_jc_fail_code=''
	_jc_unreached=''
	_jc_reason=''
	_jc_pending=''
	_jc_last_step=''
	_jc_step_seconds=0.000
	_jc_recorded=''
	_jc_assisted_steps=''
	_jc_steps=0
	_jc_files=0
	_jc_lines=0
	_jc_chars=0
	_jc_doc_words=0
	_jc_idp=0
	_jc_certs=0
	_jc_refusals=0
	_jc_named=0
	_jc_assist_count=0
	_jc_seconds=0.000
	_jc_concepts=''
	_jc_touched=''
	_jc_blockers_json='[]'
	_jc_t1_json=null
	_jc_t2_json=null
}

journey__require_cell() {
	[[ $_jc_open -eq 1 ]] || journey__script_error "no cell is open; call journey_cell_begin first"
}

journey__check_step() {
	if [[ ! "$1" =~ $_journey_re_step ]] || ! journey__in_list "$1" "$_journey_steps"; then
		journey__script_error "'$1' is not a step of journey $JOURNEY_NAME (the table lists: ${_journey_steps//$_journey_nl/ })"
	fi
}

journey__require_running() {
	[[ $_jc_failed -eq 0 && -z "$_jc_unreached" ]] ||
		journey__script_error "$_jc_product already stopped at step ${_jc_fail_step:-$_jc_unreached}; a journey stops a product at its first blocker"
}

journey__require_resolved() {
	[[ -z "$_jc_pending" ]] ||
		journey__script_error "the command of step $_jc_pending failed and no outcome was recorded for it (journey_fail, journey_needs or journey_blocker)"
}

journey__require_step_start() {
	journey__require_cell
	journey__check_step "$1"
	journey__require_running
	journey__require_resolved
	! journey__in_list "$1" "$_jc_recorded" || journey__script_error "step $1 of $_jc_product was already recorded"
}

journey__declare_concepts() {
	local rest="$1," concept
	[[ -n "$1" ]] || return 0
	while [[ -n "$rest" ]]; do
		concept=${rest%%,*}
		rest=${rest#*,}
		journey__in_list "$concept" "$_journey_concept_ids" || journey__script_error "concept '$concept' is not in concepts.yaml"
		journey__in_list "$concept" "$_jc_concepts" || _jc_concepts+="$concept"$'\n'
	done
}

journey__count_command() {
	_jc_steps=$((_jc_steps + 1))
	_jc_chars=$((_jc_chars + ${#1}))
}

journey__output_base() {
	local _jr_base="$JOURNEY_OUT/$_jc_product/$2" _jr_n=2
	if [[ -e "$_jr_base.stdout" ]]; then
		while [[ -e "$_jr_base.$_jr_n.stdout" ]]; do
			_jr_n=$((_jr_n + 1))
		done
		_jr_base="$_jr_base.$_jr_n"
	fi
	printf -v "$1" '%s' "$_jr_base"
}

journey__add_step_time() {
	local seconds
	journey__elapsed "$2" "$3" seconds
	if [[ "$_jc_last_step" == "$1" ]]; then
		journey__sum "$_jc_step_seconds" "$seconds" _jc_step_seconds
	else
		_jc_step_seconds=$seconds
		_jc_last_step=$1
	fi
	journey__sum "$_jc_seconds" "$seconds" _jc_seconds
}

# What the reader types for a command: its base name and its arguments.
journey__typed_text() {
	local text=${1##*/} argument
	shift
	for argument in "$@"; do
		text+=" $argument"
	done
	_jo_typed=$text
}

# Options every step function takes. Sets _jo_* and _jo_shift.
journey__step_options() {
	_jo_cwd=''
	_jo_stdin=/dev/null
	_jo_timeout=''
	_jo_settle=2
	_jo_concepts=''
	_jo_words=0
	_jo_typed=''
	_jo_typed_set=0
	_jo_shift=0
	while [[ $# -gt 0 && "$1" != -- ]]; do
		[[ $# -ge 2 ]] || journey__script_error "step option $1 needs a value"
		case "$1" in
		--cwd) [[ -d "$2" ]] || journey__script_error "--cwd $2 is not a directory" ;;
		--stdin) [[ -f "$2" ]] || journey__script_error "--stdin $2 is not a file" ;;
		--timeout | --settle) [[ "$2" =~ $_journey_re_posint ]] || journey__script_error "$1 needs a whole number of seconds" ;;
		--doc-words) [[ "$2" =~ $_journey_re_uint ]] || journey__script_error "--doc-words needs a count" ;;
		--concepts | --typed) ;;
		*) journey__script_error "unknown step option $1" ;;
		esac
		case "$1" in
		--cwd) _jo_cwd=$2 ;;
		--stdin) _jo_stdin=$2 ;;
		--timeout) _jo_timeout=$2 ;;
		--settle) _jo_settle=$2 ;;
		--doc-words) _jo_words=$2 ;;
		--concepts) _jo_concepts=$2 ;;
		--typed)
			_jo_typed=$2
			_jo_typed_set=1
			;;
		esac
		shift 2
		_jo_shift=$((_jo_shift + 2))
	done
	[[ "${1:-}" == -- ]] || journey__script_error "put -- before the step's command"
	_jo_shift=$((_jo_shift + 1))
}

journey__begin_command() {
	journey__declare_concepts "$_jo_concepts"
	journey__count_command "$_jo_typed"
	_jc_doc_words=$((_jc_doc_words + _jo_words))
}

# journey_step STEP [--cwd DIR] [--stdin FILE] [--timeout S] [--concepts A,B]
#   [--doc-words N] [--typed TEXT] -- COMMAND...
# Run one command a reader would type, as part of STEP of the open cell. Its
# output is saved, redacted, as <out>/<product>/<step>.stdout and .stderr
# (a second command of the same step gets <step>.2.*). Returns the command's
# exit status and records nothing: follow with journey_pass, or with
# journey_fail, journey_needs or journey_blocker when it failed. A command
# that runs past its deadline is a harness failure.
journey_step() {
	local step=${1:-} base raw_out raw_err started ended status=0 timeout
	[[ $# -eq 0 ]] || shift
	journey__require_step_start "$step"
	journey__step_options "$@"
	shift "$_jo_shift"
	[[ $# -gt 0 ]] || journey__script_error "step $step needs a command"
	[[ $_jo_typed_set -eq 1 ]] || journey__typed_text "$@"
	timeout=${_jo_timeout:-$JOURNEY_STEP_TIMEOUT}
	journey__begin_command
	journey__output_base base "$step"
	journey__raw_path raw_out "$step.stdout"
	journey__raw_path raw_err "$step.stderr"
	journey__now started
	journey__run_command "$timeout" "$_jo_cwd" "$_jo_stdin" "$raw_out" "$raw_err" "$@" || status=$?
	journey__now ended
	journey__redact_into "$raw_out" "$base.stdout"
	journey__redact_into "$raw_err" "$base.stderr"
	if [[ $_journey_run_timed_out -eq 1 ]]; then
		journey_harness_failure "step $step of $_jc_product did not finish within $timeout seconds; its output is in $base.stdout and $base.stderr"
	fi
	journey__add_step_time "$step" "$started" "$ended"
	JOURNEY_STEP_STATUS=$status
	JOURNEY_STEP_STDOUT="$base.stdout"
	JOURNEY_STEP_STDERR="$base.stderr"
	if [[ $status -ne 0 ]]; then
		_jc_pending=$step
	fi
	return "$status"
}

journey__http_headers() {
	local _jh_header
	if [[ -n "$1" ]]; then
		printf 'Authorization: Bearer %s\n' "${!1}"
	fi
	shift
	for _jh_header in "$@"; do
		printf '%s\n' "$_jh_header"
	done
}

# journey_http STEP [--bearer VAR] [--header 'Name: value']... [--form K=V]...
#   [--form-secret K=SECRET]... [--data-file FILE] [--cookie-jar NAME]
#   [--location] [--capture FILTER VAR]... [--capture-secret FILTER VAR]...
#   [--timeout S] [--concepts A,B] [--doc-words N] [--typed TEXT] METHOD URL
# One HTTP request as part of STEP. The token in VAR and every --form-secret
# value reach curl through a file descriptor or a file path, never as an
# argument. Saves <step>.http (status line and response headers), .stdout
# (body) and .stderr, all redacted; request headers are never saved. Sets
# JOURNEY_HTTP_STATUS (000 when no answer came) and JOURNEY_HTTP_PROBLEM_CODE
# (the body's "code" member, or empty). --capture and --capture-secret set VAR
# from a jq filter on a 2xx body; --capture-secret also registers the value
# for redaction. Returns 0 for a 2xx answer whose captures all succeeded.
journey_http() {
	local _jh_step=${1:-} _jh_bearer='' _jh_cookie='' _jh_location=0 _jh_data_file='' _jh_timeout=30
	local _jh_method _jh_url _jh_base _jh_raw_headers _jh_raw_body _jh_raw_err _jh_raw_status
	local _jh_started _jh_ended _jh_curl_status=0 _jh_code _jh_problem _jh_value _jh_result=0 _jh_index _jh_path
	local -a _jh_headers=() _jh_data=() _jh_capture_filters=() _jh_capture_vars=() _jh_capture_secret=() _jh_args=()
	[[ $# -eq 0 ]] || shift
	journey__require_step_start "$_jh_step"
	_jo_concepts=''
	_jo_words=0
	_jo_typed=''
	_jo_typed_set=0
	while [[ $# -gt 0 && "$1" == --* ]]; do
		case "$1" in
		--location)
			_jh_location=1
			shift
			continue
			;;
		--capture | --capture-secret)
			[[ $# -ge 3 ]] || journey__script_error "$1 needs a jq filter and a variable name"
			journey__check_var "$3"
			[[ "$3" != _jh_* ]] || journey__script_error "'$3' is not a variable name journey_http can set (names starting with _jh_ are its own)"
			_jh_capture_filters+=("$2")
			_jh_capture_vars+=("$3")
			if [[ "$1" == --capture-secret ]]; then _jh_capture_secret+=(1); else _jh_capture_secret+=(0); fi
			shift 3
			continue
			;;
		esac
		[[ $# -ge 2 ]] || journey__script_error "$1 needs a value"
		case "$1" in
		--bearer)
			journey__check_var "$2"
			[[ "$2" != _jh_* ]] || journey__script_error "'$2' is not a variable name journey_http can read (names starting with _jh_ are its own)"
			[[ -n "${!2-}" ]] || journey__script_error "the bearer token variable $2 is empty"
			_jh_bearer=$2
			;;
		--header)
			[[ "$2" =~ $_journey_re_header ]] || journey__script_error "a header is 'Name: value', not '$2'"
			[[ ! "$2" =~ $_journey_re_credential_header ]] || journey__script_error "pass a token with --bearer VAR, never as a header"
			_jh_headers+=("$2")
			;;
		--form)
			[[ "$2" == ?*=* ]] || journey__script_error "--form needs KEY=VALUE"
			_jh_data+=(--data-urlencode "$2")
			;;
		--form-secret)
			[[ "$2" == ?*=* ]] || journey__script_error "--form-secret needs KEY=secret-name"
			journey_secret_path "${2#*=}" _jh_path
			_jh_data+=(--data-urlencode "${2%%=*}@$_jh_path")
			;;
		--data-file)
			[[ -f "$2" ]] || journey__script_error "--data-file $2 is not a file"
			_jh_data_file=$2
			;;
		--cookie-jar)
			journey__check_id "cookie jar" "$2"
			_jh_cookie="$JOURNEY_OUT/secrets/cookies-$2"
			if [[ ! -e "$_jh_cookie" ]]; then
				(
					umask 077
					: >"$_jh_cookie"
				) || journey_harness_failure "cannot create cookie jar $2"
				journey__own_secret_file "$_jh_cookie" ''
			fi
			;;
		--timeout)
			[[ "$2" =~ $_journey_re_posint ]] || journey__script_error "--timeout needs a whole number of seconds"
			_jh_timeout=$2
			;;
		--concepts) _jo_concepts=$2 ;;
		--doc-words)
			[[ "$2" =~ $_journey_re_uint ]] || journey__script_error "--doc-words needs a count"
			_jo_words=$2
			;;
		--typed)
			_jo_typed=$2
			_jo_typed_set=1
			;;
		*) journey__script_error "journey_http: unknown option $1" ;;
		esac
		shift 2
	done
	[[ $# -eq 2 ]] || journey__script_error "journey_http needs METHOD and URL after its options"
	_jh_method=$1
	_jh_url=$2
	[[ "$_jh_method" =~ ^[A-Z]+$ ]] || journey__script_error "'$_jh_method' is not an HTTP method"
	[[ "$_jh_url" =~ ^https?://[^[:space:]]+$ ]] || journey__script_error "'$_jh_url' is not an http or https URL"
	if [[ $_jo_typed_set -eq 0 ]]; then
		_jo_typed="curl -X $_jh_method $_jh_url"
		[[ -z "$_jh_bearer" ]] || _jo_typed+=' -H "Authorization: Bearer $TOKEN"'
	fi
	journey__begin_command
	journey__output_base _jh_base "$_jh_step"
	journey__raw_path _jh_raw_headers "$_jh_step.http"
	journey__raw_path _jh_raw_body "$_jh_step.stdout"
	journey__raw_path _jh_raw_err "$_jh_step.stderr"
	journey__raw_path _jh_raw_status "$_jh_step.status"
	_jh_args=(--silent --show-error --max-time "$_jh_timeout" --connect-timeout 10 -X "$_jh_method"
		--dump-header "$_jh_raw_headers" --output "$_jh_raw_body" --write-out '%{http_code}')
	[[ $_jh_location -eq 0 ]] || _jh_args+=(--location)
	[[ -z "$_jh_cookie" ]] || _jh_args+=(--cookie "$_jh_cookie" --cookie-jar "$_jh_cookie")
	[[ -z "$_jh_data_file" ]] || _jh_args+=(--data-binary "@$_jh_data_file")
	journey__now _jh_started
	curl "${_jh_args[@]}" ${_jh_data[@]+"${_jh_data[@]}"} \
		-H "@"<(journey__http_headers "$_jh_bearer" ${_jh_headers[@]+"${_jh_headers[@]}"}) \
		"$_jh_url" </dev/null >"$_jh_raw_status" 2>"$_jh_raw_err" || _jh_curl_status=$?
	journey__now _jh_ended
	_jh_code="$(<"$_jh_raw_status")"
	[[ "$_jh_code" =~ ^[0-9]{3}$ ]] || _jh_code=000
	[[ -f "$_jh_raw_headers" ]] || : >"$_jh_raw_headers"
	[[ -f "$_jh_raw_body" ]] || : >"$_jh_raw_body"
	JOURNEY_HTTP_STATUS=$_jh_code
	JOURNEY_HTTP_CAPTURE_FAILED=''
	# A body that is not a JSON object has no problem code; that is an answer,
	# not an error, so jq's refusal is not reported.
	_jh_problem="$(jq -r 'if type == "object" and (.code | type) == "string" then .code else empty end' "$_jh_raw_body" 2>/dev/null)" || _jh_problem=''
	JOURNEY_HTTP_PROBLEM_CODE=$_jh_problem
	if [[ $_jh_curl_status -ne 0 || ! "$_jh_code" =~ ^2 ]]; then
		_jh_result=1
	else
		for ((_jh_index = 0; _jh_index < ${#_jh_capture_filters[@]}; _jh_index++)); do
			if ! _jh_value="$(jq -er "${_jh_capture_filters[$_jh_index]}" "$_jh_raw_body")" || [[ -z "$_jh_value" ]]; then
				JOURNEY_HTTP_CAPTURE_FAILED=${_jh_capture_filters[$_jh_index]}
				_jh_result=1
				break
			fi
			printf -v "${_jh_capture_vars[$_jh_index]}" '%s' "$_jh_value"
			if [[ "${_jh_capture_secret[$_jh_index]}" == 1 ]]; then
				journey_secret_register "$_jh_step-capture" "${_jh_capture_vars[$_jh_index]}"
			fi
		done
	fi
	journey__redact_into "$_jh_raw_headers" "$_jh_base.http"
	journey__redact_into "$_jh_raw_body" "$_jh_base.stdout"
	journey__redact_into "$_jh_raw_err" "$_jh_base.stderr"
	journey__discard "$_jh_raw_status"
	journey__add_step_time "$_jh_step" "$_jh_started" "$_jh_ended"
	JOURNEY_STEP_STATUS=$_jh_result
	JOURNEY_STEP_STDOUT="$_jh_base.stdout"
	JOURNEY_STEP_STDERR="$_jh_base.stderr"
	JOURNEY_HTTP_HEADERS="$_jh_base.http"
	if [[ $_jh_result -ne 0 ]]; then
		_jc_pending=$_jh_step
	fi
	return "$_jh_result"
}

journey__process_index() {
	local _jr_index
	for ((_jr_index = 0; _jr_index < ${#_journey_process_keys[@]}; _jr_index++)); do
		if [[ "${_journey_process_keys[$_jr_index]}" == "$2" && -n "${_journey_process_pids[$_jr_index]}" ]]; then
			printf -v "$1" '%s' "$_jr_index"
			return 0
		fi
	done
	return 1
}

journey__refresh_process_logs() {
	local index=$1
	journey_redact "${_journey_process_raws[$index]}.stdout" "${_journey_process_bases[$index]}.stdout" &&
		journey_redact "${_journey_process_raws[$index]}.stderr" "${_journey_process_bases[$index]}.stderr"
}

journey__finish_process() {
	local index=$1
	journey__refresh_process_logs "$index" || journey_harness_failure "cannot redact the log of ${_journey_process_keys[$index]}"
	journey__discard "${_journey_process_raws[$index]}.stdout"
	journey__discard "${_journey_process_raws[$index]}.stderr"
	_journey_process_pids[index]=''
}

# journey_start STEP NAME [--cwd DIR] [--stdin FILE] [--settle S]
#   [--concepts A,B] [--doc-words N] [--typed TEXT] -- COMMAND...
# Start a long-running product process (a server) in the background as STEP.
# Its output is saved, redacted, as <out>/<product>/<step>.stdout and .stderr.
# Returns 0 when it is still running after S seconds (default 2). When it
# exits first, returns 1, sets JOURNEY_PROCESS_STATUS and leaves the step for
# journey_fail. Cleanup stops every process still running.
journey_start() {
	local step=${1:-} name=${2:-} base raw started ended pid index attempts=0 status=0
	[[ $# -lt 2 ]] || shift 2
	journey__require_step_start "$step"
	journey__check_id "process name" "$name"
	! journey__process_index index "$_jc_product/$name" || journey__script_error "process $name of $_jc_product is already running"
	journey__step_options "$@"
	shift "$_jo_shift"
	[[ $# -gt 0 ]] || journey__script_error "step $step needs a command"
	[[ $_jo_typed_set -eq 1 ]] || journey__typed_text "$@"
	journey__begin_command
	journey__output_base base "$step"
	journey__raw_path raw "$step.process"
	: >"$raw.stdout"
	: >"$raw.stderr"
	_journey_raw_files+=("$raw.stdout" "$raw.stderr")
	journey__now started
	(
		if [[ -n "$_jo_cwd" ]]; then
			cd -- "$_jo_cwd" || exit 126
		fi
		exec "$@"
	) <"$_jo_stdin" >"$raw.stdout" 2>"$raw.stderr" &
	pid=$!
	_journey_process_keys+=("$_jc_product/$name")
	_journey_process_pids+=("$pid")
	_journey_process_bases+=("$base")
	_journey_process_raws+=("$raw")
	index=$((${#_journey_process_pids[@]} - 1))
	printf '%s\t%s\t%s\n' "$pid" "$_jc_product" "$name" >>"$JOURNEY_OUT/processes.txt" ||
		journey_harness_failure "cannot record process $name in processes.txt"
	while ((attempts < _jo_settle * 5)) && journey__process_alive "$pid"; do
		sleep 0.2
		attempts=$((attempts + 1))
	done
	journey__now ended
	journey__add_step_time "$step" "$started" "$ended"
	JOURNEY_STEP_STDOUT="$base.stdout"
	JOURNEY_STEP_STDERR="$base.stderr"
	if journey__process_alive "$pid"; then
		JOURNEY_PROCESS_STATUS=''
		journey__refresh_process_logs "$index" || journey_harness_failure "cannot redact the log of $name"
		return 0
	fi
	wait "$pid" || status=$?
	JOURNEY_PROCESS_STATUS=$status
	journey__finish_process "$index"
	_jc_pending=$step
	return 1
}

# journey_ready STEP NAME [--timeout S] [--cwd DIR] [--concepts A,B]
#   [--doc-words N] [--typed TEXT] -- PROBE...
# Poll PROBE once a second until it succeeds while process NAME keeps running,
# for up to S seconds (default 60). The last probe's output is saved. Returns
# 1 when the process exits (JOURNEY_PROCESS_STATUS is set) or time runs out.
journey_ready() {
	local step=${1:-} name=${2:-} index base raw_out raw_err started ended deadline remaining status=1 attempt pid
	[[ $# -lt 2 ]] || shift 2
	journey__require_step_start "$step"
	journey__process_index index "$_jc_product/$name" || journey__script_error "no running process $name for $_jc_product"
	journey__step_options "$@"
	shift "$_jo_shift"
	[[ $# -gt 0 ]] || journey__script_error "step $step needs a probe command"
	[[ $_jo_typed_set -eq 1 ]] || journey__typed_text "$@"
	journey__begin_command
	journey__output_base base "$step"
	journey__raw_path raw_out "$step.stdout"
	journey__raw_path raw_err "$step.stderr"
	: >"$raw_out"
	: >"$raw_err"
	pid=${_journey_process_pids[$index]}
	JOURNEY_PROCESS_STATUS=''
	journey__now started
	deadline=$((SECONDS + ${_jo_timeout:-60}))
	while :; do
		if ! journey__process_alive "$pid"; then
			attempt=0
			wait "$pid" || attempt=$?
			JOURNEY_PROCESS_STATUS=$attempt
			journey__finish_process "$index"
			break
		fi
		remaining=$((deadline - SECONDS))
		((remaining > 0)) || break
		attempt=0
		journey__run_command "$remaining" "$_jo_cwd" /dev/null "$raw_out" "$raw_err" "$@" || attempt=$?
		if [[ $attempt -eq 0 && $_journey_run_timed_out -eq 0 ]]; then
			status=0
			break
		fi
		sleep 1
	done
	journey__now ended
	journey__redact_into "$raw_out" "$base.stdout"
	journey__redact_into "$raw_err" "$base.stderr"
	journey__add_step_time "$step" "$started" "$ended"
	JOURNEY_STEP_STDOUT="$base.stdout"
	JOURNEY_STEP_STDERR="$base.stderr"
	if [[ $status -ne 0 ]]; then
		_jc_pending=$step
	fi
	return "$status"
}

# journey_stop STEP NAME [--timeout S] [--concepts A,B] [--typed TEXT]
# Stop process NAME as a reader would (SIGTERM), waiting up to S seconds
# (default 30) before SIGKILL. Sets JOURNEY_PROCESS_STATUS. Returns 1 when the
# process had to be killed.
journey_stop() {
	local step=${1:-} name=${2:-} index started ended
	[[ $# -lt 2 ]] || shift 2
	journey__require_step_start "$step"
	journey__process_index index "$_jc_product/$name" || journey__script_error "no running process $name for $_jc_product"
	journey__step_options "$@" --
	shift "$((_jo_shift - 1))"
	[[ $# -eq 0 ]] || journey__script_error "journey_stop takes options only, not '$*'"
	[[ $_jo_typed_set -eq 1 ]] || _jo_typed='^C'
	journey__begin_command
	journey__now started
	journey__terminate "${_journey_process_pids[$index]}" "${_jo_timeout:-30}"
	journey__now ended
	JOURNEY_PROCESS_STATUS=$_journey_terminate_status
	journey__finish_process "$index"
	journey__add_step_time "$step" "$started" "$ended"
	if [[ $_journey_terminate_killed -eq 1 ]]; then
		_jc_pending=$step
		return 1
	fi
	return 0
}

# journey_process_running NAME: true while process NAME of the open cell runs.
journey_process_running() {
	local index
	journey__require_cell
	journey__process_index index "$_jc_product/${1:-}" || return 1
	journey__process_alive "${_journey_process_pids[$index]}"
}

# journey_process_log NAME VAR: refresh the redacted log of process NAME of
# the open cell and set VAR to its stderr file.
journey_process_log() {
	local _jr_name=${1:-} _jr_target=${2:-} _jpl_index
	journey__check_var "$_jr_target"
	journey__require_cell
	journey__process_index _jpl_index "$_jc_product/$_jr_name" || journey__script_error "no running process $_jr_name for $_jc_product"
	journey__refresh_process_logs "$_jpl_index" || journey_harness_failure "cannot redact the log of $_jr_name"
	printf -v "$_jr_target" '%s' "${_journey_process_bases[$_jpl_index]}.stderr"
}

journey__work_path() {
	[[ "$1" == "$JOURNEY_OUT/work/"* && "$1" != *"/../"* && "$1" != */.. ]] ||
		journey__script_error "a file the reader writes must be under $JOURNEY_OUT/work/, not $1"
	[[ -d "${1%/*}" ]] || journey__script_error "the folder of $1 does not exist"
}

journey__touch_file() {
	journey__in_list "$1" "$_jc_touched" || {
		_jc_touched+="$1"$'\n'
		_jc_files=$((_jc_files + 1))
	}
}

# journey_write_file PATH [--concepts A,B] < CONTENT: a file the reader
# creates by hand. Counts the file, its lines and its characters.
journey_write_file() {
	local path=${1:-} counts
	[[ $# -eq 0 ]] || shift
	journey__require_cell
	journey__require_running
	journey__require_resolved
	journey__work_path "$path"
	if [[ "${1:-}" == --concepts ]]; then
		[[ $# -ge 2 ]] || journey__script_error "--concepts needs a list"
		journey__declare_concepts "$2"
	elif [[ $# -gt 0 ]]; then
		journey__script_error "journey_write_file: unknown option $1"
	fi
	counts="$(perl -e '
		local $/; my $text = <STDIN>; $text = "" unless defined $text;
		open my $out, ">:raw", $ARGV[0] or die "cannot write $ARGV[0]: $!\n";
		print {$out} $text; close $out or die "cannot write $ARGV[0]: $!\n";
		my $lines = () = $text =~ /\n/g; $lines++ if length($text) && $text !~ /\n\z/;
		printf "%d %d\n", $lines, length $text;' "$path")" || journey_harness_failure "cannot write $path"
	journey__touch_file "$path"
	_jc_lines=$((_jc_lines + ${counts% *}))
	_jc_chars=$((_jc_chars + ${counts#* }))
}

# journey_edit_file PATH SEARCH REPLACE [--concepts A,B]: an edit the reader
# makes by hand. SEARCH must occur exactly once. Counts the file, the lines of
# REPLACE and its characters.
journey_edit_file() {
	local path=${1:-} search=${2:-} replace=${3:-} counts
	[[ $# -ge 3 ]] || journey__script_error "journey_edit_file needs PATH SEARCH REPLACE"
	shift 3
	journey__require_cell
	journey__require_running
	journey__require_resolved
	journey__work_path "$path"
	[[ -f "$path" ]] || journey__script_error "cannot edit $path: it does not exist"
	[[ -n "$search" ]] || journey__script_error "journey_edit_file needs the text to replace"
	if [[ "${1:-}" == --concepts ]]; then
		[[ $# -eq 2 ]] || journey__script_error "--concepts needs one list"
		journey__declare_concepts "$2"
	elif [[ $# -gt 0 ]]; then
		journey__script_error "journey_edit_file: unknown option $1"
	fi
	counts="$(perl -e '
		my ($path, $search, $replace) = @ARGV;
		open my $in, "<:raw", $path or die "cannot read $path: $!\n";
		local $/; my $text = <$in>; close $in; $text = "" unless defined $text;
		my $count = () = $text =~ /\Q$search\E/g;
		die "the text to replace occurs $count times in $path; it must occur once\n" if $count != 1;
		substr($text, index($text, $search), length $search) = $replace;
		open my $out, ">:raw", $path or die "cannot write $path: $!\n";
		print {$out} $text; close $out or die "cannot write $path: $!\n";
		my $lines = () = $replace =~ /\n/g; $lines++ if length($replace) && $replace !~ /\n\z/;
		printf "%d %d\n", $lines, length $replace;' "$path" "$search" "$replace")" ||
		journey__script_error "cannot edit $path"
	journey__touch_file "$path"
	_jc_lines=$((_jc_lines + ${counts% *}))
	_jc_chars=$((_jc_chars + ${counts#* }))
}

journey__seconds_for() {
	if [[ "$_jc_last_step" == "$1" ]]; then
		printf -v "$2" '%s' "$_jc_step_seconds"
	else
		printf -v "$2" '%s' 0.000
	fi
}

journey__record_line() {
	printf '%s\t%s\t%s\t%s\t%s\n' "$_jc_product" "$1" "$2" "$3" "$4" >>"$JOURNEY_OUT/cells.tsv" ||
		journey_harness_failure "cannot append to cells.tsv"
}

journey__check_code() {
	local code=$1 kind suffix stage
	if [[ "$code" =~ $_journey_re_code_journey ]]; then
		kind=${BASH_REMATCH[1]}
		suffix=${BASH_REMATCH[2]}
		jq -e --arg kind "$kind" --arg suffix "$suffix" \
			'any((.journeyCodeSuffixes[$kind] // [])[]; . == $suffix)' <<<"$_journey_expected_json" >/dev/null ||
			journey__script_error "code $code: journeyCodeSuffixes.$kind in the table does not list $suffix"
	elif [[ "$code" =~ $_journey_re_code_http ]]; then
		stage=${BASH_REMATCH[1]}
		jq -e --arg stage "$stage" 'any((.authenticationStages // [])[]; . == $stage)' <<<"$_journey_expected_json" >/dev/null ||
			journey__script_error "code $code: $stage is not an authentication stage the table lists"
	elif [[ ! "$code" =~ $_journey_re_code_product ]]; then
		journey__script_error "code '$code' has none of the forms journey.<kind>.<thing>, http.<status>.<stage>, product.<dotted code>"
	fi
}

journey__is_refusal() {
	[[ "$1" == http.* || "$1" == product.* ]]
}

# journey_pass STEP: STEP of the open cell passed.
journey_pass() {
	local step=${1:-} seconds
	journey__require_cell
	journey__check_step "$step"
	journey__require_running
	if [[ "$_jc_pending" == "$step" ]]; then
		journey__script_error "the command of step $step failed; record journey_fail or journey_blocker, not journey_pass"
	fi
	journey__require_resolved
	! journey__in_list "$step" "$_jc_recorded" || journey__script_error "step $step of $_jc_product was already recorded"
	journey__seconds_for "$step" seconds
	journey__record_line "$step" pass - "$seconds"
	_jc_recorded+="$step"$'\n'
}

# journey_fail STEP CODE: the open cell stops at STEP with CODE.
journey_fail() {
	local step=${1:-} code=${2:-} seconds
	journey__require_cell
	journey__check_step "$step"
	journey__require_running
	if [[ -n "$_jc_pending" && "$_jc_pending" != "$step" ]]; then
		journey__require_resolved
	fi
	! journey__in_list "$step" "$_jc_recorded" || journey__script_error "step $step of $_jc_product was already recorded"
	journey__check_code "$code"
	journey__seconds_for "$step" seconds
	journey__record_line "$step" fail "$code" "$seconds"
	_jc_recorded+="$step"$'\n'
	_jc_failed=1
	_jc_fail_step=$step
	_jc_fail_code=$code
	_jc_pending=''
	if journey__is_refusal "$code"; then
		_jc_refusals=$((_jc_refusals + 1))
	fi
}

# journey_needs STEP THING: the only way past STEP is one of the things the
# pass rule forbids; the cell stops with journey.needs.THING.
journey_needs() {
	journey_fail "${1:-}" "journey.needs.${2:-}"
}

# journey_unreached STEP REASON: the cell cannot reach STEP by design.
journey_unreached() {
	local step=${1:-} reason=${2:-}
	journey__require_cell
	journey__check_step "$step"
	journey__require_running
	journey__require_resolved
	[[ -n "$reason" ]] || journey__script_error "journey_unreached needs a reason"
	journey__plain_text reason "$reason"
	journey__record_line "$step" unreached - 0.000
	_jc_unreached=$step
	_jc_reason=$reason
}

# journey_assist_enabled NAME: true when --assist lists NAME.
journey_assist_enabled() {
	[[ ",$JOURNEY_ASSISTS," == *",${1:-},"* ]]
}

# journey_blocker STEP CODE ASSIST [ARGUMENTS]...: STEP meets a blocker CODE.
# With --assist ASSIST, the use is counted, journey_assist_ASSIST runs with
# ARGUMENTS and 0 is returned so the journey continues. Without it the cell
# stops with CODE and 1 is returned. A failing assist is a harness failure.
journey_blocker() {
	local step=${1:-} code=${2:-} assist=${3:-} seconds function
	journey__require_cell
	journey__check_step "$step"
	journey__require_running
	if [[ -n "$_jc_pending" && "$_jc_pending" != "$step" ]]; then
		journey__require_resolved
	fi
	journey__check_id assist "$assist"
	journey__check_code "$code"
	if ! journey_assist_enabled "$assist"; then
		journey_fail "$step" "$code"
		return 1
	fi
	[[ $# -lt 3 ]] || shift 3
	journey__seconds_for "$step" seconds
	journey__record_line "$step" assisted "$code" "$seconds"
	_jc_pending=''
	_jc_assisted_steps+="$step"$'\n'
	_jc_assist_count=$((_jc_assist_count + 1))
	if journey__is_refusal "$code"; then
		_jc_refusals=$((_jc_refusals + 1))
	fi
	if [[ "$assist" == certificate ]]; then
		_jc_certs=$((_jc_certs + 1))
	fi
	_jc_blockers_json="$(jq -c --arg step "$step" --arg code "$code" --arg assist "$assist" \
		'. + [{step: $step, code: $code, assist: $assist}]' <<<"$_jc_blockers_json")" ||
		journey_harness_failure "cannot record the blocker at $step"
	function="journey_assist_${assist//-/_}"
	if ! "$function" "$@"; then
		journey_harness_failure "assist $assist failed at step $step of $_jc_product"
	fi
	return 0
}

# journey_count COUNTER [N]: add N (default 1) to a counted quantity the
# library cannot see: identity-provider-changes, certificates,
# documentation-words, refusals or errors-that-say-what-to-change.
journey_count() {
	local counter=${1:-} amount=${2:-1}
	journey__require_cell
	[[ "$amount" =~ $_journey_re_uint ]] || journey__script_error "journey_count needs a whole number"
	case "$counter" in
	identity-provider-changes) _jc_idp=$((_jc_idp + amount)) ;;
	certificates) _jc_certs=$((_jc_certs + amount)) ;;
	documentation-words) _jc_doc_words=$((_jc_doc_words + amount)) ;;
	refusals) _jc_refusals=$((_jc_refusals + amount)) ;;
	errors-that-say-what-to-change) _jc_named=$((_jc_named + amount)) ;;
	*) journey__script_error "journey_count: unknown counter $counter" ;;
	esac
}

journey__counters_json() {
	local _jr_json
	_jr_json="$(jq -cn \
		--argjson steps "$_jc_steps" --argjson files "$_jc_files" --argjson lines "$_jc_lines" \
		--argjson characters "$_jc_chars" --argjson words "$_jc_doc_words" --argjson idp "$_jc_idp" \
		--argjson certificates "$_jc_certs" --argjson refusals "$_jc_refusals" --argjson named "$_jc_named" \
		--argjson assists "$_jc_assist_count" --argjson seconds "$_jc_seconds" \
		--arg concepts "$_jc_concepts" --arg files_list "$_jc_touched" --argjson model "$_journey_model_json" \
		'($concepts | split("\n") | map(select(length > 0))) as $c |
		 {
		   steps: $steps, filesTouched: $files, files: ($files_list | split("\n") | map(select(length > 0))),
		   linesWritten: $lines, charactersTyped: $characters, documentationWords: $words,
		   identityProviderChanges: $idp, certificatesMade: $certificates, concepts: $c,
		   conceptCount: ($c | length), refusalsMet: $refusals, assistsUsed: $assists,
		   errorsThatSayWhatToChange: $named, machineSeconds: $seconds,
		   readerMinutesModelled: ((
		     $characters / $model.typingCharactersPerMinute
		     + $words / $model.readingWordsPerMinute
		     + $lines * $model.secondsPerHandWrittenLine / 60
		     + ($c | length) * $model.secondsPerConceptFirstMet / 60
		     + $refusals * $model.minutesPerRefusalMet
		     + $assists * $model.minutesPerAssistUsed) * 100 | round / 100)
		 }')" || journey_harness_failure "cannot compute the counters of $_jc_product"
	printf -v "$1" '%s' "$_jr_json"
}

# journey_reached t1|t2: the open cell reached an end point of the pass rule
# (t1: the first 2xx authenticated read; t2: the hour). Snapshots the counters.
journey_reached() {
	journey__require_cell
	journey__require_resolved
	case "${1:-}" in
	t1)
		[[ "$_jc_t1_json" == null ]] || journey__script_error "$_jc_product already reached t1"
		journey__counters_json _jc_t1_json
		;;
	t2)
		[[ "$_jc_t2_json" == null ]] || journey__script_error "$_jc_product already reached t2"
		journey__counters_json _jc_t2_json
		;;
	*) journey__script_error "journey_reached takes t1 or t2" ;;
	esac
}

# journey_cell_end: close the open cell and write <out>/<product>/cell.json.
# A cell that neither failed nor was unreached must have passed the journey's
# last step.
journey_cell_end() {
	local outcome total
	journey__require_cell
	journey__require_resolved
	if [[ $_jc_failed -eq 1 ]]; then
		outcome=fail
	elif [[ -n "$_jc_unreached" ]]; then
		outcome=unreached
	else
		journey__in_list "$_journey_last_step" "$_jc_recorded" || journey__in_list "$_journey_last_step" "$_jc_assisted_steps" ||
			journey__script_error "the cell of $_jc_product ended without a failure and without its last step $_journey_last_step"
		outcome=pass
		if [[ $_jc_assist_count -gt 0 ]]; then
			outcome=assisted
		fi
	fi
	journey__counters_json total
	jq -n \
		--arg product "$_jc_product" --arg outcome "$outcome" \
		--arg step "${_jc_fail_step:-$_jc_unreached}" --arg code "$_jc_fail_code" --arg reason "$_jc_reason" \
		--argjson blockers "$_jc_blockers_json" --argjson t1 "$_jc_t1_json" --argjson t2 "$_jc_t2_json" \
		--argjson total "$total" \
		'def opt: if . == "" then null else . end;
		 {
		   product: $product, outcome: $outcome, step: ($step | opt), code: ($code | opt), reason: ($reason | opt),
		   blockers: $blockers, toT1: $t1, toT2: $t2, total: $total,
		   passRule: {
		     "steps-to-t1": $t1.steps, "files-touched-to-t1": $t1.filesTouched,
		     "lines-written-to-t1": $t1.linesWritten,
		     "identity-provider-changes": $total.identityProviderChanges,
		     "certificates-made": $total.certificatesMade,
		     "concepts-met-to-t1": $t1.conceptCount,
		     "reader-time-to-t1-modelled": $t1.readerMinutesModelled,
		     "reader-time-to-t2-modelled": $t2.readerMinutesModelled,
		     "machine-time-to-t1": (if $t1 == null then null else ($t1.machineSeconds / 60 * 100 | round / 100) end),
		     "errors-that-say-what-to-change": $total.errorsThatSayWhatToChange
		   }
		 }' >"$JOURNEY_OUT/$_jc_product/cell.json" || journey_harness_failure "cannot write the cell of $_jc_product"
	_journey_done_cells+="$_jc_product"$'\n'
	_jc_open=0
}

# ---------------------------------------------------------------------------
# End of a run

journey__verdicts() {
	local cells=$1 _jr_json
	_jr_json="$(jq -n \
		--argjson cells "$cells" --argjson table "$_journey_expected_json" \
		--arg journey "$JOURNEY_NAME" --arg mode "$JOURNEY_MODE" \
		'def rows($kind; $list): [($list // [])[] | select(.journey == $journey) | . + {kind: $kind}];
		 (rows("fail"; $table.expectedFailures) + rows("unreached"; $table.unreached) + rows("pass"; $table.passes)) as $rows |
		 [$cells[] | . as $cell |
		   [$rows[] | select(.product == $cell.product)] as $match |
		   (if ($match | length) == 1 then ($match[0] | {kind, step: (.step // null), code: (.code // null)}) else null end) as $expected |
		   $cell + {expected: $expected, verdict: (
		     if $mode != "ratchet" then (if $cell.outcome == "pass" then "ok" else "not-passed" end)
		     elif ($match | length) > 1 then "listed-twice"
		     elif $expected == null then "unlisted"
		     elif $cell.outcome == "pass" and $expected.kind == "pass" then "ok"
		     elif $cell.outcome == "pass" then "stale"
		     elif $cell.outcome == $expected.kind and $cell.step == $expected.step
		          and ($cell.outcome == "unreached" or $cell.code == $expected.code) then "ok"
		     else "mismatch" end)}]')" || journey_harness_failure "cannot compare the cells with the table"
	printf -v "$2" '%s' "$_jr_json"
}

# journey_finish: compare every cell with the mode's requirement, write
# summary.json, print one line per cell and exit with the journey's status.
journey_finish() {
	local product cells verdicts rows strict='' code=0 missing=''
	local -a files=() line=()
	[[ $_jc_open -eq 0 ]] || journey__script_error "the cell of $_jc_product is still open at journey_finish"
	for product in "${JOURNEY_PRODUCTS[@]}"; do
		journey__in_list "$product" "$_journey_done_cells" || missing+=" $product"
		files+=("$JOURNEY_OUT/$product/cell.json")
	done
	[[ -z "$missing" ]] || journey__script_error "the journey recorded no cell for:$missing"
	cells="$(jq -s '.' "${files[@]}")" || journey_harness_failure "cannot read the cell files"
	journey__verdicts "$cells" verdicts
	jq -n --arg journey "$JOURNEY_NAME" --arg run "$JOURNEY_RUN_ID" --arg mode "$JOURNEY_MODE" \
		--argjson strict "$JOURNEY_STRICT" --arg assists "$JOURNEY_ASSISTS" --argjson cells "$verdicts" \
		'{schema: "registry.journey-summary/v1", journey: $journey, runId: $run, mode: $mode,
		  strict: ($strict == 1), assists: ($assists | split(",") | map(select(length > 0))), cells: $cells}' \
		>"$JOURNEY_OUT/summary.json" || journey_harness_failure "cannot write summary.json"
	rows="$(jq -r '.[] | [.product, .outcome, (.step // "-"), (.code // "-"),
		(if .expected == null then "not in the table"
		 else ([.expected.kind, .expected.step, .expected.code] | map(select(. != null)) | join(" ")) end),
		.verdict] | @tsv' <<<"$verdicts")" || journey_harness_failure "cannot format the verdicts"
	[[ $JOURNEY_STRICT -eq 0 ]] || strict=' (strict)'
	printf '%s, %s mode%s, run %s\n' "$JOURNEY_NAME" "$JOURNEY_MODE" "$strict" "$JOURNEY_RUN_ID"
	printf '%-18s %-10s %-20s %-36s %-48s %s\n' product outcome step code expected verdict
	while IFS=$'\t' read -r -a line; do
		printf '%-18s %-10s %-20s %-36s %-48s %s\n' "${line[0]}" "${line[1]}" "${line[2]}" "${line[3]}" "${line[4]}" "${line[5]}"
	done <<<"$rows"
	if [[ "$JOURNEY_MODE" == ratchet ]]; then
		if jq -e 'any(.[]; .verdict == "mismatch" or .verdict == "unlisted" or .verdict == "listed-twice")' <<<"$verdicts" >/dev/null; then
			code=1
		fi
		if jq -e 'any(.[]; .verdict == "stale")' <<<"$verdicts" >/dev/null; then
			if [[ $JOURNEY_STRICT -eq 1 ]]; then
				code=1
				journey__say "a listed failure no longer fails: delete its row and add the cell to passes"
			else
				journey__say "warning: a listed failure no longer fails (stale row); --strict makes this an error"
			fi
		fi
	elif jq -e 'any(.[]; .verdict != "ok")' <<<"$verdicts" >/dev/null; then
		code=1
	fi
	_journey_finished=1
	exit "$code"
}

# ---------------------------------------------------------------------------
# Cleanup

journey__cleanup_problem() {
	journey__say "cleanup failure: $*"
	_journey_cleanup_failures+="$*"$'\n'
}

journey__stop_processes() {
	local index pid failed=0
	if [[ -n "$_journey_watchdog_pid" ]]; then
		journey__end_watchdog "$_journey_watchdog_pid"
		_journey_watchdog_pid=''
	fi
	if [[ -n "$_journey_foreground_pid" ]]; then
		journey__terminate "$_journey_foreground_pid" "$JOURNEY_KILL_GRACE"
		_journey_foreground_pid=''
	fi
	for ((index = 0; index < ${#_journey_process_pids[@]}; index++)); do
		pid=${_journey_process_pids[$index]}
		[[ -n "$pid" ]] || continue
		journey__terminate "$pid" "$JOURNEY_KILL_GRACE"
		if [[ $_journey_terminate_killed -eq 1 ]]; then
			journey__say "process ${_journey_process_keys[$index]} (pid $pid) ignored SIGTERM and was killed"
		fi
		if journey__refresh_process_logs "$index"; then
			rm -f -- "${_journey_process_raws[$index]}.stdout" "${_journey_process_raws[$index]}.stderr" ||
				{
					journey__cleanup_problem "cannot delete the raw log of ${_journey_process_keys[$index]}"
					failed=1
				}
		else
			journey__cleanup_problem "cannot redact the log of ${_journey_process_keys[$index]}"
			failed=1
		fi
		_journey_process_pids[index]=''
	done
	return "$failed"
}

journey__remove_containers() {
	local name failed=0
	[[ -f "$JOURNEY_OUT/containers.txt" ]] || return 0
	while IFS= read -r name || [[ -n "$name" ]]; do
		[[ -n "$name" ]] || continue
		if [[ "$name" != "$JOURNEY_CONTAINER_PREFIX-"* || ! "$name" =~ $_journey_re_container ]]; then
			journey__cleanup_problem "containers.txt lists $name, which this run did not name; it was not removed"
			failed=1
			continue
		fi
		if [[ $JOURNEY_KEEP -eq 1 ]]; then
			journey__say "kept container $name"
			continue
		fi
		if docker rm --force --volumes "$name" </dev/null >/dev/null; then
			journey__say "removed container $name"
		else
			journey__cleanup_problem "docker rm --force --volumes $name failed; remove it by that name"
			failed=1
		fi
	done <"$JOURNEY_OUT/containers.txt"
	return "$failed"
}

journey__discard_raw() {
	local file failed=0
	for file in ${_journey_raw_files[@]+"${_journey_raw_files[@]}"}; do
		if [[ -e "$file" ]] && ! rm -- "$file"; then
			journey__cleanup_problem "cannot delete $file"
			failed=1
		fi
	done
	if ! rmdir -- "$JOURNEY_OUT/.raw"; then
		journey__cleanup_problem "$JOURNEY_OUT/.raw holds files this run did not create; it was left in place"
		failed=1
	fi
	return "$failed"
}

# Scan every saved file outside secrets/, work/ and .raw/ for a registered
# secret value, a private key block or a compact JWT. Exit 1 lists findings.
_journey_perl_scan='
use strict;
use warnings;
use File::Find;
my ($root) = @ARGV;
open my $list, "<&=", 3 or die "cannot read the secret list: $!\n";
my @pairs;
while (my $line = <$list>) {
    chomp $line;
    my ($label, $value) = split /\t/, $line, 2;
    push @pairs, [$label, $value] if defined $value && length $value;
}
my @findings;
find({ no_chdir => 1, wanted => sub {
    my $path = $File::Find::name;
    return if $path eq $root;
    my $relative = substr $path, length($root) + 1;
    if (-d $path && !-l $path) {
        $File::Find::prune = 1 if $relative =~ m{\A(?:secrets|work|\.raw)\z};
        return;
    }
    return if -l $path || !-f $path;
    open my $fh, "<:raw", $path or do { push @findings, "$relative: unreadable"; return };
    local $/;
    my $text = <$fh>;
    close $fh;
    $text = "" unless defined $text;
    for my $pair (@pairs) {
        push @findings, "$relative: the value of secret $pair->[0]" if index($text, $pair->[1]) >= 0;
    }
    push @findings, "$relative: a private key block" if $text =~ /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
    push @findings, "$relative: a compact JWT" if $text =~ /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;
} }, $root);
print "$_\n" for @findings;
exit(@findings ? 1 : 0);
'

journey__scan_saved_output() {
	local findings status=0 line
	findings="$(perl -e "$_journey_perl_scan" "$JOURNEY_OUT" 3< <(journey__secret_lines))" || status=$?
	case "$status" in
	0) _journey_secret_scan=clean ;;
	1)
		_journey_secret_scan=found
		while IFS= read -r line; do
			journey__say "secret found in saved output: $line"
		done <<<"$findings"
		;;
	*)
		_journey_secret_scan=found
		journey__say "the scan of saved output for secrets could not run (exit status $status); the run is treated as leaking"
		;;
	esac
}

journey__dispose_secrets() {
	local index file failed=0 directory
	if [[ $JOURNEY_KEEP -eq 1 ]]; then
		: >"$JOURNEY_OUT/kept" || {
			journey__cleanup_problem "cannot write $JOURNEY_OUT/kept"
			failed=1
		}
		journey__say "kept the secrets in $JOURNEY_OUT/secrets (mode 0600) for a later run; they are deleted by the run that takes this one over"
		return "$failed"
	fi
	for ((index = 0; index < ${#_journey_secret_files[@]}; index++)); do
		file=${_journey_secret_files[$index]}
		if [[ -e "$file" ]] && ! rm -- "$file"; then
			journey__cleanup_problem "cannot delete secret file $file"
			failed=1
		fi
	done
	for directory in ${_journey_secret_dirs[@]+"${_journey_secret_dirs[@]}"}; do
		if [[ -d "$directory" ]] && ! rmdir -- "$directory"; then
			journey__cleanup_problem "$directory still holds files this run did not create; it was left in place"
			failed=1
		fi
	done
	return "$failed"
}

journey__cleanup() {
	local index failed=0
	for ((index = ${#_journey_cleanup_hooks[@]} - 1; index >= 0; index--)); do
		if ! "${_journey_cleanup_hooks[$index]}"; then
			journey__cleanup_problem "cleanup hook ${_journey_cleanup_hooks[$index]} failed"
			failed=1
		fi
	done
	journey__stop_processes || failed=1
	journey__adopt_pending_container || failed=1
	journey__remove_containers || failed=1
	journey__discard_raw || failed=1
	journey__scan_saved_output
	journey__dispose_secrets || failed=1
	return "$failed"
}

# A signal during cleanup is noted and cleanup carries on, so a second Ctrl-C
# cannot leave containers behind. A handler, not an ignored signal, so the
# watchdogs cleanup starts can still trap TERM.
journey__signal_during_cleanup() {
	journey__say "cleanup is running; the signal waits until it ends"
}

journey__on_exit() {
	local status=$? cleanup_status=0
	trap journey__signal_during_cleanup HUP INT TERM
	trap - EXIT
	set +e
	if [[ $_journey_cleaned -eq 1 ]]; then
		exit "$status"
	fi
	_journey_cleaned=1
	if [[ $_journey_finished -ne 1 ]]; then
		case "$status" in
		2 | 3) ;;
		129 | 130 | 143) journey__say "interrupted (exit status $status); cleaning up" ;;
		*)
			_journey_harness_message="the journey script stopped before journey_finish (exit status $status)"
			journey__say "harness failure: $_journey_harness_message"
			status=3
			;;
		esac
	fi
	journey__cleanup
	cleanup_status=$?
	if [[ "$_journey_secret_scan" == found ]]; then
		status=3
	elif [[ $cleanup_status -ne 0 && ($status -eq 0 || $status -eq 1) ]]; then
		status=3
	fi
	_journey_exit_status=$status
	if ! journey__write_run_json end; then
		journey__say "cleanup failure: cannot write $JOURNEY_OUT/run.json"
		[[ $status -ne 0 ]] || status=3
	fi
	exit "$status"
}
