#!/usr/bin/env bash
# A stand-in for the docker CLI in rstack dev tests. Put it first on PATH
# under the name `docker`. It appends each invocation's arguments, one
# invocation per line, to argv.log in its state directory and answers the
# verbs a managed run uses: version, image inspect, pull, run, port, exec,
# cp, ps, rm and volume.
#
# The state directory is $FAKE_DOCKER_STATE, else a fake-docker-state
# directory beside the invoked path. Without either it answers as a Docker
# CLI whose daemon is not running.
#
# Files a test may place in the state directory:
#   port-answer  the exact `docker port` answer (default 127.0.0.1:5432)
#   replace-volume-on-run  simulate Docker creating an unlabelled mount
#   never-ready  pg_isready never succeeds
#
# Files it leaves for a test to read:
#   argv.log            every invocation's arguments
#   containers/<id>     one file per container, holding its label
#   env-file            a copy of the last `run --env-file`
#   pulled              the images `pull` fetched
#   psql.log            the statements `exec ... psql` read on stdin
#   copied/<name>       the files `cp` copied, by target base name
set -euo pipefail

state="${FAKE_DOCKER_STATE:-}"
if [[ -z "$state" && -d "$(dirname "$0")/fake-docker-state" ]]; then
	state="$(dirname "$0")/fake-docker-state"
fi
if [[ -z "$state" ]]; then
	printf 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n' >&2
	exit 1
fi
mkdir -p "$state/containers" "$state/copied" "$state/volumes"
printf '%s\n' "$*" >>"$state/argv.log"

verb="${1:-}"
if [[ $# -gt 0 ]]; then
	shift
fi
case "$verb" in
info)
	if [[ -f "$state/daemon-id" ]]; then
		cat "$state/daemon-id"
	else
		printf 'fixture-daemon
'
	fi
	;;
version)
	printf '27.0.0\n'
	;;
image)
	image="${*: -1}"
	if [[ "${1:-}" == inspect && -f "$state/pulled" ]] && grep -qxF -- "$image" "$state/pulled"; then
		printf 'sha256:0000000000000000000000000000000000000000000000000000000000000000\n'
	else
		printf 'Error response from daemon: No such image: %s\n' "$image" >&2
		exit 1
	fi
	;;
pull)
	printf '%s\n' "${*: -1}" >>"$state/pulled"
	;;
volume)
    case "$1" in
    create)
        volume="${*: -1}"
        if [[ ! -f "$state/volumes/$volume" ]]; then
            printf '%s\n' "$3" "$5" >"$state/volumes/$volume"
        fi
        printf '%s\n' "$volume"
        ;;
    ls)
        filter="${*: -1}"
        for record in "$state/volumes"/*; do
            if [[ -f "$record" && "$(head -n 1 "$record")" == "${filter#label=}" ]]; then
                basename "$record"
            fi
        done
        ;;
    inspect)
        tail -n 1 "$state/volumes/${*: -1}" | cut -d= -f2-
        ;;
    rm)
        rm "$state/volumes/$2"
        ;;
    esac
    ;;
run)
	label=""
	env_file=""
	while [[ $# -gt 1 ]]; do
		case "$1" in
		--label)
			label="$2"
			shift 2
			;;
		--env-file)
			env_file="$2"
			shift 2
			;;
		-v)
			if [[ -f "$state/replace-volume-on-run" ]]; then
				: >"$state/volumes/${2%%:*}"
			fi
			shift 2
			;;
		--name | --publish | --platform)
			shift 2
			;;
		*)
			shift
			;;
		esac
	done
	id="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
	printf '%s\n' "$label" >"$state/containers/$id"
	if [[ -n "$env_file" ]]; then
		cp "$env_file" "$state/env-file"
	fi
	printf '%s\n' "$id"
	;;
port)
	if [[ -f "$state/port-answer" ]]; then
		cat "$state/port-answer"
	else
		printf '127.0.0.1:5432\n'
	fi
	;;
exec)
	while [[ $# -gt 0 && "$1" == -* ]]; do
		case "$1" in
		--user | -u | --env | -e)
			shift 2
			;;
		*)
			shift
			;;
		esac
	done
	if [[ $# -gt 0 ]]; then
		shift
	fi
	case "${1:-}" in
	pg_isready)
		if [[ -f "$state/never-ready" ]]; then
			printf '127.0.0.1:5432 - no response\n'
			exit 2
		fi
		printf '127.0.0.1:5432 - accepting connections\n'
		;;
	psql)
		script="$(cat)"
		printf '%s\n' "$script" >>"$state/psql.log"
		if [[ "$script" == *"SHOW hba_file"* ]]; then
			printf '/var/lib/postgresql/18/docker/pg_hba.conf\n'
		elif [[ "$script" == *"SHOW ssl"* ]]; then
			cat "$state/tls"
		elif [[ "$script" == *"SET ssl = 'off'"* ]]; then
			printf 'off\n' >"$state/tls"
		elif [[ "$script" == *"SET ssl = 'on'"* ]]; then
			printf 'on\n' >"$state/tls"
		fi
		;;
	esac
	;;
cp)
	source="$1"
	target="${2#*:}"
	cp "$source" "$state/copied/$(basename "$target")"
	;;
ps)
	filter=""
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--filter)
			filter="${2#label=}"
			shift 2
			;;
		*)
			shift
			;;
		esac
	done
	if [[ "$filter" == volume=* && -f "$state/volume-holder" ]]; then
		cat "$state/volume-holder"
		exit 0
	fi
	for record in "$state/containers"/*; do
		if [[ -f "$record" && "$(cat "$record")" == "$filter" ]]; then
			basename "$record"
		fi
	done
	;;
rm)
	for argument in "$@"; do
		if [[ "$argument" != -* ]]; then
			rm -f "$state/containers/$argument"
		fi
	done
	;;
*)
	printf 'fake docker: unsupported verb %s\n' "$verb" >&2
	exit 1
	;;
esac
