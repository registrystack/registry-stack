#!/usr/bin/env bash

# Wait for a child started by the current shell. TERM and INT received while
# waiting are forwarded only to that child PID. HUP is mapped to TERM because
# the child is launched through nohup and deliberately ignores HUP. No signal
# is sent to its process group or another service on the host.
payment_fee_wait_for_owned_child() {
	local payment_fee_owned_child_pid=$1
	local payment_fee_forwarded_signal=
	local interrupted_status=
	local status

	[[ "$payment_fee_owned_child_pid" =~ ^[1-9][0-9]*$ ]] || {
		printf 'Refusing to wait for an invalid owned child PID\n' >&2
		return 2
	}

	trap 'payment_fee_forwarded_signal=TERM; kill -TERM "$payment_fee_owned_child_pid" 2>/dev/null || true' TERM
	trap 'payment_fee_forwarded_signal=INT; kill -INT "$payment_fee_owned_child_pid" 2>/dev/null || true' INT
	trap 'payment_fee_forwarded_signal=HUP; kill -TERM "$payment_fee_owned_child_pid" 2>/dev/null || true' HUP

	while :; do
		if wait "$payment_fee_owned_child_pid"; then
			status=0
		else
			status=$?
		fi
		if [[ -n "$payment_fee_forwarded_signal" && "$status" -ge 128 ]]; then
			interrupted_status=$status
			payment_fee_forwarded_signal=
			continue
		fi
		if [[ "$status" -eq 127 && -n "$interrupted_status" ]]; then
			status=$interrupted_status
		fi
		break
	done

	trap - HUP TERM INT
	return "$status"
}
