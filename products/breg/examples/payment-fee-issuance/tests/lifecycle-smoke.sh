#!/usr/bin/env bash
set -euo pipefail

script_dir=$(
	python3 - "${BASH_SOURCE[0]}" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).resolve().parent)
PY
)
readonly script_dir
readonly lifecycle="$script_dir/../lifecycle.sh"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/payment-fee-lifecycle.XXXXXX")
readonly scratch

cleanup() {
	rm -f \
		"$scratch/child.py" \
		"$scratch/waiter.sh" \
		"$scratch/term-child-signal" \
		"$scratch/term-child-ready" \
		"$scratch/term-bystander-signal" \
		"$scratch/term-bystander-ready" \
		"$scratch/int-child-signal" \
		"$scratch/int-child-ready" \
		"$scratch/int-bystander-signal" \
		"$scratch/int-bystander-ready" \
		"$scratch/hup-child-signal" \
		"$scratch/hup-child-ready" \
		"$scratch/hup-bystander-signal" \
		"$scratch/hup-bystander-ready"
	rmdir "$scratch"
}
trap cleanup EXIT

cat >"$scratch/child.py" <<'PY'
#!/usr/bin/env python3
import os
import signal
import sys
import time
from pathlib import Path

signal_file = Path(sys.argv[1])
ready_file = Path(sys.argv[2])

def stop(signum, _frame):
    signal_file.write_text(signal.Signals(signum).name.removeprefix("SIG") + "\n")
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGHUP, signal.SIG_IGN)
ready_file.write_text(f"{os.getpid()}\n")
while True:
    time.sleep(1)
PY
chmod 700 "$scratch/child.py"

cat >"$scratch/waiter.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
readonly lifecycle=$1
readonly child_script=$2
readonly signal_file=$3
readonly child_ready_file=$4
source "$lifecycle"
"$child_script" "$signal_file" "$child_ready_file" &
owned_pid=$!
payment_fee_wait_for_owned_child "$owned_pid"
EOF
chmod 700 "$scratch/waiter.sh"

python3 - "$lifecycle" "$scratch" <<'PY'
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

lifecycle = sys.argv[1]
scratch = Path(sys.argv[2])

def wait_for_file(path):
    deadline = time.time() + 5
    while time.time() < deadline:
        if path.exists() and path.stat().st_size:
            return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {path.name}")

def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)

for name, parent_signal, child_signal_name in (
    ("term", signal.SIGTERM, "TERM"),
    ("int", signal.SIGINT, "INT"),
    ("hup", signal.SIGHUP, "TERM"),
):
    child_signal = scratch / f"{name}-child-signal"
    child_ready = scratch / f"{name}-child-ready"
    bystander_signal = scratch / f"{name}-bystander-signal"
    bystander_ready = scratch / f"{name}-bystander-ready"
    bystander = None
    waiter = None
    try:
        bystander = subprocess.Popen([scratch / "child.py", bystander_signal, bystander_ready])
        wait_for_file(bystander_ready)
        waiter = subprocess.Popen(
            [scratch / "waiter.sh", lifecycle, scratch / "child.py", child_signal, child_ready]
        )
        wait_for_file(child_ready)
        os.kill(waiter.pid, parent_signal)
        if waiter.wait(timeout=5) != 0:
            raise RuntimeError(f"{name} waiter did not exit cleanly")
        if child_signal.read_text().strip() != child_signal_name:
            raise RuntimeError(f"{name} did not deliver {child_signal_name} to the owned child")
        if bystander.poll() is not None or bystander_signal.exists():
            raise RuntimeError(f"{name} reached a bystander process")
    finally:
        stop(waiter)
        stop(bystander)
PY
printf 'lifecycle smoke passed\n'
