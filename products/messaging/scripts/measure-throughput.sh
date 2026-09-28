#!/usr/bin/env bash
# Measure SMS dispatch throughput of one runtime replica against a mock HTTP
# provider that answers after a fixed latency. It starts `messagingctl dev`
# from a release build on a starter whose SMS provider is the example mock
# provider, raises the sender's request rate so admission is not the limit,
# submits MESSAGING_THROUGHPUT_COUNT SMS (default 600) from
# MESSAGING_THROUGHPUT_SUBMITTERS concurrent callers (default 32), and samples
# the provider-accepted attempt counter on the metrics listener. It reports
# the submission rate, the dispatch rate over the whole run, and the steady
# dispatch rate between 10 and 90 percent of the messages. Needs Docker,
# curl, and python3. It asserts nothing about the number; it measures it.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

dev_name=measure-throughput
count=${MESSAGING_THROUGHPUT_COUNT:-600}
submitters=${MESSAGING_THROUGHPUT_SUBMITTERS:-32}
latency_ms=${MESSAGING_THROUGHPUT_LATENCY_MS:-200}
# shellcheck source=products/messaging/scripts/dev-session.sh
. "$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/dev-session.sh"

dev_prepare --release
python3 - "$dev_project/messaging.yaml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
limits = "requestsPerMinute: 60\n    burst: 10\n"
if limits not in text:
    sys.exit("measure-throughput: the starter's access limits changed; update this script")
path.write_text(text.replace(limits, "requestsPerMinute: 600000\n    burst: 10000\n", 1))
PY
dev_start --mock-latency-ms "$latency_ms"
dev_log "session ready with a ${latency_ms} ms mock provider"

header=$("$messagingctl_bin" dev token case-system "$dev_project" --format json | dev_member headerFile)

case "$(uname -s)" in
Darwin) machine="$(sysctl -n machdep.cpu.brand_string), $(sysctl -n hw.ncpu) logical CPUs" ;;
*) machine="$(uname -m), $(getconf _NPROCESSORS_ONLN) logical CPUs" ;;
esac
dev_log "machine: $(uname -s) $machine"

python3 - "$dev_api" "$dev_metrics" "$header" "$count" "$submitters" <<'PY'
import concurrent.futures
import json
import threading
import time
import urllib.error
import urllib.request
import uuid
import sys

api, metrics, header_file, count, submitters = sys.argv[1:6]
count, submitters = int(count), int(submitters)
with open(header_file) as handle:
    name, _, value = handle.read().strip().partition(": ")
authorization = {name: value}
run = uuid.uuid4().hex
series = "messaging_provider_attempts_total{outcome=\"accepted\"}"


def accepted():
    with urllib.request.urlopen(metrics, timeout=5) as response:
        for line in response.read().decode().splitlines():
            if line.startswith(series + " "):
                return int(float(line.split()[-1]))
    raise SystemExit("measure-throughput: the metrics listener has no accepted attempt series")


def submit(index):
    body = {
        "senderProfile": "reminders-sms",
        "to": {"phone": "+1555555%04d" % (index % 10000)},
        "template": {"id": "appointment-reminder-sms", "version": "1"},
        "locale": "en",
        "data": {"name": "Ada", "day": "2026-10-01", "office": "North"},
    }
    request = urllib.request.Request(
        api + "/v1/messages",
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            **authorization,
            "content-type": "application/json",
            "Idempotency-Key": "throughput-%s-%d" % (run, index),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as refused:
        return refused.code


baseline = accepted()
samples = []
done = threading.Event()


failures = []


def sample():
    try:
        while not done.is_set():
            samples.append((time.monotonic(), accepted() - baseline))
            if samples[-1][1] >= count:
                done.set()
            time.sleep(0.05)
    except BaseException as failure:
        failures.append(failure)
        done.set()


started = time.monotonic()
sampler = threading.Thread(target=sample, daemon=True)
sampler.start()
with concurrent.futures.ThreadPoolExecutor(submitters) as pool:
    statuses = list(pool.map(submit, range(count)))
submitted = time.monotonic()
refused = [status for status in statuses if not 200 <= status < 300]
if refused:
    done.set()
    raise SystemExit("measure-throughput: %d submissions were refused, statuses %s"
                     % (len(refused), sorted(set(refused))))
if not done.wait(600):
    raise SystemExit("measure-throughput: %d of %d were accepted by the provider in 600 s"
                     % (samples[-1][1], count))
sampler.join()
if failures:
    raise SystemExit("measure-throughput: sampling the metrics listener failed: %r" % failures[0])
finished = next(moment for moment, value in samples if value >= count)


def reached(fraction):
    return next(moment for moment, value in samples if value >= count * fraction)


low, high = reached(0.1), reached(0.9)
steady = (0.8 * count) / (high - low)
print("measure-throughput: submitted %d SMS in %.2f s (%.1f per second, %d submitters)"
      % (count, submitted - started, count / (submitted - started), submitters))
print("measure-throughput: the provider accepted all %d in %.2f s from the first submission (%.1f per second)"
      % (count, finished - started, count / (finished - started)))
print("measure-throughput: steady dispatch between 10 and 90 percent: %.1f SMS per second"
      % steady)
PY

dev_stop
dev_log "session stopped and removed its containers"
