# Registry Scheduling acceptance demo

`run.sh` proves four acceptance scenarios from the Scheduling functional
specification against the real binaries and a real PostgreSQL database, over
the public HTTP contract and under real authentication:

| Scenario | What the demo asserts |
| --- | --- |
| AT-01 | Two callers confirm against the last station concurrently. Exactly one appointment is created; the loser receives `capacity.exhausted` (409), and the slot afterwards holds no free unit. |
| AT-05 | A hold expires. The slot becomes bookable again, and confirming the expired hold fails with `hold.expired` (410). |
| AT-06 | A confirmation commits but its response is lost. A retry under the same `idempotency-key` returns the original appointment; a changed payload under that key is refused with `idempotency.key-reused` (409). |
| AT-19 | The New York hall opening across the 2026-11-01 daylight-saving fold serves the grid the morning closure moved (anchored 04:45Z), never the wall-clock match 06:30Z, which is refused with `schedule.unpublished` (422). |

## Running it

```sh
products/scheduling/demo/run.sh
```

Docker, cargo, openssl, python3, curl, and jq must be available. The script
builds `scheduling` and `schedulingctl`, starts a disposable PostgreSQL 17
container it removes afterwards, publishes the `standalone-exact-time`
example policy with demo environment records (one station per pool, plus the
fold-day closure), serves the runtime on loopback, and runs the scenarios.
The demo shortens the hold TTL to one minute so the expiry scenario runs
quickly; the other scenarios run while that clock does.

`--database-url URL` runs against a disposable PostgreSQL you own instead of
a Docker container (migrations are applied and the data is replaced).
`--installed` uses the two binaries from `PATH` rather than building them.

## How authentication works here

There is no auth-free mode. The script generates a throwaway RSA key pair,
publishes the public half as the static JWKS document the runtime
configuration points at, and signs RFC 9068 access tokens (`typ: at+jwt`)
for three demo callers. Reads carry the `scheduling-read` scope; bookings
carry no product scope but a complete task grant whose `scheduling`
permissions name the offering's service, location, and action, which the
runtime re-checks inside the capacity transaction. Nothing in the run
directory is a credential beyond the throwaway key pair, and the key pair
never leaves the run directory.

## What this demo does not cover

The AT-05 row says "while the cleanup worker is stopped". The runtime's
cleanup loop is a fixed internal interval with no operator switch, and the
store counts a hold only while it is unexpired at the observed now, so a
stopped or delayed worker cannot keep capacity locked either way. The demo
asserts the observable contract the scenario pins (capacity reopens, late
confirmation fails) immediately at expiry, and the worker-independent
enforcement is covered directly by the store's own PostgreSQL tests in
`crates/registry-scheduling/tests/postgres_commitments.rs`.

The support module carries unit tests for its pure pieces:

```sh
python3 -m unittest products/scheduling/demo/support/test_demo.py -v
```
