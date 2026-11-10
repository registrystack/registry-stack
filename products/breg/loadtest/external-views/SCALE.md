# Native external projection scale fixture

Run this acceptance fixture against the same paired candidate binaries as
the [small licensing example](README.md). The native run uses two fresh
loopback PostgreSQL 18 TLS databases, distinct migration and runtime
roles, and a dedicated plan log. The predeclared machine is the shared
M5 Max workstation with local storage. Load and timing on the shared
machine can vary.

| Measure | Predeclared target |
|---|---|
| Licence population | 1,000,000 authorized roots and 100,000 outside the runtime profile's row boundary |
| Holder reuse | 50,000 source keys, 20 roots per key, including 2,500 authorized absent keys |
| Related records | 120 rows for each of two allowed parents and two denied parents |
| Candidate HTTP | Each measured indexed read, including refusal, finishes within 5 seconds |
| Freshness and retention | Complete the sweep and the measured reads within 600 seconds from the first refresh. Retention ceiling is 900 seconds |
| Person source requests | At most 1,100 batch reads and no exact reads during the sweep |
| Holdings source requests | Six reads for the two allowed parents, no request to a denied parent |
| Indexed query source requests | Zero, including reads with missing coverage |

The freshness target covers reads made after the refresh sweep completes. The
exercise does not measure reads while refresh is still running continuously.

The reviewed Adapter pack permits at most 64 Person keys per request and
128 rows per complete related snapshot. The fixture orders the first
50,000 local roots so that their keys are distinct. At 100 local roots per
refresh page, the first 500 pages should each make two Adapter requests.
Later pages should reuse published keys from this sweep. The 1,100-call
ceiling allows headroom above the 1,000 calls this layout predicts. The
native service must traverse 10,000 HTTP refresh pages. Each authorized
holding snapshot uses three source pages of 40 rows. The scale holdings
are company shareholders. The small native fixture covers reuse of a
Person label.

Set the serving runtime role's PostgreSQL defaults to `work_mem = '64MB'`
and `statement_timeout = '10s'`. For the dedicated serving database,
configure the runtime role to load `auto_explain` at session start and
set `auto_explain.log_min_duration = '50ms'`,
`auto_explain.log_analyze = on`, `auto_explain.log_buffers = on`, and
`auto_explain.log_format = 'text'`. Route PostgreSQL logs to an existing
readable file with the prefix `[breg-plan] %d %u ` and keep it from rotating
during the run. Limit this configuration to the disposable fixture. The
runner extracts only appended plans from the named database and runtime
role after refresh. The plans must contain the candidate's actual
coverage and page nodes with buffers.

```sh
python3 -B products/breg/loadtest/external-views/run_candidate.py \
  --breg-bin "$BREG_BIN" \
  --bregctl-bin "$BREGCTL_BIN" \
  --database-url-dir "$FIXTURE_DATABASE_URL_DIR" \
  --postgres-ca-file "$BREG_TEST_TLS_CA_PEM_PATH" \
  --work-dir "$FIXTURE_NEW_WORK_DIR" \
  --scale \
  --postgres-plan-log "$FIXTURE_POSTGRES_PLAN_LOG"
```

The launcher copies the authored fixture to its private work directory and
sets the two indexed cache lifetimes to 600 seconds. It rehearses and
activates that project using the candidate binaries. After activation, the
migration role uses PostgreSQL `generate_series` to bulk load only the
fixture's two empty owned Record tables under the fixture editor's row
policy. Table and field names come from the checked package inventory. This
setup does not measure Record ingestion or create Record history. Every
external snapshot is acquired through the candidate refresh endpoint and
the reviewed Adapter pack.

The runner compares three first-page repetitions and every page of the
selected surname to an independently computed set of root IDs. It compares
both sort directions and their first continuations, authorized missing
values and their count, the unfiltered population count, and all related
rows plus filtered pages for both permitted parents. It inserts a new
authorized root through the ordinary HTTP route after the sweep and expects
a coverage refusal even though the requested surname would exclude that
root. It checks the two denied collection roots and compares source counters
before and after all indexed requests.

Read `scale-report.json` for candidate binary SHA-256 values, the pack and
package inventory digests, PostgreSQL settings, refresh metrics, source
request counts and query wall times. The report includes partial measurements
on failure after the scale run begins. `scale-native-plans.log` contains the
matching native plans. Record the candidate repository revision and the
command beside these files.

Test the deterministic corpus, source bounds and oracle without starting a
candidate or PostgreSQL:

```sh
python3 -B products/breg/loadtest/external-views/test_scale.py
```
