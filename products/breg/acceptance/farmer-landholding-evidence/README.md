# Farmer landholding Evidence trial

This synthetic project registers a landholding through one governed Rhai action.
It trims each identifier component in place, joins them with a hyphen, checks
farmer status, and optionally records a separately requested category. The exact
identifier sent to Evidence is the identifier persisted by the action.

Run from the repository root:

```sh
cargo run --locked -p registry-bregctl -- check products/breg/acceptance/farmer-landholding-evidence
for case in status-only with-category inactive blank; do
  cargo run --locked -p registry-bregctl -- project planner-test \
    products/breg/acceptance/farmer-landholding-evidence \
    --action register-landholding \
    --input products/breg/acceptance/farmer-landholding-evidence/examples/$case.input.json \
    --expect products/breg/acceptance/farmer-landholding-evidence/examples/$case.expect.json
done
cargo run --locked -p registry-bregctl -- project planner-test \
  products/breg/acceptance/farmer-landholding-evidence --action check-procedure \
  --input products/breg/acceptance/farmer-landholding-evidence/examples/zero-call.input.json \
  --expect products/breg/acceptance/farmer-landholding-evidence/examples/zero-call.expect.json
```

`evidenceCalls` in an expectation is an ordered list of `capability`, `selectors`
and synthetic `response` maps. Every expected call must occur once in order with
exact selectors. Missing, unexpected or mismatched calls fail; diagnostics report
safe transcript locations without values. An empty list asserts zero helper
calls. The existing `effects` and `refusal` expectations continue to compare the
complete computed outcome. Typed mocks prove authored business logic, not JWS
verification, remote authorization or database atomicity.

The status-only case calls once. The category case calls twice. The inactive
case refuses after status; blank identifiers refuse before any request. The
separately granted `check-procedure` action succeeds with zero calls and creates a separate procedure-check record,
showing that declared capabilities are optional. It cannot create a landholding.

Both status and category are in the registrar's reviewed processing ceiling;
`include-category` selects optional disclosure within that ceiling and grants no
additional authority. There are no CRUD create permissions, other mutation actions
or reviewed-change permissions that can bypass the registration procedure. The reader
can only read. Local unique parcel constraints still apply to every writer.

The imported contract is synthetic and offline. Its fixed revision is a test
value. A real deployment must import its reviewed provider contract and configure
operator endpoint, credentials and approved trust separately. Provider exact
selector resolution is an explicit first-use trust decision. Two assertions are
separate observations; applications requiring a common observation should use a
single appropriately minimized Evidence requirement.

This remains a trial ABI. External calls are optional and bounded, while local
write-target admission, conditions and requirements remain mandatory even for
omitted write slots. Receipt replay performs no calls. Retention and real
Evidence/PostgreSQL integration are host responsibilities and require their
separate executable acceptance checks.

Erase expired protected assertion material using the configured migration role:

```sh
bregctl evidence-retention erase-expired \
  --runtime-config /absolute/operator/runtime.yaml \
  --before 2026-01-01T00:00:00Z
```

The cutoff must be no later than the current time. The command reports a count,
keeps receipt replay intact, and never returns assertion bytes. Runtime database
credentials cannot delete this protected material.

The trial supports Evidence declarations on project-level actions, selected
scalar outputs, request-origin selectors and audience-scoped signed JWS only.
Each declared capability can be invoked once, with at most two capabilities per
action. Defaults allow eight concurrent evaluations, 1 MiB retained material per
action, 256 KiB per response and 24-hour retention. Assertion lifetime is bounded
at 300 seconds with zero clock skew; observation age is declared per capability
(here 60 seconds, ceiling 300 seconds), within one 10-second action deadline.
`bregctl explain actions` shows the effective capabilities and limits offline.

## Real local adopter journey

With `bregctl`, `breg`, `evidence`, OpenSSL, Python with PyYAML, and `psql`
available, point the two environment variables below at a disposable TLS
PostgreSQL service whose administrator may create databases and roles. Run from
the repository root:

```sh
export BREG_TEST_DATABASE_URL='postgresql://operator@localhost:5432/postgres'
export BREG_TEST_TLS_CA_PEM_PATH='/absolute/postgres-ca.pem'
python3 products/breg/acceptance/farmer-landholding-evidence/tests/run-live.py \
  --bregctl "$PWD/target/debug/bregctl" \
  --breg "$PWD/target/debug/breg" \
  --evidence "$PWD/target/debug/evidence"
```

The runner starts the real Evidence binary with a synthetic HTTP source and
imports its published contracts into a temporary project copy. It creates its
own database roles, schema-test database and live database. It drives the native
schema-test receipt, external Ed25519 signing, package publication, apply,
verification and a live BREG HTTP process. The journey checks canonical stored
fields, active/inactive decisions, receipt replay, denied direct create and
expiry maintenance. Its databases and roles are removed on exit; owner-only
reports and fixture secrets stay in the printed temporary directory for review.
No container or domain-specific Rust extension is required.

Callers use `POST /v1/actions/register-landholding` with the ordinary `input`
envelope and `Idempotency-Key`. Current Rust, Node and Python BREG clients do not
provide immediate-action invocation or typed governed-refusal handling. This
trial uses HTTP and adds no SDK convenience method.
