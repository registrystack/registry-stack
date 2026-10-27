# Payment simulator

A small Python service for developing programmes and workflows against
GovStack-aligned payment interfaces. Its five G2P APIs register, update and look
up beneficiary mappings, submit a payment batch, and read its instruction
results. Two P2G APIs request a citizen payment and read collection status.
**It uses synthetic data and never moves money.**

FastAPI and Pydantic own the HTTP shapes. SQLite keeps accepted commands,
destination snapshots, replay responses and simulated credits across restarts.
Amounts use exact minor units. Everything stays in this directory, with no
Registry Stack runtime imports or Rust build.

For programme workflows, the Coordinator's maintained
[beneficiary management](../../products/coordinator/examples/payment-beneficiary-management/README.md),
[G2P disbursement](../../products/coordinator/examples/payment-disbursement/README.md), and
[P2G collection](../../products/coordinator/examples/payment-collection/README.md) projects bind
these seven APIs through generic configured HTTP operations. Payment meanings remain in YAML/Rhai.
A compatible service can replace this simulator for new work after existing commands have settled.

## Start locally

Install [uv](https://docs.astral.sh/uv/) and use Python 3.11–3.14. From this
directory, install the locked dependencies and create a private local token:

```sh
uv sync --locked
uv run python - <<'PY'
import os, secrets
from pathlib import Path
os.umask(0o077)
Path(".state").mkdir(exist_ok=True)
with Path(".state/token").open("x") as token:
    token.write(secrets.token_urlsafe(32) + "\n")
PY
uv run payment-simulator serve \
  --database .state/payments.sqlite --token-file .state/token
```

Create the token once. On later starts, reuse it and the same database. The
server binds to `127.0.0.1:8008`, advances instructions automatically, and
serves its OpenAPI at `/openapi.json` and interactive documentation at `/docs`.
The token is read on every request, so replacing its contents rotates the
credential while preserving the producer identity and replay records.
An existing version 1 database is upgraded to version 2 in one additive
transaction when the server starts, preserving its G2P records and credits.

In another terminal in this directory:

```sh
uv run python examples/quickstart.py --token-file .state/token
uv run payment-simulator inspect --database .state/payments.sqlite
```

The example exercises all five APIs, updates one destination, submits two
instructions totaling 250 USD, replays the same submission, and polls until
both report `ACCC`. It prints `outcome: completed` and `sameBatchOnReplay: true`.
The local ledger shows two simulated credits. Stop the server with Ctrl-C,
restart it with the same command, and rerun the example. It recovers the same
batch and adds no credits.

Use `--run-id other` only for a deliberately new batch (at most six lowercase
letters/digits). An uncertain submission must retain its original IDs.

## Control outcomes

Local CLI controls affect future acceptance. They are not public HTTP APIs.
All controls need the same database path as the server.

```sh
uv run payment-simulator scenario --database .state/payments.sqlite \
  --name partial --reject-request pay2-part
uv run python examples/quickstart.py --token-file .state/token \
  --run-id part --expect partial
uv run payment-simulator scenario --database .state/payments.sqlite --name success
```

The partial fixture rejects the named instruction with `account-rejected`;
other valid instructions succeed. A missing mapping always finishes as
`RJCT` with `mapping-not-found`, even if the mapping is added after acceptance.
Updating a mapping affects future batches, not accepted destinations.

For deterministic steps, start `serve` with `--manual`. Each command below
moves existing instructions once: `PDNG` to `ACSP`, then `ACCC` or `RJCT`.
Use `--steps 2` to finish both transitions.

```sh
uv run payment-simulator advance --database .state/payments.sqlite
```

The lost-response scenario lives in the test fixture: a relay observes a
committed `202`, disconnects before the client receives it, then restarts the
service and retries the unchanged command. There is no HTTP fault switch.

## Collect a citizen payment

With the same server running in automatic mode:

```sh
uv run python examples/collect_payment.py --token-file .state/token
uv run payment-simulator inspect-collections --database .state/payments.sqlite
```

This requests a synthetic 25.50 USD fee, replays the command, and polls until
`paymentStatus` is `PAID` with a stable `PaymentReferenceID`. Rerunning the same
example after restart recovers the same request and payment reference.

The new public operations are `POST /rtpRequest` and
`GET /transferRequests/{transferRequestId}`. P2G preserves its upstream
`X-Platform-TenantId` and `X-billerId` headers. See [the P2G profile](P2G-SPEC.md)
for the exact shapes, scope and reviewed differences from GovStack.

**An RTP status of `COM` does not mean paid.** The mock deliberately passes
through `COM/PENDING` before `COM/PAID`. Consumers must validate the payment
status, original IDs, amount, currency and confirmed payment reference.

Choose other outcomes for future requests:

```sh
uv run payment-simulator collection-scenario --database .state/payments.sqlite --outcome failed
uv run python examples/collect_payment.py --token-file .state/token --run-id reject --expect failed
uv run payment-simulator collection-scenario --database .state/payments.sqlite --outcome expired
uv run python examples/collect_payment.py --token-file .state/token --run-id expire --expect expired
uv run payment-simulator collection-scenario --database .state/payments.sqlite --outcome paid
```

Each run ID here represents a different synthetic bill. The profile allows one
request per bill, including failed and expired requests; it has no reissue or
refund policy. Keep the original run ID when recovering an uncertain payment.
Expiry is a fixture outcome, not a configured real-time deadline. In manual
mode, the existing `advance` command advances both G2P and P2G in two steps.

## Configuration and boundaries

The local credential belongs to one producer per server. The defaults are:

| Scope | Default | `serve` override |
|---|---|---|
| Producer / source | `registry` / `registry` | `--producer` / `--source-id` |
| Tenant | `pilot` | `--tenant` |
| Institution | `ministry` | `--institution` |
| Programme | `cash-support` | `--program` |
| Payer account | `programme-account` | `--payer-account` |
| P2G biller | `ministry` | `--biller` |
| Currency and decimal scale | `USD:2` | `--currency` |
| Submission mode | `00` | `--mode` (`00`, `01`, `03`) |
| Accepted callback URLs | `https://programme.example.test/callback`, `https://programme.example.test/api/v1/batch` | `--callback-url` |

Repeat an override to allow several values, except producer/source. Supplying
an override replaces its default set. Currency scales range from 0 to 6.
Headers select permitted scope; they do not grant it. Token files must have
private permissions (`chmod 600`) and contain one ASCII bearer token of at
least 16 characters. Keep token and SQLite files in ignored `.state/`.

Callbacks are accepted as configured wire fields but **are not delivered**.
Use polling. Receipts are retained for the lifetime of this disposable
database. There is no receipt expiry, reset API, real rail, production identity
provider, high availability, container publishing or CI integration. An
unsupported database version is refused; only the additive v1-to-v2 upgrade is
provided. Programme funding and real citizen checkout are outside this mock.
Do not use real beneficiary data or expose this development server as a
payment service.

## Verify and reuse the contract tests

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run payment-simulator openapi --check
uv run pytest -q
```

Regenerate the checked-in schema with `uv run payment-simulator openapi`.
The live HTTP suite is `tests/contract/`. It starts isolated local processes,
uses ordinary HTTP for public assertions, and keeps scenario control, restart
and ledger inspection in `tests/fixtures/`. `tests/test_service.py` and
`tests/test_p2g_service.py` contain implementation-specific checks. No real
provider is contacted by default.

To run the portable subset against an existing synthetic sandbox:

```sh
uv run pytest tests/contract/test_g2p_profile.py -q \
  --target-url https://payments.sandbox.example.test \
  --token-file /path/to/private-sandbox-token --external-sandbox \
  --target-capability success
```

Use `uv run pytest --help` for target scope, currency and polling options.
Select `tests/contract/test_p2g_profile.py` and `--target-capability collection-paid`
instead to check the collection profile; `--target-biller` defaults to `ministry`.
The external server need only expose the selected profile's APIs, not `/healthz`.
Unavailable partial-outcome, held-processing, restart and ledger controls are
reported as **NOT VERIFIED** skips. A provider fixture driver must supply
those controls before claiming their evidence; declaring a capability alone
does not implement it. The suite creates synthetic records with unique IDs
and does not delete remote data.

The [Coordinator payment examples](../../products/coordinator/README.md#configured-http-operations)
use generic HTTP operations and authored payment contracts. The replacement boundary is this HTTP profile, implemented directly
by a provider or an adapter. Matching wire shapes alone does not establish
equivalent retry guarantees or prove recipient credit.

| Document | Purpose |
|---|---|
| [Definition of done](DEFINITION-OF-DONE.md) | Required scope and explicit exclusions |
| [Specification](SPEC.md) | Five APIs and differences from the pinned GovStack sources |
| [P2G collection profile](P2G-SPEC.md) | Request to pay, payment evidence and collection scenarios |
| [API traces](SCENARIOS.md) | Three illustrative request/response journeys |
| [Contract tests](CONTRACT-TESTS.md) | Executed coverage versus future test catalogue |
| [Implementation plan](IMPLEMENTATION-PLAN.md) | Implementation structure and follow-ups |
| [Generated OpenAPI](contracts/openapi.json) | Implemented wire schemas |

These are **Payment Simulator G2P Profile 0.1** and **P2G Collection Profile 0.1**,
not full GovStack conformance or a claim that a real provider has moved money.
