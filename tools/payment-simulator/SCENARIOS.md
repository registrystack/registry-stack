# G2P API traces

**Status: illustrative acceptance traces.** These three
scenarios use [Profile 0.1](SPEC.md). All IDs, destinations, and amounts below
are synthetic. Provider-generated batch and transaction IDs are illustrative;
tests capture returned IDs instead of requiring these literal values.

## Common fixture

Each scenario runs in an independent tenant owned by the test runner:
`trace-success`, `trace-partial`, or `trace-replay`. The authenticated producer
is `registry`, its source ID is `registry`, the institution is `ministry`, and
the programme is `cash-support`. The producer can use payer account
`programme-account`. Do not run these traces against a payment environment
that can move real funds.

The fixture approves the two callback URL values before any request.
Examples use `https://programme.example.test/callback` and
`https://programme.example.test/api/v1/batch`; a test target supplies its actual
approved receiver. `<token>` and `<tenant>` below are fixture substitutions.
Only these connection and fixture values vary across targets.
The initial simulator accepts these values but does not deliver callbacks.

Register two beneficiaries through the public API:

```http
POST /identityAccountMapper/beneficiary
Authorization: Bearer <token>
Content-Type: application/json
Platform-TenantId: <tenant>
X-Registering-Institution-ID: ministry
X-Callback-URL: https://programme.example.test/callback
```

```json
{
  "RequestID": "reg-001",
  "Beneficiaries": [
    {
      "payeeIdentity": "beneficiary-001",
      "PaymentModality": "00",
      "FinancialAddress": "acct-001",
      "bankingInstitutionCode": "TESTBANK"
    },
    {
      "payeeIdentity": "beneficiary-002",
      "PaymentModality": "00",
      "FinancialAddress": "acct-002",
      "bankingInstitutionCode": "TESTBANK"
    }
  ]
}
```

Expect `200` and:

```json
{"responseCode":"00","responseDescription":"Applied","requestID":"reg-001"}
```

Exercise update before payment. Only the selected mapping changes:

```http
PUT /identityAccountMapper/beneficiary
Authorization: Bearer <token>
Content-Type: application/json
Platform-TenantId: <tenant>
X-Registering-Institution-ID: ministry
```

```json
{
  "requestID": "update-001",
  "sourceBBID": "registry",
  "beneficiaries": [
    {
      "payeeIdentity": "beneficiary-002",
      "paymentModality": "00",
      "financialAddress": "acct-002b"
    }
  ]
}
```

Expect `200` and:

```json
{"responseCode":"00","responseDescription":"Applied","requestID":"update-001"}
```

Confirm the current mapping:

```http
GET /beneficiary/?payeeIdentity=beneficiary-002&requestId=lookup-001
Authorization: Bearer <token>
Platform-TenantId: <tenant>
registeringInstitutionId: ministry
```

Expect `200` and:

```json
{
  "requestId": "lookup-001",
  "paymentModalityList": [
    {
      "payeeIdentity": "beneficiary-002",
      "paymentModality": "00",
      "financialAddress": "acct-002b",
      "bankingInstitutionCode": "TESTBANK"
    }
  ]
}
```

All three scenarios submit this same two-instruction body in their isolated
tenants. The amount is 250.00 USD in total:

```json
[
  {
    "requestId": "payment-001",
    "creditParty": [{"key":"payeeIdentity","value":"beneficiary-001"}],
    "debitParty": [{"key":"accountId","value":"programme-account"}],
    "paymentMode": "00",
    "amount": 100.00,
    "currency": "USD"
  },
  {
    "requestId": "payment-002",
    "creditParty": [{"key":"payeeIdentity","value":"beneficiary-002"}],
    "debitParty": [{"key":"accountId","value":"programme-account"}],
    "paymentMode": "00",
    "amount": 150.00,
    "currency": "USD"
  }
]
```

Scenario selection and release of held transitions happen through the target's
fixture driver, outside these HTTP messages. The simulator supports a manual
clock so tests do not depend on arbitrary sleeps. A real target may already be
terminal at the first poll; portable tests require the outcome, not that every
intermediate state was observable.

## Scenario 1: all instructions succeed

Fixture: `trace-success`; both destinations accept a simulated credit.

```http
POST /batchtransactions?type=raw
Authorization: Bearer <token>
Content-Type: application/json
Platform-TenantId: trace-success
X-CorrelationID: batch-001
X-Program-Id: cash-support
X-Registering-Institution-Id: ministry
X-Callback-URL: https://programme.example.test/api/v1/batch
```

Send the common instruction body. Expect `202` and:

```json
{"batchId":"batch-0001"}
```

The caller saves the returned ID alongside the original command. Poll:

```http
GET /api/v1/batch/detail?batchId=batch-0001&pageNo=0&pageSize=10
Authorization: Bearer <token>
Platform-TenantId: trace-success
```

With processing held by the fixture, expect `200` and:

```json
[
  {
    "requestId": "payment-001",
    "transactionId": "tx-0001",
    "batchId": "batch-0001",
    "amount": 100.00,
    "currency": "USD",
    "status": "PDNG",
    "startedAt": "2026-10-16T10:00:00Z",
    "direction": "OUTGOING",
    "payeePartyId": "acct-001",
    "payeePartyIdType": "FINANCIAL_ADDRESS",
    "payeeDfspId": "TESTBANK"
  },
  {
    "requestId": "payment-002",
    "transactionId": "tx-0002",
    "batchId": "batch-0001",
    "amount": 150.00,
    "currency": "USD",
    "status": "PDNG",
    "startedAt": "2026-10-16T10:00:00Z",
    "direction": "OUTGOING",
    "payeePartyId": "acct-002b",
    "payeePartyIdType": "FINANCIAL_ADDRESS",
    "payeeDfspId": "TESTBANK"
  }
]
```

Release both instructions and repeat the same GET. Expect the same rows and
identities with `status: "ACCC"` and `completedAt` set. Example final response:

```json
[
  {
    "requestId": "payment-001",
    "transactionId": "tx-0001",
    "batchId": "batch-0001",
    "amount": 100.00,
    "currency": "USD",
    "status": "ACCC",
    "startedAt": "2026-10-16T10:00:00Z",
    "completedAt": "2026-10-16T10:00:02Z",
    "direction": "OUTGOING",
    "payeePartyId": "acct-001",
    "payeePartyIdType": "FINANCIAL_ADDRESS",
    "payeeDfspId": "TESTBANK"
  },
  {
    "requestId": "payment-002",
    "transactionId": "tx-0002",
    "batchId": "batch-0001",
    "amount": 150.00,
    "currency": "USD",
    "status": "ACCC",
    "startedAt": "2026-10-16T10:00:00Z",
    "completedAt": "2026-10-16T10:00:02Z",
    "direction": "OUTGOING",
    "payeePartyId": "acct-002b",
    "payeePartyIdType": "FINANCIAL_ADDRESS",
    "payeeDfspId": "TESTBANK"
  }
]
```

The caller derives `completed`: 2 credited, 0 rejected, 250.00 USD credited.
The optional callback in [the specification](SPEC.md#optional-batch-notifications)
may prompt another eligible poll, but is not needed to reach this outcome.

## Scenario 2: one instruction is rejected

Fixture: `trace-partial`; `payment-001` succeeds and `payment-002` is rejected
with `account-rejected`. This rule is installed out of band, not encoded in
the beneficiary ID or payment request.

```http
POST /batchtransactions?type=raw
Authorization: Bearer <token>
Content-Type: application/json
Platform-TenantId: trace-partial
X-CorrelationID: batch-002
X-Program-Id: cash-support
X-Registering-Institution-Id: ministry
X-Callback-URL: https://programme.example.test/api/v1/batch
```

Send the common body. Expect `202` and:

```json
{"batchId":"batch-0002"}
```

After releasing the transitions, poll:

```http
GET /api/v1/batch/detail?batchId=batch-0002&pageNo=0&pageSize=10
Authorization: Bearer <token>
Platform-TenantId: trace-partial
```

Expect `200` and:

```json
[
  {
    "requestId": "payment-001",
    "transactionId": "tx-0003",
    "batchId": "batch-0002",
    "amount": 100.00,
    "currency": "USD",
    "status": "ACCC",
    "startedAt": "2026-10-16T10:05:00Z",
    "completedAt": "2026-10-16T10:05:02Z",
    "direction": "OUTGOING",
    "payeePartyId": "acct-001",
    "payeePartyIdType": "FINANCIAL_ADDRESS",
    "payeeDfspId": "TESTBANK"
  },
  {
    "requestId": "payment-002",
    "transactionId": "tx-0004",
    "batchId": "batch-0002",
    "amount": 150.00,
    "currency": "USD",
    "status": "RJCT",
    "errorInformation": "account-rejected",
    "startedAt": "2026-10-16T10:05:00Z",
    "completedAt": "2026-10-16T10:05:02Z",
    "direction": "OUTGOING",
    "payeePartyId": "acct-002b",
    "payeePartyIdType": "FINANCIAL_ADDRESS",
    "payeeDfspId": "TESTBANK"
  }
]
```

The caller derives `partial`: 100.00 USD credited and 150.00 USD rejected.
Both instruction outcomes remain visible. It does not resend the whole batch.
A follow-up payment after a deliberate business decision would have its own
new instruction and command IDs.

## Scenario 3: acceptance succeeds but the response is lost

Fixture: `trace-replay`; both instructions succeed. Put an HTTP relay between
the caller and target. The relay forwards one complete submission, receives
the target's `202`, retains that response as test evidence, then closes the
client-facing connection without delivering any of the response to the caller.
This proves the fault occurred after acceptance. A request dropped before
reaching the target is a different test.

```http
POST /batchtransactions?type=raw
Authorization: Bearer <token>
Content-Type: application/json
Platform-TenantId: trace-replay
X-CorrelationID: batch-003
X-Program-Id: cash-support
X-Registering-Institution-Id: ministry
X-Callback-URL: https://programme.example.test/api/v1/batch
```

Send the common body. The target commits and returns this to the relay only:

```json
{"batchId":"batch-0003"}
```

The caller sees a transport failure and records an unknown outcome. It keeps
the original body, correlation ID, and other effect-bearing headers. It does
not obtain the relay's hidden receipt through its recovery logic.

Restart the simulator using the same database, then replay the original POST
with the same body and headers. Fresh credentials for the same producer are
allowed. A real target's controlled restart is a separate fixture capability;
do not claim restart durability if only the relay fault was exercised.

Expect `202` and the same `batchId` held by the relay:

```json
{"batchId":"batch-0003"}
```

The caller can now poll normally:

```http
GET /api/v1/batch/detail?batchId=batch-0003&pageNo=0&pageSize=10
Authorization: Bearer <token>
Platform-TenantId: trace-replay
```

The final `200` has the same shape as scenario 1: exactly `payment-001` and
`payment-002`, their original amounts and destination snapshots, one stable
transaction ID each, and `ACCC` for both. The caller derives `completed`.
The target must have accepted one batch and credited each instruction at
most once. HTTP results prove identity recovery; a controlled ledger witness
is required to prove that no hidden duplicate credit occurred.

Finally, repeat the command with the same `batch-003` correlation ID but
change the first amount from `100.00` to `101.00`. Expect `409`:

```json
{
  "type": "about:blank",
  "title": "Command identity already used",
  "status": 409,
  "code": "request.id-reused"
}
```

Polling still returns the original 100.00 and 150.00 instructions and the
original transaction IDs. No second batch or credit is created.

## Checks that accompany the three scenarios

The reusable suite also tests replayed mapping writes, atomic validation,
unauthorized scope, exact decimal handling, stable pagination, and mapping
changes after acceptance. These are focused assertions, not additional
business scenarios. See [the test matrix](CONTRACT-TESTS.md#test-matrix).
