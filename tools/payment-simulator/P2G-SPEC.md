# Payment Simulator P2G Collection Profile 0.1

This profile adds two biller-facing operations to the existing G2P simulator:

| Operation | Method and path | Success |
|---|---|---|
| Request a citizen payment | `POST /rtpRequest` | `200`, durable acknowledgement and polling ID |
| Observe collection status | `GET /transferRequests/{transferRequestId}` | `200`, current RTP and payment status |

It supports one full payment request per bill, with a known payer financial
address. It does not create bills, collect real money, or implement a citizen
checkout. A programme or registry remains responsible for the bill and what
confirmed payment permits. Coordinator integration is a separate change.

## GovStack review and source decisions

The source baseline is the same pinned GovStack Payments revision as G2P:
`4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a`.

| Source | Use |
|---|---|
| [billerRtpReq.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/api/P2G%20API%20YAMLs/billerRtpReq.yml) | Actual biller-to-Payments request creation contract |
| [rtpStatusUpdateRequest.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/.gitbook/assets/rtpStatusUpdateRequest.yml) | Status inquiry path and headers |
| [rtpStatusUpdateResponse.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/.gitbook/assets/rtpStatusUpdateResponse.yml) | Status vocabulary and response field spelling |
| [P2G workflow](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/9-internal-workflows/9.3-p2g-bill-payments.md) | Distinguishes the RTP exchange from the later bill payment stage |

Review found that the P2G service page labels a mark-paid acknowledgement as
`billerRtpReq` and links it to `/billTransferRequests`. That operation does not
create a request to pay. The standalone `billerRtpReq.yml` above owns the
creation shape. The aggregate `P2G.yaml` does not define a creation route.

The workflow also separates completing the request-to-pay exchange from the
subsequent payment. **`COM` alone is not evidence that the bill was paid.**
This profile adds an explicit `paymentStatus` and requires a confirmed payment
reference before reporting `PAID`.

These are deliberate profile decisions, not full GovStack conformance:

| Topic | Decision |
|---|---|
| Request spelling | Preserve `requestId`, `rtpId`, `billID`, `payerFiDetails`, `payerFIBIC`, and `billDetails` from the selected creation asset. |
| Authentication | Bearer credential with current producer/tenant/biller authority. Correlation IDs are not credentials, despite upstream's API-key declaration. |
| Tenant header | P2G uses upstream's `X-Platform-TenantId`. Existing G2P uses `Platform-TenantId`. They are not aliases. |
| Required input | Require the fields below, reject unknown members and nulls, and bound positive integer IDs. Upstream omits required-property declarations. |
| Payer routing | Support only `requestType: "00"` with explicit payer FI/address. Alias lookup (`01`) is outside this profile. |
| Money | Add required `billDetails.currency`, which the RTP asset omits despite multicurrency prose. Accept exact positive decimal JSON numbers instead of integer-only amounts. |
| Correlation | Require create `X-CorrelationID` to equal `requestId`, giving one command identity. |
| Acknowledgement | Add `transferRequestId` for polling and echo `rtpId`. `200` means durably accepted, not paid. |
| Status delivery | Return status synchronously from GET. Upstream's GET acknowledges with `202` and delivers status to a separate POST callback. No GET body or callback is needed here. |
| Status correlation | Response `RequestId` identifies the original create command. The GET's fresh `X-CorrelationID` is echoed in the response header. |
| Payment evidence | Add `paymentStatus`, original bill/amount/currency, and polling ID. `PaymentReferenceID` exists only for confirmed `PAID`. |
| Expiry | Simulate an unpaid request expiring; there is no authored TTL or wall-clock expiry scheduler in this increment. |
| Reissue | One request per bill within producer/tenant/biller scope, including failed/expired requests. Reissue, cancellation, partial payments and refunds need a later explicit policy. |

The bank-to-Payments payment notification and Payments-to-biller mark-paid
advice are not exposed as caller writes. Neither a registry workflow nor a
citizen can mark a payment successful by posting to this mock.

## Common rules

All requests require `Authorization: Bearer <token>`, `X-Platform-TenantId`
(1–20 characters), and `X-billerId` (1–20 characters). The configured producer
must be permitted to use that tenant and biller. `serve --biller` is repeatable
and defaults to `ministry`; providing values replaces that default set.

Use the G2P profile's exact-money decoder, 64 KiB body/response bounds and
problem format. Reject unknown or duplicate JSON members, wrong field casing,
wrong types, nulls, duplicate singleton selectors and unsupported query fields.
Unknown/hidden resources return `404`; invalid credentials return `401`;
unauthorized tenant or biller returns `403` before reading receipts.

Currency defaults to `USD:2` and is configured with `serve --currency`.
Amounts must be positive and fit the configured scale without rounding, with
at most `9007199254740991` minor units. Quote neither amounts nor integer IDs.

## Create a request to pay

`POST /rtpRequest`

Require `Content-Type: application/json`, `X-CorrelationID` (1–12 characters,
equal to `requestId`), and `X-Callback-URL` (1–100 characters, approved in
server configuration). The callback value is retained for wire compatibility;
the mock makes no outbound request.

All body fields below are required:

| Field | Constraint |
|---|---|
| `requestId` | Opaque command ID, 1–12 characters |
| `rtpId` | Caller RTP identity, integer 1–9007199254740991 |
| `billID` | Opaque bill identity, 1–10 characters |
| `requestType` | Exactly `"00"` |
| `payerFiDetails.payerFIBIC` | Opaque FI identifier, 1–10 characters |
| `payerFiDetails.financialAddress` | Synthetic payer address, 1–30 characters |
| `billDetails.billerName` | Display name, 1–10 characters; not an authority selector |
| `billDetails.amount` | Exact positive JSON number |
| `billDetails.currency` | Configured uppercase three-letter currency |

```json
{
  "requestId": "fee-demo",
  "rtpId": 1001,
  "billID": "bill-demo",
  "requestType": "00",
  "payerFiDetails": {
    "payerFIBIC": "TESTBANK",
    "financialAddress": "citizen-demo"
  },
  "billDetails": {"billerName": "Ministry", "amount": 25.50, "currency": "USD"}
}
```

Successful acknowledgement:

```json
{
  "responseCode": "00",
  "responseDescription": "Accepted",
  "requestID": "fee-demo",
  "rtpId": 1001,
  "transferRequestId": "provider-generated-id"
}
```

Do not infer payment from this acknowledgement. Persist the request and IDs
before dispatch. After a timeout or lost response, replay the unchanged command
to recover its acknowledgement and polling ID.

Command identity is `(producer, tenant, collection, requestId)`. Its fingerprint
includes the body, biller and callback URL. Equivalent decimal notation and
object ordering replay identically; changed content returns `409
request.id-reused`. The acknowledgement, immutable request snapshot, exact
amount/scale and selected outcome commit in one SQLite transaction.

Within a producer and tenant, `rtpId` cannot identify another accepted request
(`409 payment.id-reused`). Within producer, tenant and biller, a bill cannot
have another request (`409 collection.bill-in-use`). Refusals create no request
or receipt and do not spend a fresh command identity. Do not change bill IDs
to bypass this rule after an uncertain payment.

Current authority applies to every replay. Currency/scale changes and fixture
changes apply to new work only; existing requests keep their accepted values.

## Read status

`GET /transferRequests/{transferRequestId}`

The opaque path ID is 1–50 characters. Require a read `X-CorrelationID` of
1–20 characters. There is no body or query string. Reads are scoped to the
current producer, tenant and biller and return fresh observations.

```json
{
  "transferRequestId": "provider-generated-id",
  "RequestId": "fee-demo",
  "rtpId": 1001,
  "billId": "bill-demo",
  "amount": 25.50,
  "currency": "USD",
  "requestStatus": "COM",
  "paymentStatus": "PAID",
  "PaymentReferenceID": "provider-payment-ref",
  "lastUpdateDate": 1792134000
}
```

All shown fields except `PaymentReferenceID` are always present.
`RequestId` is the original create ID, `rtpId` is its original integer, and
`billId`, amount and currency must match the accepted intent. The payment
reference is 1–20 characters and is required only when `paymentStatus` is
`PAID`; it is absent otherwise. `lastUpdateDate` is an integer Unix timestamp
in seconds. Failed/expired results include the bounded `failureReason` below.

| RTP status | Payment status | Meaning |
|---|---|---|
| `PND` | `PENDING` | Request has been accepted; no confirmed payment |
| `COM` | `PENDING` | RTP exchange completed; payment is still unconfirmed |
| `COM` | `PAID` | Full payment confirmed; stable payment reference present |
| `RJC` | `FAILED` | Payer rejected this request; `failureReason: payer-rejected` |
| `EXP` | `EXPIRED` | Request expired unpaid; `failureReason: request-expired` |

Only the last three rows are terminal. Terminal results and payment references
remain stable across polls, replays and restarts. A consumer must validate the
IDs, amount, currency and status pairing. Unknown or contradictory results
remain unresolved, never treated as paid. A future real-provider adapter must
map actual payment evidence, not RTP delivery/acceptance, to `PAID`.

## Deterministic local outcomes and verification

Select an outcome for future requests only:

```sh
uv run payment-simulator collection-scenario --database .state/payments.sqlite \
  --producer registry --tenant pilot --biller ministry --outcome paid
```

Outcomes are `paid` (default), `failed`, or `expired`. Automatic mode advances
them in two worker steps. With `serve --manual`, `advance --steps 1` exposes
the intermediate state, and a second step produces the terminal result. The
paid scenario deliberately exposes `COM/PENDING` before `COM/PAID`. Expiry is
an injected fixture outcome, not proof that a configured real-time TTL passed.

The payment receipt and terminal transition commit together, with one receipt
per accepted request. `inspect-collections --database ...` provides separate
local evidence; it is not a public API. It can filter by `--transfer-request-id`.

`tests/contract/test_p2g_profile.py` uses live HTTP and the existing portable
target driver for outcome, replay, conflict, scope and lost-response recovery
checks. Missing external outcome/restart/witness capabilities remain explicit
not-verified skips. Implementation tests additionally cover malformed input,
concurrent replay, currency changes, and preservation of G2P state through the
single additive database upgrade from version 1 to version 2.

No programme funding, checkout UI, alias resolution, bill inquiry forwarding,
bank notification ingress, callback delivery, refunds, cancellation, expiry
scheduler, or Coordinator operation is added by this profile.
