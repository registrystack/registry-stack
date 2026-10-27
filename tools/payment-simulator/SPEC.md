# Payment Simulator G2P Profile 0.1

This document owns the five G2P operations. The separate
[P2G collection profile](P2G-SPEC.md) adds request-to-pay creation and status
lookup without changing these operations or their tenant-header spelling.

**Status: implemented local development profile.** The five API operations
and polling/replay behavior are implemented. Optional notification delivery
and replacement-provider retention rules below are extension requirements,
not claims of shipped features or external conformance.

The first implementation follows the [lean definition of done](DEFINITION-OF-DONE.md).
It implements the five API operations and polling/replay behavior. Optional
outbound callbacks and production deployment machinery are deferred.

## Purpose and boundary

Allow programme authors to register payment destinations, submit a batch, and
reconcile each instruction through the same HTTP contract they will use with
a real provider. The simulator owns mappings, accepted commands, simulated
payment state. It has no knowledge of Coordinator
workflows, eligibility rules, registry records, or human approvals.

The initial service has five public business operations:

| Operation | Method and path | Success |
|---|---|---|
| Register beneficiary mappings | `POST /identityAccountMapper/beneficiary` | `200`, applied acknowledgement |
| Update beneficiary mappings | `PUT /identityAccountMapper/beneficiary` | `200`, applied acknowledgement |
| Look up beneficiary mappings | `GET /beneficiary/` | `200`, current mappings |
| Submit a batch | `POST /batchtransactions?type=raw` | `202`, durable `batchId` |
| Read batch details | `GET /api/v1/batch/detail` | `200`, instruction rows |

Health probes and local development controls are outside these five operations.
Optional batch notifications describe a future sender to a caller's configured
receiver; that receiver is not another simulator business endpoint. The initial
mock accepts approved callback URL fields but makes no outbound calls.

There are no bank-facing account-validation or funds-authorization APIs, payer
funding ledger, fees, settlement, reversals, refunds, cancellation, voucher
issuance/redemption, FX, files, or production payment rails. Those internal
behaviors can be represented by deterministic success or rejection outcomes.
An accepted payment cannot be undone by cancelling a workflow.

## Source baseline and compatibility

The upstream baseline is the GovStack Payments repository at
[`4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a`](https://github.com/GovStackWorkingGroup/bb-payments/tree/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a).
The owning source files are:

| Area | Pinned source |
|---|---|
| Register | [RegisterBeneficiaryRequest.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/.gitbook/assets/RegisterBeneficiaryRequest.yml) |
| Update | [UpdateBeneficiaryRequest.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/.gitbook/assets/UpdateBeneficiaryRequest.yml) |
| Lookup | [AccountLookup.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/api/G2P%20API%20YAMLs/AccountLookup.yml) |
| Submit | [v1_0_1_fixed_BulkPayment.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/.gitbook/assets/v1_0_1_fixed_BulkPayment.yml) |
| Detail | [BatchDetails.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/api/G2P%20API%20YAMLs/BatchDetails.yml) |
| Batch notification | [v1_0_1_fixed_BulkPaymentStatusUpdate.yml](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/.gitbook/assets/v1_0_1_fixed_BulkPaymentStatusUpdate.yml) |
| Flow and modality definitions | [G2P workflow](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/9-internal-workflows/9.1-g2p-bulk-payment.md), [data structures](https://github.com/GovStackWorkingGroup/bb-payments/blob/4b63a6b5efbb20123c442e0b09fb44ec2d7e6b6a/spec/7-data-structures.md) |

Use the corrected bulk assets above. The older bulk YAML repeats a
`parameters` key and can silently lose parameters when parsed. Lookup and
batch detail are present in the upstream API directory but are not a complete,
consistently linked part of the G2P prose. This profile explicitly adopts them.

The following decisions are profile requirements. Upstream does not specify
all of them, and an upstream-shaped server does not automatically satisfy them.

| Topic | Profile decision |
|---|---|
| Field casing | Preserve the selected upstream operation's spelling, including register's mixed case. Do not silently accept aliases. HTTP header names remain case-insensitive. |
| Missing requirements | Require bodies, populated arrays, identifying fields, bounded values, and complete success responses as specified below. |
| Authentication and scope | Require bearer authentication and `Platform-TenantId` on all five APIs. A callback URL is never an authentication credential. |
| Mapping writes | A `200` with `responseCode: "00"` means the whole write committed and is visible to lookup. Upstream describes separate asynchronous onboarding notifications. This profile does not emit those notifications. |
| Mapping institution | Retain register's institution header and lookup's `registeringInstitutionId`; add the institution header to update. `sourceBBID` identifies the authorized source, not an alternative mapping namespace. |
| Registration bank code | Add optional `bankingInstitutionCode`, present in the upstream data model and update API but absent from register's selected schema. |
| Mapping status | Do not accept update's `status` field in 0.1. Upstream supplies `0` and `1` without defining their meanings. |
| Payment modes | Mapping supports codes `00` through `04`; submission supports configured account/balance modes from `00`, `01`, and `03`, default `00`. Voucher and proxy disbursement require a later profile. |
| Lookup callback | Omit the anomalous required `X-Callback_URL` header. Lookup is synchronous and never initiates a callback. |
| Correlation | Limit batch `X-CorrelationID` to 12 characters, the intersection of submit's 20 and callback's 12. |
| Instruction identity | Echo the submitted `requestId` in every detail row. This is an additive field, absent upstream. `transactionId` remains provider-owned. |
| Durability and states | Define atomic acceptance, immutable membership and destination snapshots, replay/conflict rules, pagination, and terminal-state meanings. |
| Amounts | Preserve JSON numbers, but process them as exact decimal amounts rather than upstream's suggested binary `float`. One currency per batch. |
| Notifications | Polling is authoritative. Notifications are optional hints, with `result_file: null` for JSON batches, resolving the upstream string/null contradiction. |
| Errors | Use consistent HTTP errors and problem bodies rather than register's alternate capitalized error object. No validation response uses FastAPI's default `422`. |

A real implementation may implement this profile directly or expose it through
an adapter. An adapter may translate wire shapes, provider authentication, and
status vocabulary, and retain durable correlation state. It must not invent
recipient-credit evidence or retry an uncertain downstream effect without an
equivalent downstream deduplication guarantee. Matching OpenAPI alone is
insufficient for replacement.

## Common request and response rules

All five APIs require `Authorization: Bearer <token>` and
`Platform-TenantId` (1 to 20 characters). The authenticated principal maps to
a stable producer ID and allowed tenants, institutions, source IDs, payer
accounts, and programmes. Headers select authorized scope; they never grant it.
Token rotation must preserve the producer identity used for replay.

Mapping records are keyed by `(tenant, institution, payeeIdentity,
paymentModality)`. Authorized producers can share an institution's mappings;
mutation replay records and batches remain producer-scoped. Reads enforce the
current caller's scope. An unauthorized tenant or institution is refused before
lookup; an absent or inaccessible resource inside permitted scope returns the
same `404`.

Requests use `application/json` where a body is present. Object member names
are case-sensitive. Unknown members, duplicate JSON keys, duplicate singleton
headers/query parameters, wrong types, and empty required strings are refused.
Clients must ignore additional response members but validate all fields they
use. IDs and destinations are opaque, case-sensitive strings; no trimming or
case folding changes their identity.

Initial bounded limits are 64 KiB per request and response, 1 to 100 entries
per mapping write or batch, and 1 to 50 detail rows per page (default 10).
These limits bound this development profile; supporting larger batches is a
later explicit profile change. Body timestamps are RFC 3339 UTC strings, at
most 35 characters. Leave out informational optional response fields where
necessary to fit a valid page within the size limit; never truncate required
fields or omit rows to make a page fit.

Amounts are positive JSON numbers with at most the configured currency scale.
The default fixture currency is `USD`, scale 2. Additional uppercase
three-letter currencies and their scales are explicit operator configuration.
Reject unsupported currencies, non-finite numbers, quoted amounts, excessive
precision, and mixed-currency batches. Store exact minor units; each amount
and the batch total must be at most `9007199254740991` minor units. Never round
input or parse it through a binary float. `100`, `100.0`, and `100.00` represent
the same amount.

Failures use `application/problem+json`, with `type: "about:blank"`, `title`,
numeric `status`, and a stable `code`. An optional `field` is a field path,
never the submitted value. Error bodies must not contain credentials,
financial addresses, or another tenant's identifiers.

| HTTP | Code | Meaning |
|---|---|---|
| `400` | `request.invalid` | Invalid body, selector, currency, or profile feature; nothing accepted by this attempt |
| `401` | `auth.required` | Missing or invalid credential |
| `403` | `auth.forbidden` | Current authority does not permit the requested scope or effect |
| `404` | `resource.not-found` | Resource absent or not visible |
| `409` | `request.id-reused` | A command identity already exists with different content |
| `409` | `mapping.exists` | Registration would overwrite an existing mapping |
| `409` | `payment.id-reused` | An instruction identity already belongs to another accepted batch |
| `410` | `receipt.expired` | A retained identity exists but its detailed receipt has expired |
| `413` | `request.too-large` | Payload or entry count exceeds a published bound |
| `415` | `request.media-type` | Unsupported request content type |
| `503` | `service.unavailable` | The service cannot complete the request |

A timeout, disconnect, malformed success, or `5xx` after possible dispatch is
an uncertain submission. Even a later `400`, `401`, `403`, `404`, or `410`
cannot prove that an earlier uncertain attempt had no effect. Operational
failure is not a negative payment outcome.

## 1. Register beneficiary mappings

`POST /identityAccountMapper/beneficiary`

Additional required headers:

- `X-Registering-Institution-ID`: 1 to 12 characters, authorized institution.
- `X-Callback-URL`: absolute URL, at most 100 characters, matching a configured
  receiver. Retained for upstream compatibility; registration is synchronous
  in this profile and does not send an onboarding callback.

Body fields, required unless marked optional:

| Field | Contract |
|---|---|
| `RequestID` | Command ID, 1 to 12 characters |
| `Beneficiaries` | Nonempty array |
| `Beneficiaries[].payeeIdentity` | Functional beneficiary ID, 1 to 20 characters |
| `Beneficiaries[].PaymentModality` | One of `00`, `01`, `02`, `03`, `04` |
| `Beneficiaries[].FinancialAddress` | Opaque destination, 1 to 30 characters |
| `Beneficiaries[].bankingInstitutionCode` | Optional institution code, 1 to 11 characters |

The modality vocabulary is bank account (`00`), mobile money (`01`), voucher
(`02`), digital wallet (`03`), and proxy (`04`). The simulator treats them as
distinct mapping selectors. It does not implement any rail's validation or
voucher lifecycle. Operator fixtures supply any institution code a target
requires.

Every `(payeeIdentity, PaymentModality)` pair must occur once. The entire write
is atomic. A previously registered pair causes `409 mapping.exists`, even
when its address matches; use the original command ID to recover an earlier
registration or use update for a deliberate change. An exact replay returns
the original response without reapplying the write.

Successful response, with all fields required:

```json
{"responseCode":"00","responseDescription":"Applied","requestID":"reg-001"}
```

The response's `requestID` echoes `RequestID`. `responseDescription` is
informational and at most 200 characters; clients branch on the HTTP status
and `responseCode`, not its wording.

## 2. Update beneficiary mappings

`PUT /identityAccountMapper/beneficiary`

Require `X-Registering-Institution-ID` with the same scope and length as
registration. There is no callback header requirement.

| Field | Contract |
|---|---|
| `requestID` | Required command ID, 1 to 12 characters |
| `sourceBBID` | Required source ID, 1 to 12 characters, bound to the authenticated producer |
| `beneficiaries` | Required nonempty array |
| `beneficiaries[].payeeIdentity` | Required ID, 1 to 20 characters |
| `beneficiaries[].paymentModality` | Required existing modality selector, `00` through `04` |
| `beneficiaries[].financialAddress` | Optional replacement, 1 to 30 characters |
| `beneficiaries[].bankingInstitutionCode` | Optional replacement, 1 to 11 characters |

Each item must supply at least one replacement field. Omission preserves that
field; null and empty values are invalid. There is no field-clearing, mapping
deletion, identity rename, or activation/deactivation operation in 0.1.
Changing modality requires registering a separate mapping. Unknown pairs cause
`404 resource.not-found`, and duplicate pairs are invalid. Validate all items
before atomically applying any of them.

Return the same acknowledgement shape as register, echoing `requestID`.
Distinct update commands serialize in commit order. Replaying an earlier
command returns its original acknowledgement and must not restore an older
mapping over a later update. Already accepted batches retain their original
destination snapshots.

## 3. Look up beneficiary mappings

`GET /beneficiary/?payeeIdentity=<id>&requestId=<read-id>`

Require `registeringInstitutionId` as the institution header, 1 to 12
characters. The query's `payeeIdentity` is 1 to 20 characters and `requestId`
is 1 to 12. The read ID is echoed for correlation; repeated reads are fresh
observations, not idempotency receipts. The trailing slash is part of the path;
clients do not rely on redirects.

```json
{
  "requestId": "lookup-001",
  "paymentModalityList": [
    {
      "payeeIdentity": "beneficiary-001",
      "paymentModality": "00",
      "financialAddress": "acct-001",
      "bankingInstitutionCode": "TESTBANK"
    }
  ]
}
```

Return one current item per modality, sorted by modality code. All shown
fields are required except `bankingInstitutionCode`, which is omitted when
unset. Return `404` when no mapping is visible. Lookup must observe a committed
register or update from before the read began. It never initiates a callback.

## 4. Submit a batch

`POST /batchtransactions?type=raw`

All these headers are required by this profile:

| Header | Contract |
|---|---|
| `X-CorrelationID` | Stable command ID, 1 to 12 characters |
| `X-Program-Id` | Authorized programme ID, 1 to 20 characters |
| `X-Registering-Institution-Id` | Authorized mapping institution, 1 to 12 characters |
| `X-Callback-URL` | Configured absolute receiver URL, at most 100 characters |

The body is a nonempty array. Each instruction has:

| Field | Contract |
|---|---|
| `requestId` | Stable payment instruction ID, 1 to 16 characters |
| `creditParty` | Exactly one `{ "key": "payeeIdentity", "value": "<functional ID>" }`, value at most 20 characters |
| `debitParty` | Exactly one `{ "key": "accountId", "value": "<payer account>" }`, value at most 30 characters |
| `paymentMode` | A configured disbursement modality from `00`, `01`, `03`; default `00` |
| `amount` | Exact amount under the common rules |
| `currency` | Configured currency |
| `descriptionText` | Optional nonempty text, at most 50 characters |

The party-key vocabulary and the binding of `paymentMode` to mapper modality
are profile decisions; upstream leaves these open. Bank (`00`), mobile-money
(`01`), and digital-wallet (`03`) modes can model a recipient account or balance
credit. A target declares its enabled subset, and a replacement must support
the modes its workflow uses with the same terminal-evidence meaning. Voucher
(`02`) and proxy (`04`) mappings can be stored but cannot be submitted for
disbursement in 0.1. An unsupported or disabled mode returns `400 request.invalid`.

All instructions in a batch use the same payer account and currency. Duplicate
instruction IDs are invalid. Payer-account and programme authority are checked
before acceptance.
An instruction ID is unique across accepted batches of one producer and tenant,
including batches in different programmes. An intentional subsequent payment
uses a new ID; a retry of the same payment does not.

Within one durable transaction, acceptance must:

1. Establish the authenticated producer and validate current tenant,
   institution, programme and payer authority before disclosing any stored
   command or conflict. Recheck that authority at the acceptance boundary.
2. Check the producer-scoped command identity and fingerprint for replay or
   conflict. For a new identity, validate all remaining syntactic constraints
   and instruction uniqueness before creating anything.
3. Allocate one `batchId` and one provider-owned `transactionId` per instruction.
4. Freeze the complete instruction list, amounts, programme, payer, original
   instruction IDs, and resolved destination for each mapping. A mapping update
   racing with submission takes effect wholly before or wholly after this
   snapshot, never partway through it.
5. Persist the command fingerprint, response, rows, and durable work before
   acknowledging acceptance or starting simulated processing.

A missing mapping is a per-instruction business rejection, not malformed
batch syntax. Freeze that missing-mapping result at acceptance and resolve it
to `RJCT` with `mapping-not-found`; a later registration cannot rescue that
accepted instruction. Configured business rejections similarly produce
instruction outcomes. There is no partial acceptance of malformed batches.

```json
{"batchId":"batch-0001"}
```

The response is `202`, with a nonempty `batchId` of at most 50 characters.
It proves durable acceptance, not successful payment. While the response is
retained, exact replay returns this same response even after processing
completes or the service restarts. Retention behavior is defined below.

## 5. Read batch details

`GET /api/v1/batch/detail?batchId=<id>&pageNo=0&pageSize=10`

| Query | Contract |
|---|---|
| `batchId` | Required accepted ID, at most 50 characters |
| `pageNo` | Zero-based integer, default 0 |
| `pageSize` | Integer 1 to 50, default 10 |
| `X-CorrelationID` | Optional original command ID; mismatch returns `404` |
| `direction` | Optional; only `OUTGOING` is supported |
| `status` | Unsupported in 0.1; reject it rather than risk an incomplete reconciliation |

Return a bare JSON array. Every row requires:

| Field | Meaning |
|---|---|
| `requestId` | Exact original instruction ID; profile addition |
| `transactionId` | Stable provider-owned ID, at most 50 characters |
| `batchId` | Exact batch ID |
| `amount`, `currency` | Exact accepted amount and currency |
| `status` | `PDNG`, `ACSP`, `ACCC`, or `RJCT` |
| `startedAt` | Time the instruction was durably accepted |
| `direction` | `OUTGOING` |

For a resolved mapping, also require `payeePartyId` equal to the **frozen
financial address** and `payeePartyIdType: "FINANCIAL_ADDRESS"`. Return
`payeeDfspId` when an institution code was frozen. Those fields are absent
for a missing mapping. They must never be regenerated from the current mapper.
The submitted beneficiary identity is correlated through `requestId`; do not
interpret a financial address as that identity.

Terminal rows require `completedAt`. Rejected rows also require
`errorInformation`, a stable reason such as `account-rejected` or
`mapping-not-found`, at most 100 characters. Optional `statusDetail` is bounded
to 200 characters and is informational. Omit unset optional fields. Never
substitute the original ID into `transactionId` or `workflowInstanceKey`.

The row set is fixed at acceptance and sorted by `requestId` in ascending
Unicode code-point order. With a fixed page size, each row stays on the same
page. Beyond the last row, return `200 []`. States can advance between page
reads; membership, correlation, amounts, and terminal outcomes cannot change.
Persist terminal rows for recovery. `404` is not evidence that no payment was
accepted.

## Payment and batch outcomes

| Status | Meaning for the caller | Terminal |
|---|---|---|
| `PDNG` | Accepted, not yet resolved | No |
| `ACSP` | Processing | No |
| `ACCC` | Recipient credited; simulated credit in this service | Yes |
| `RJCT` | Instruction rejected without a recipient credit | Yes |

Allow `PDNG -> ACSP -> ACCC`, `PDNG -> ACSP -> RJCT`, and direct transitions
from `PDNG` to either terminal state. Terminal states never change. An unknown
status holds reconciliation for investigation. In particular, `ACSC` is not
recipient-credit evidence and must not be translated to `ACCC` solely because
the debtor account settled. The distinction follows the
[Open Banking transaction-status descriptions](https://standards.openbanking.org.uk/get-started/propositions/p9/).
Returns or reversals after a real recipient credit need a later contract.

The caller keeps the original instruction set and collects every page with a
fixed page size. Before completing, it must account for each original ID
exactly once, with the correct batch, stable transaction ID, amount, and
currency. Missing, duplicate, extra, or changed rows hold reconciliation;
they are not partial business failures. Valid terminal rows can be accumulated
across polls because terminal states are immutable.

The caller derives the batch result only when every instruction is terminal:

- `completed`: all rows are `ACCC`.
- `failed`: all rows are `RJCT`.
- `partial`: at least one `ACCC` and at least one `RJCT`.
- Otherwise the batch remains `pending`.

These are caller result names, not additional server status codes. A partial
outcome does not authorize resubmitting the batch or automatically retrying
rejected instructions. Timeout or exhausted observation budget means the
caller stopped waiting; accepted source work may continue.

## Durable replay and retention

Command identities are `(producer, tenant, operation, command ID)`.
Register uses `RequestID`, update uses `requestID`, and submit uses
`X-CorrelationID`. Including the operation separates the three ID spaces.

The fingerprint covers the method, operation, parsed body, and all
effect-bearing scope and callback values. Canonicalization ignores JSON object
member order, whitespace, header-name case, and equivalent decimal notation.
Array order and string values are significant. Credentials and transient
tracing headers are excluded. Store a canonicalization version alongside the
fingerprint, including any currency-scale assumptions it needs, so an upgrade
or configuration change cannot silently change an old command's meaning.

Authenticate and authorize every attempt. For an authorized exact replay whose
response is still retained, return the stored success without evaluating current
mappings or running work again. New-payment currency, scale and enabled-mode
configuration is evaluated only for a new command; it cannot invalidate an
existing receipt. Current payer and other scope authority still applies to
replays. Expired evidence follows the `410` rule below.
Different content with the same identity returns `409 request.id-reused`
and preserves the original effect. Two concurrent identical submissions must
converge on one accepted batch. Reusing an instruction ID under a different
batch command returns `409 payment.id-reused` without accepting any new rows.

A definitely refused attempt that creates no accepted command does not spend
its command identity. A corrected request may reuse that identity and be
accepted. This rule never frees an identity already accepted by another attempt,
and a caller must not use a later refusal to dismiss an earlier unknown outcome.

If a submission might have reached the service, retain the original command
and identity. Within the original caller deadline, recover by replaying that
same command, then poll its recovered `batchId`. Do not invent a new key after
a lost response. This profile has no separate read-only receipt lookup by
original command ID; lookup of a beneficiary is not a payment receipt.

Initial simulator storage has no automatic receipt expiry or pruning. State
survives process restarts through the same SQLite file. A test
runner may dispose of its own isolated fixture after a test; the business API
has no reset operation.

A replacement's documented retention must cover the workflow's maximum
recovery horizon. If it erases terminal detail later, retain command,
instruction and batch tombstones. An authorized exact POST replay returns
`410 receipt.expired`; an authorized detail GET for the expired batch also
returns `410 receipt.expired`. Changed content under the spent command identity
still conflicts. Never accept a fresh effect under a spent identity. The word
receipt here means retained acceptance/result evidence, not a separate API.
Pending or uncertain work cannot expire. A missing or expired receipt leaves
the original outcome unresolved. Provider migrations must retain or continue
routing outstanding commands to the provider that accepted them.

## Optional batch notifications

This section is a future extension. No callback sender, receiver credentials,
outbox, or notification tests are implemented in the initial mock.

The sender can POST to the exact `X-Callback-URL` selected from operator-approved
receivers, appending `batchId` and `X-CorrelationID` query parameters. Receiver
URLs have no existing query or fragment. The conventional path is
`/api/v1/batch`, as in the selected upstream asset. Credentials for the receiver
are configured separately; never forward the incoming caller's token. Send
`Content-Type: application/json`, `Platform-TenantId`, and a dedicated receiver
`Authorization: Bearer <receiver-token>`. The receiver binds this credential
to the expected producer and tenant. Do not forward arbitrary caller headers.

When notifications are enabled, create exactly two logical events per batch:
an accepted snapshot with all instructions `PDNG`, and a final snapshot when
the last instruction becomes terminal. Create each event in the same
transaction as the corresponding state change. Do not emit an event for
intermediate progress. Delivery can still be duplicated or out of order.
`ongoing` counts `PDNG` and `ACSP`, `completed` counts `ACCC`, and `failed`
counts `RJCT`; their amount fields sum the corresponding accepted amounts.

Use the upstream body fields, with all required:

```json
{
  "requestId": "event-001",
  "batchId": "batch-0001",
  "TotalTransactions": 2,
  "ongoing": 0,
  "failed": 0,
  "completed": 2,
  "currency": "USD",
  "totalAmount": 250.00,
  "completed_amount": 250.00,
  "ongoing_amount": 0.00,
  "failed_amount": 0.00,
  "result_file": null,
  "resultGeneratedAt": "2026-10-16T10:00:02Z",
  "note": "Batch status available"
}
```

`requestId` is a persisted notification ID of at most 12 characters, unique
within a producer and tenant across batches and events. It has a separate
namespace from instruction IDs. Counts are nonnegative integers and partition the
original instruction count; exact amounts partition the total. Save an
immutable notification snapshot with the state change, then deliver it from
a durable outbox. Retries reuse the same ID and body. `200` or `202` acknowledges
delivery. Use bounded attempts, timeouts, and retry delays; exhausted delivery
does not change payment state or block polling. No redirects are followed.

Notifications may be absent, duplicated, delayed, or delivered out of order.
They only make an existing eligible poll useful sooner within the caller's
observation floor; they never prove a payment outcome, reset a deadline, or
start a new workflow. Batch notification support is an optional capability
for replacement targets. Required callback headers do not require the caller
to depend on delivery.

## Simulator implementation boundary

Use an independent Python package with FastAPI/Pydantic for HTTP models and
validation, SQLite for durable state, and a single-process durable worker.
Use exact decimal parsing at the HTTP boundary and integer minor units in
storage. Pydantic serialization must preserve numeric JSON amounts, not emit
Decimal values as quoted strings. Framework defaults must not silently add
redirects, accept unknown fields, or change error status codes.

HTTP handlers and the worker share service functions and transactions. Store
mappings, command fingerprints and responses, batches, instruction snapshots,
pending transition state, and simulated credit records.
Unique constraints enforce command, instruction, and simulated-credit
identities. A worker restart resumes durable work; a credit and its terminal
transition commit together. An in-memory timer or FastAPI background task is
not the only record of unfinished work.

Local CLI controls select scenarios and advance held transitions in discrete
steps. They operate on an explicitly selected development
database and are never public payment APIs. Public request bodies contain no
`scenario`, `forceFailure`, special beneficiary sentinel, or mock-only field.
Bind a fixture's scenario to an isolated producer/tenant before submission,
then freeze it with accepted work. Replays do not reselect a scenario.

Default to loopback, synthetic data, and an explicit development credential
read from a protected file. Keep credentials, bodies, and financial addresses
out of logs. Callback URLs must be explicit approved HTTP(S) URLs; the mock
never connects to them. Any future delivery implementation needs the receiver
credential and destination protections described above.
There is no unauthenticated data API or remotely exposed reset/fault API.
This development authentication profile does not model full GovStack
deployment security, bulk signatures, or production payment authorization.

## Coordinator integration boundary

The Coordinator provides generic `external.command/v1` and `external.read/v1`
operations. A workflow project defines payment schemas, mappings, interpretation,
and completion in YAML/Rhai. No payment-specific runtime operation or simulator database access is required.

An integration must save the original command before dispatch, use
same-command recovery, validate complete per-instruction results, and respect
Coordinator's observation budgets and original deadline. It must not claim
read-only original-key receipt recovery that this profile does not provide.
One response-page interpreter cannot prove completion of a multipage batch;
the integration must either collect bounded pages durably or enforce an
explicit single-page batch limit. The maintained disbursement example durably observes two
50-row pages and checks an empty third page, covering the profile's 100-instruction ceiling.

Provider selection, endpoint, credential references, and provider-specific
translation belong to the connection/adapter. Programme workflows contain
the payment intent and typed outcomes. Switching a validated connection must
not require simulator branches in workflow definitions. Changing a connection
for new work is separate from migrating unfinished payments and their replay
history.
