# G2P disbursement instruction

This synthetic project keeps the authoritative disbursement instruction in
BReg while the Payment Adapter owns one provider dispatch, polling, recovery, and
uncertain outcomes. It performs no provider calls.

The benefit service creates one instruction through
`create-disbursement-instruction`. Its stable `instructionId` is globally
unique in this project, and a positive `instructionVersion` plus
`instructionDigest` bind the source version. The instruction also freezes the
institution, service, programme and cycle, beneficiary identity and destination, funding account,
amount in minor units, currency, and currency scale. No profile has generated
Create or Patch authority, and neither later Action writes those fields.

`instructionId` is the immutable source correlation UUID. It is deliberately
distinct from the BReg record-root UUID returned as the Action result. Adapter
calls name that root as `instructionRecordId`, then compare the stored source
ID, version, digest, and every frozen instruction fact before any transition.
The exact read route is
`GET /v1/records/disbursement-instructions/{instructionRecordId}` with either
the `payment-adapter-binder` or `payment-adapter-reporter` profile.

The state machine has three Action-owned transitions:

1. `create-disbursement-instruction` creates `instruction-ready`.
2. `bind-payout-attempt` changes `instruction-ready` to `attempt-bound`,
   atomically recording one `payoutAttemptId` and `providerBindingRevision`
   before the Adapter dispatches to a provider.
3. `record-provider-confirmation` changes `attempt-bound` to
   `provider-confirmed`, recording exact `providerStatus: COMPLETED`,
   `providerReference`, and `providerResultDigest` after the Adapter verifies
   the provider response.

Every Action that changes an existing instruction compares the stored source
identity, version, digest, institution, service, programme, cycle, beneficiary, destination, funding,
and money facts with the Adapter's exact snapshot. It also requires an opaque
BReg target condition captured immediately before the attempt. A changed fact,
changed version, stale condition, or different attempt is refused.

Only requester client `benefit-service` with scope
`registry:disbursement:create` can create an instruction. Only requester client
`payment-adapter` can select the bind and report profiles, and each profile
requires its separate `registry:payout-attempt:bind` or
`registry:payout-result:report` scope. The Adapter recovers a lost response by
repeating the original idempotency key and exact request. A new key cannot bind
a second attempt or replace a confirmation after the state has advanced.

The Action routes and profile selections are:

- `POST /v1/actions/create-disbursement-instruction?accessProfile=disbursement-authority`
- `POST /v1/actions/bind-payout-attempt?accessProfile=payment-adapter-binder`
- `POST /v1/actions/record-provider-confirmation?accessProfile=payment-adapter-reporter`

## Provider meaning

`provider-confirmed` means that the configured provider reported the exact
one-instruction batch as `COMPLETED`. It does not establish beneficiary credit,
settlement, or receipt. Those stronger claims require a separately defined and
verified source.

Pending and unknown provider observations have no BReg mutation. The Adapter
retains them in its attempt custody and continues recovery against the same
attempt. `record-provider-confirmation` accepts only the exact string
`COMPLETED`; `PENDING` and `UNKNOWN` fail input validation, and the instruction
stays `attempt-bound`. That state also makes a second bind fail its commit
guard.

The Mifos one-instruction batch maps as follows:

| BReg field | Mifos batch meaning |
| --- | --- |
| `instructionId`, `instructionVersion`, `instructionDigest` | Source instruction correlation and version |
| `institutionId`, `serviceId` | Exact Adapter connection authority |
| `programmeId`, `cycleId` | Programme header and cycle description context |
| `beneficiaryDestination` | One `creditParty` destination |
| `fundingAccountId` | One `debitParty` funding identity |
| `amountMinor`, `currency`, `currencyScale` | Exact batch amount converted without binary floating point |
| `payoutAttemptId` | Adapter-owned attempt correlation before dispatch |
| `providerBindingRevision` | Exact Adapter provider configuration binding |
| `providerReference` | Correlated provider transaction reference from operations detail |
| `providerStatus` | Exact verified provider status, currently only `COMPLETED` |
| `providerResultDigest` | Adapter commitment to the exact verified provider result |

The authored journey in [`tests/journeys.yaml`](tests/journeys.yaml) covers
authorized creation and exact readback, instruction ID uniqueness, unauthorized
requester clients, changed version and frozen facts, exact idempotent binding,
second-attempt refusal, no-effect pending and unknown results, exact provider
confirmation, and replacement refusal. It uses only synthetic identifiers and
does not contact Mifos or any other provider.

Validate the authoring contract with a `bregctl` executable built from this
source revision:

```sh
bregctl check products/breg/examples/g2p-disbursement
```

Compiler validation does not prove PostgreSQL uniqueness, authorization,
transaction atomicity, target-condition enforcement, or idempotent recovery.
Those guarantees require `bregctl test` against a disposable PostgreSQL
database using matching `bregctl` and BReg source.
