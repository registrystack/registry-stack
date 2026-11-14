# Payment-gated service issuance

This synthetic example keeps the authoritative fee and issuance decision in
BReg while the Payment Adapter owns provider identifiers, retries, pending or
unknown outcomes, and its receipt-reporting journal in PostgreSQL. It does not
turn BReg into a provider queue.

`create-fee-bill` applies the service-owned `synthetic-licence-fee` tariff. It
creates one bill at version 1 for USD 25.00, represented exactly as 2500 minor
units with currency scale 2. The unique
`(institution-id, service-id, request-id)` constraint prevents a fresh workflow
from creating another bill UUID for the same service request. The BReg record
root UUID is the payment protocol's `billId`. The `bill-version` field is the
protocol's positive domain `billVersion`; it is not the BReg record revision or
HTTP condition.

Every Action that changes an existing bill also requires BReg target
conditions captured immediately before the attempted transition. That opaque
condition carries the current BReg document revision and prevents a concurrent
mutation from committing against a stale read. It is deliberately separate
from the service-owned `bill-version`, which remains an explicit Action input
and exact stored-field guard.

The authorised service supplies `bill-digest` as its opaque commitment to the
frozen bill facts. BReg requires exactly 64 characters, stores it, and compares it
exactly in every later Action. BReg does not recompute SHA-256 or RFC 8785 JCS.
The Adapter must independently hash and retain its full exact intent snapshot,
and the binding and receipt Actions compare every financial and identity fact
even when the digest matches.

## Guarded state transitions

The bill moves only through these Action-owned transitions:

1. `create-fee-bill`: absent to `due-unbound`.
2. `bind-payment-attempt`: `due-unbound` to `attempt-bound`, atomically
   freezing `payment-attempt-id` and `provider-binding-revision` before provider
   dispatch.
3. `record-payment-receipt`: `attempt-bound` to `paid`, after exact comparison
   of institution, service, request, tariff identity/version/digest, payer,
   payer financial address, bill version and digest, amount, currency, scale,
   simulation flag, payment attempt, and provider binding.
4. `issue-paid-service`: `paid` to `issued`, using only `billId`, expected
   `billVersion`, `requestId`, `paymentReceiptId`, and a new `issuanceId`. The
   Action reads the authoritative stored state and cannot replace or reassemble
   provider evidence.

No access profile has CRUD Create or Patch authority. Only the issuance service
can create bills and issue the service. Only the Payment Adapter can bind an
attempt or report a receipt. One Adapter credential can carry both exact
scopes while selecting the separate binder and reporter profiles. The
Coordinator profile is read-only and citizens
have no profile. Once an attempt is bound, Adapter outcomes `pending` and
`unknown` both remain BReg `attempt-bound`; neither creates a route to bind a
second attempt. An exact retry uses the original BReg idempotency key. A new
idempotency key cannot replace the binding or receipt because the state guard
has already advanced.

The Action invoke routes are:

- `POST /v1/actions/create-fee-bill?accessProfile=service-biller`
- `POST /v1/actions/bind-payment-attempt?accessProfile=payment-adapter-binder`
- `POST /v1/actions/record-payment-receipt?accessProfile=payment-adapter-reporter`
- `POST /v1/actions/issue-paid-service?accessProfile=service-issuer`

The exact receipt can be recovered through the normal
`GET /v1/records/service-fee-bills/{billId}` route with
`payment-adapter-reporter`. The Action result named `bill` returns the same
record envelope after each successful transition.

The HTTP input contracts use these authored camel-case names:

- `create-fee-bill`, profile `service-biller`, client `issuance-service`, scope
  `registry:fee-bill:create`: `institutionId`, `serviceId`, `requestId`,
  `payerId`, `payerFinancialAddress`, `billDigest`, `simulation`.
- `bind-payment-attempt`, profile `payment-adapter-binder`, client
  `payment-adapter`, scope `registry:payment-attempt:bind`: `billId`,
  `billVersion`, `billDigest`, `institutionId`, `serviceId`, `requestId`,
  `tariffId`, `tariffVersion`, `tariffDigest`, `payerId`,
  `payerFinancialAddress`, `amountMinor`, `currency`, `currencyScale`,
  `simulation`, `paymentAttemptId`, `providerBindingRevision`.
- `record-payment-receipt`, profile `payment-adapter-reporter`, client
  `payment-adapter`, scope `registry:payment-receipt:report`: every bind input
  plus `paymentReceiptId`, `providerReference`, and `receiptDigest`.
- `issue-paid-service`, profile `service-issuer`, client `issuance-service`,
  scope `registry:paid-service:issue`: `billId`, `billVersion`, `requestId`,
  `paymentReceiptId`, `issuanceId`.

Every successful Action response exposes result `bill`, the resulting BReg
record envelope. Exact readback uses profile `payment-adapter-reporter`, client
`payment-adapter`, and scope `registry:payment-receipt:report`. The read-only
Coordinator profile is `coordinator-bill-reader`, client
`service-coordinator`, scope `registry:fee-bill:read`; it receives no Action
permission.

## Payment protocol mapping

| BReg field | Payment protocol field |
| --- | --- |
| record root UUID | `billId` |
| `bill-version` | `billVersion` |
| `amount-minor`, `currency`, `currency-scale` | exact `Money.value`, `currency`, `scale` |
| `payment-attempt-id` | `collectionId` |
| `provider-binding-revision` | `bindingRevision` |
| `simulation` | `simulation` |
| `payment-receipt-id` | `receiptId` |
| `provider-reference` | `providerReference` |

The Adapter converts minor units to canonical decimal text without binary
floating point. The fixture bounds positive minor units and bill versions to
9,007,199,254,740,991, matching the payment protocol's portable JSON integer
limit. Adapter provider configuration must independently allow the bill's
currency and currency scale before dispatch; the BReg Actions then require
those frozen values to remain exact.

`payer-financial-address` is a frozen synthetic provider address of at most 30
printable ASCII characters. BReg enforces that persisted pattern and exact
comparison, while the Adapter validates the provider-specific address grammar.
`receipt-digest` is exactly 64 lowercase hexadecimal characters, representing
the Adapter's SHA-256 commitment to its exact receipt object. `payerFiBic`
remains in the provider connection configuration and is not a bill fact.

## Synthetic and live operation

The authored journey uses `simulation: true` and synthetic references. BReg
freezes and compares that flag, so a receipt with a different flag cannot
satisfy the bill. BReg trusts the restricted Adapter reporter for provider
facts and cannot detect a compromised reporter relabelling synthetic data.
Live rejection therefore also belongs to Adapter configuration: a live binding
must refuse the simulator or any receipt marked as simulation before invoking
the BReg reporter Action.

Validate the authored project and its journey with the pinned `bregctl` build
for this branch:

```sh
bregctl check products/breg/examples/payment-fee-issuance
```

The 30-step journey covers duplicate bill creation, unauthorised binding and receipt
reporting through missing scopes, changed bill/version/amount/attempt facts,
simulation mismatch, exact idempotent recovery, pending or unknown guards,
receipt readback, and single-use issuance. The journey reader intentionally
refuses a requester client outside the selected profile even for an expected
404, so native acceptance separately probes the Coordinator credential and an
unauthenticated citizen against both Adapter Actions. Compiler validation does
not prove PostgreSQL uniqueness, authorization, transaction atomicity, or
idempotent replay; those require the native real-PostgreSQL fixture run.

## Native acceptance and runtime handoff

[`run-native.sh`](run-native.sh) is the maintained synthetic acceptance helper.
It requires a caller-owned TLS PostgreSQL cluster and absolute paths supplied
through these environment variables:

- `PAYMENT_FEE_BREGCTL_BIN`: the pinned normal `bregctl` executable.
- `PAYMENT_FEE_BREG_BIN`: the matching normal `breg` executable.
- `PAYMENT_FEE_DATABASE_ADMIN_URL`: an administration URL for the isolated
  cluster, including `sslmode=require`, `verify-ca`, or `verify-full`. Inject
  credential-bearing values without placing them in shell history.
- `PAYMENT_FEE_POSTGRES_CA_FILE`: the PEM trust root for that server.
- `PAYMENT_FEE_ACCEPTANCE_ROOT`: an existing private directory under which the
  helper may create `payment-fee-issuance/runs/`.
- `PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH`: optional macOS dynamic-library
  directory required by the pinned binaries.
- `PAYMENT_FEE_DYLD_LIBRARY_PATH`: optional macOS dynamic-library directory
  for a preserved binary whose FIPS library is referenced through `@rpath`.
- `PAYMENT_FEE_LISTENER`: optional `127.0.0.1:PORT` override. Otherwise the
  helper chooses an available loopback port.
- `PAYMENT_FEE_KEEP_RUNNING`: optional `0` or `1`, default `0`. Set it to `1`
  for a joined Adapter and Coordinator run that must retain BReg after the
  helper publishes its handoff.
- `PAYMENT_FEE_BREG_FEATURE_PROFILE` and
  `PAYMENT_FEE_BREGCTL_FEATURE_PROFILE`: optional bounded provenance labels,
  default `unspecified`. Set these from the pinned build metadata rather than
  inferring compile-time features from a filename.

The helper creates unique schema-test and runtime databases, with separate
non-administrative migration and runtime roles. It preserves all existing
databases and services and deliberately does not delete its own databases or
roles after a run. It executes the maintained sequence `check`, `test`,
`package`, `plan`, `apply`, and `status`, then starts the matching `breg`
process. Every command report is retained under the private run directory.
The private `reports/binary-provenance.json` and handoff record each binary's
absolute path, SHA-256 digest, version output, and supplied feature-profile
label.
With `PAYMENT_FEE_KEEP_RUNNING=1`, the helper prints the completed handoff and
then waits in the foreground for its own BReg child. Keep that terminal or
managed session open for the joined run. Sending `TERM` or `INT` to the helper
forwards the signal only to that owned child PID and waits for it to finish.
Closing the retained terminal can send `HUP` to the helper. Because its
`nohup`-launched child ignores `HUP`, the helper deliberately maps parent
`HUP` to child `TERM`, then waits for that same owned PID to finish. The
default `0` preserves the non-waiting handoff behavior.

On success, the helper prints only the path to its owner-readable
`handoff.json`. The stable pointer
`payment-fee-issuance/latest-run` contains the private run-directory path. The
handoff names the loopback base URL, package root and digest, schema
fingerprint, runtime configuration, process ID file, action routes and
profiles, selected helper lifetime mode, and these credential references:

- `secrets/payment-adapter-token`: client `payment-adapter`, purpose
  `payment-processing`, with only `registry:payment-attempt:bind` and
  `registry:payment-receipt:report`.
- `secrets/issuance-service-token`: client `issuance-service`, purpose
  `service-issuance`, with only `registry:fee-bill:create` and
  `registry:paid-service:issue`.
- `secrets/service-coordinator-token`: client `service-coordinator`, purpose
  `service-orchestration`, with only `registry:fee-bill:read`.

These are synthetic acceptance credentials, not deployment credentials. The
helper generates a run-local Ed25519 key and static JWKS, writes every key and
token owner-only, and issues JWTs for at most 7,200 seconds. Tokens bind the
configured issuer and audience plus `client_id`, `sub`, `jti`,
`registry_actor_kind`, `registry_principal`, `registry_purpose`, and the exact
space-separated `scope` claim. The Coordinator receives no bind or receipt
scope. The runtime additionally probes that its credential sees both Adapter
Action routes as `404 resource.not_found` and that an unauthenticated caller
receives `401`.

The schema test uses additional one-scope token files for each Action profile,
so every journey step proves its declared authority without relying on a
broader combined runtime credential.
