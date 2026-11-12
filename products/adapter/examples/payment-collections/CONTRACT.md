# First P2G payment contract

The in-source `payments/v1` host contract supports synthetic fee collection,
exact receipt reporting and payment-gated service issuance. It does **not**
claim conformance to `payments-capability-v1` in Registry Service Composition,
or general GovStack Payments conformance. The simulator's wire profile is
separate from this service-facing contract.

BReg owns the bill, frozen tariff and single-use issuance gate. Adapter owns
provider identifiers, durable attempts, original connection snapshots and
prepared bind/receipt commands in PostgreSQL. Coordinator owns workflow state
and bounded observation through the named `collection` completion. Provider
acceptance, payment confirmation and a recorded registry receipt are distinct
facts.

## HTTP and native operations

All routes require an admitted OIDC client and the connection's configured
scope. Retained attempts also require their original issuer, client and
subject, and the current connection's institution/service scope. Caller-supplied
amounts, provider outcomes, tenant/biller routing and Action names are refused.

| Operation | HTTP route below `/v1/payments/{connection}` | Input | Success |
| --- | --- | --- | --- |
| `payments.request-collection/v1` | `POST /collections` | `billId`, positive `billVersion`; `Idempotency-Key` header | 202, durable collection identity after provider acceptance |
| Recovery lookup | `POST /collections/receipt` | Original request and key | 200 if acceptance is known; lookup never dispatches |
| `payments.read-collection/v1` | `GET /collections/{collectionId}` | Collection identifier | 200 with exact identity, money and current validated state |
| `payments.record-receipt/v1` | `POST /collections/{collectionId}/record-receipt` | Matching `collectionId`; `Idempotency-Key` header | 200 only after exact BReg receipt readback |

`adapterctl payments contract FILE` exports these routes and the generated
wire schemas. `registry-payment-protocol` owns the DTOs and the bounded problem
vocabulary; `registry-payment-client` validates responses before exposing them
to Coordinator. JSON Schema checks structural bounds. Runtime checks also
enforce currency scale, portable integer limits, exact correlation and evidence
consistency.

## Relationship to payments-capability-v1

The earlier [composition capability contract](https://github.com/registrystack/registry-service-composition/blob/main/docs/capabilities/payments.md)
contains 31 numbered rules. This table records the first slice's behavior and
differences, rather than certifying that contract. Source and focused regression
coverage are not a substitute for a joined native runtime acceptance run.

| Rule | First slice |
| --- | --- |
| 1 | Exact decimal-string `Money` with currency and scale. |
| 2 | Integer minor-unit conversion and exact JSON-number serialization, without binary floating point. |
| 3 | Positive amounts, configured scale, decimal precision and portable integer bounds are enforced. |
| 4 | Bill currency/scale must match the operator's connection policy. The fixture freezes a service-owned synthetic tariff; it does not model a tariff registry. |
| 5 | All bindings must declare `simulation: true`. No live or XTS-specific mode exists. |
| 6 | Source bill UUID/version remain unchanged. Bounded provider identifiers are derived separately. |
| 7 | Provider identifiers live in Adapter PostgreSQL. BReg stores the attempt ID and binding revision, not the provider's wire identifiers. |
| 8 | Domain-separated SHA-256 binds bounded provider identifiers to the full immutable bill and provider origin/producer/tenant/biller. Disjoint digest portions supply request, RTP and bill identifiers independently of the Adapter database. Source UUIDs are never truncated. |
| 9 | Provider transfer identity is durably stored before acceptance is exposed. |
| 10 | Confirmation requires a bounded `SIM-` reference. The connector does not independently enforce reference inequality with the transfer identifier. |
| 11 | One attempt per bill version, permanently, including after failure. |
| 12 | Confirmed and failed observations are terminal. Provider expiry maps to `failed` with `request-expired`, rather than a separate state. |
| 13 | Reissue/replacement after decline or expiry is outside this slice. No release/rebind Action is provided. |
| 14 | The permanent reservation is stronger than an active-attempt-only limit. BReg also binds the attempt atomically before dispatch. |
| 15 | Paid/issued bills cannot start a collection. The fixture also prevents another bill for the same institution/service/request. |
| 16 | Full bill/provider/connection snapshots and exact prepared binding are persisted before dispatch; binding readback must match. |
| 17 | Recovery reuses the original exact command only within its original declared replay window. Replay is never unconditional. |
| 18 | Missing acceptance remains unknown; elapsed replay windows remain held. Operator recovery has no automated replacement operation or configurable named-owner field. |
| 19 | Replays retain the original command. Provider conflicts or invalid acknowledgements remain uncertain and never authorize a fresh attempt. |
| 20 | Reads use the persisted transfer identity and store each validated observation before returning it. |
| 21 | Coordinator owns the observation deadline/budget. Adapter has no autonomous polling loop. A workflow timeout cannot issue a receipt. |
| 22 | Timeouts never manufacture a failed or expired payment. |
| 23 | Invalid or contradictory status responses return a protocol error and retain the last valid observation. They do not overwrite it with a fabricated terminal state. |
| 24 | Lost receipt acknowledgements recover through the original prepared command/key or exact matching bill, binding, money, reference and receipt digest. A paid flag alone is insufficient. |
| 25 | No failure Action is called. Pending, failed and unknown states stay in the Adapter journal, and the BReg bill remains bound/unpaid. |
| 26 | Only the restricted BReg receipt Action can mark the bill paid. The Adapter cannot waive it or change its frozen amount. |
| 27 | Confirmation checks all source/provider correlations, exact amount/currency and the synthetic payment reference. |
| 28 | Provider `COM/PENDING` remains pending. |
| 29 | `simulation: false` and non-loopback simulator origins are refused. The host does not read composition environment labels. |
| 30 | Provider and BReg credentials come from secret references. Persisted attempts retain references and logical identities, never credential values. |
| 31 | The fixture grants the Adapter only exact bind/receipt Actions and bill readback; it grants Coordinator no reporting Action. There is no failure Action in this slice. |

Attempts and command receipts currently have no automatic expiry. Original
provider/registry origins, tenant, biller and credential references remain
attached to retained attempts when configuration changes. Operators must keep
those bindings and protected database backups available for recovery. A new
configuration cannot redirect an existing financial command.

The provider request identifier has 72 digest bits, the wire bill identifier
has 56, and the positive RTP identifier has 52, within their respective wire
bounds. The provider must reject a reused request identifier with a different
body. The host verifies the complete saved command against its bill and
provider namespace before use; a partial identifier match never establishes
payment of another bill.

This unreleased slice does not migrate the earlier sequence-based development
snapshots. They fail integrity validation and stay held, with their original
commands intact. Preserve such disposable development databases and their
matching build for inspection; run the current synthetic fixture in a fresh
database. Do not rewrite or resend retained attempts under derived identifiers.
