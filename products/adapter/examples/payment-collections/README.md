# Payment collection and G2P configuration

The baseline `payments.example.yaml` combines the Adapter payment host with the maintained
[service-fee BReg project](../../../breg/examples/payment-fee-issuance/README.md).
The first provider is the repository's [P2G simulator](../../../../tools/payment-simulator/README.md).
It does not accept real payments or claim general GovStack Payments conformance.
The [contract and capability comparison](CONTRACT.md) names the exact HTTP
surface, ownership and differences from the earlier composition capability.
The separate `payments.mifos.example.yaml` adds an authoritative G2P
disbursement connection pinned to the public `mifos-payment-hub` pack. It is
an operator configuration example, not evidence of a live Mifos deployment.

A service creates the authoritative bill. The Coordinator workflow then uses
native payment operations:

1. `payments.request-collection/v1` supplies `billId` and `billVersion` and
   waits for the named `collection` completion.
2. `payments.read-collection/v1` can explicitly read the collection when
   needed. Reads never start a payment or record a receipt.
3. `payments.record-receipt/v1` supplies only `collectionId`. The Adapter
   derives and reports the exact confirmed receipt to the restricted BReg
   Action. The service can then invoke `issue-paid-service` with the bill,
   expected version, request, saved receipt and issuance identifiers.

The request's named completion polls the provider through the Adapter, so an
ordinary workflow does not need to author its own polling loop. See the
[Coordinator operation catalog](../../../coordinator/generated/operations/README.md)
and [connection setup](../../../coordinator/DEPLOYMENT.md).

## Bind the connection

Copy `payments.example.yaml` and `runtime.example.yaml` into the operator's
configuration directory for the simulator-only baseline. Copy
`payments.mifos.example.yaml` instead when configuring the mixed P2G and G2P
deployment. The resulting `payments.yaml` binds each service to its provider
and registry. Its caller policy must agree with the shared runtime's OIDC
issuer, audience and admitted clients. Its currency and scale must agree with
the authoritative bill or disbursement instruction.

The provider token identifies the synthetic producer. The BReg token belongs
to `payment-adapter`, with `registry:payment-attempt:bind` and
`registry:payment-receipt:report` scopes and `payment-processing` purpose.
Keep that credential separate from Coordinator and citizens. The example
names secret references, never token values. The runtime supervisor must
renew externally supplied bearer tokens at those references; the host
resolves them on each exchange. Rotation must preserve the original logical
provider or registry identity.

The disbursement binding separates the two released Mifos roles. Bulk POSTs
carry no bearer token: Adapter signs the exact retained body, tenant and
correlation through the configured Transit key, then verifies the signed Bulk
response through the distinct response key. Operations GETs carry the separate
`operationsCredentialRef` bearer token and host-owned tenant and correlation
headers. Released Operations v1.17.1 permits `/api/v1/**` by default unless
route authorization is enabled, so the deployment must enable and verify
bearer authorization or enforce it at a trusted gateway. The status response
is not signed; Adapter treats it only as a bounded provider report and compares
its batch, correlation, amount, currency, funding party and recipient with the
retained BReg instruction before reporting confirmation.

Replace the example Transit SPKI digests, key versions, key names, socket path,
origins and secret references with deployment-owned values. The socket must be
an absolute local Unix socket protected by ACLs and a trusted proxy policy.
The host validates the pinned key metadata at startup and never receives
private key bytes. Repository tests use a fake Transit endpoint and do not
establish live OpenBao `/none` plus `prehashed` interoperability.

Build matching `adapter` and `adapterctl` binaries from this checkout, using
the repository's external Cargo target directory. Check the configuration
against the exact pack pinned in `providerPack`, without resolving credentials
or contacting a provider. The pack path must contain bytes whose id, version
and digest match that pin:

```sh
adapterctl payments check /absolute/path/payments.mifos.yaml \
  --provider-pack /absolute/path/mifos-payment-hub/pack.yaml
adapterctl --format json payments contract /absolute/path/payments.mifos.yaml \
  --provider-pack /absolute/path/mifos-payment-hub/pack.yaml
```

Start the payment-only host with the configured PostgreSQL and OIDC service:

```sh
adapter serve --runtime-config /absolute/path/runtime.yaml \
  --payments-config /absolute/path/payments.yaml
```

Pass the same `--payments-config` beside an existing `--project` to share a
record facade's listener and database. Payment routes have their own fixed
contract; they do not require a record profile or a generic HTTP workflow
step. `adapter effective-contract` exports the record-facade contract;
`adapterctl payments contract` exports the payment module's routes and schemas.

## Grant the payment tables

The configured migration role creates the payment tables at startup. If the
runtime role differs, grant it the following privileges after migration and
restart the host. Startup refuses missing grants before binding the listener.
Replace `payment_adapter_runtime` with the operator's runtime role.

```sql
GRANT SELECT, INSERT, UPDATE ON adapter_payment_attempts TO payment_adapter_runtime;
GRANT SELECT, INSERT ON adapter_payment_commands, adapter_payment_events TO payment_adapter_runtime;
GRANT USAGE, SELECT ON SEQUENCE adapter_payment_events_sequence_seq
  TO payment_adapter_runtime;
```

Production builds retain the shared Adapter PostgreSQL TLS requirement. The
`postgres-test` feature permits explicitly configured plaintext only for
isolated test databases.

## Recovery and current limits

Before dispatch, the host reserves the attempt and verifies BReg's atomic
bill binding. Duplicate workflow runs with different command keys reuse the
same attempt for that bill version. A changed request under a spent key is
refused. COM/PENDING and unknown observations never release the service.

A lost provider response retains the original exact command, tenant, biller
and connection revision. Recovery may resend only inside the original replay
window. After that window, the attempt remains held. A changed connection
config applies to new attempts; it does not redirect retained ones.

G2P Bulk sends are never replayed. If the first response is lost, the attempt
stays held because no accepted batch reference exists for the Operations
status query. An operator must reconcile it with the provider; an unknown send
cannot become a failure or authorize a fresh submission. After a signed Bulk
acceptance supplies the retained batch reference, status recovery is read-only
through the Operations bearer path.

The host persists bind and receipt commands before sending them. A lost BReg
acknowledgement is recovered through the same command/key or exact bill and
receipt readback. A paid flag alone is insufficient. Every lookup remains
bound to the original authenticated caller and the currently permitted
connection/service scope.

This slice permits one attempt per bill version, including after a definitive
failure. There is no replacement-attempt operation, refund, settlement,
callback handler or live-provider connector. Attempts and command receipts
have no automatic expiry; they contain restricted bill/payer facts needed for
recovery and require protected database storage and backup. Generic facade
retention does not erase these records.

The focused `payment_service` PostgreSQL tests exercise recovery using
controlled registry/provider ports and a real database. They are separate
from the actual BReg fixture journey and a joined runtime acceptance run;
passing those focused tests alone does not establish a live integration.

## Run the native acceptance

Use an owned loopback PostgreSQL cluster with TLS and a trusted CA, normal
`breg`, `bregctl`, `adapter`, `adapterctl`, `coordinator`, and `coordinatorctl`
binaries from the same checkout, Node, `psql`, and the simulator's locked `uv`
environment. Build into the repository's required external Cargo target.
The native run does not use `postgres-test` or bypass package activation.

First run the [BReg fixture helper](../../../breg/examples/payment-fee-issuance/README.md#native-acceptance-and-runtime-handoff)
with its documented binary, database, CA, and private-directory inputs. Set
`PAYMENT_FEE_KEEP_RUNNING=1` in a retained terminal or supervised session,
and run the joined acceptance separately while BReg stays live. Retain its
`handoff.json`. Store the
loopback PostgreSQL admin URL in a private file readable only by the operator.
Then, from the repository root:

```sh
node products/adapter/scripts/test-payment-native.mjs \
  --fixture /absolute/private/breg-run/handoff.json \
  --bin-dir /absolute/external/cargo-target/debug \
  --simulator-bin /absolute/private/simulator-venv/bin/payment-simulator \
  --admin-url-file /absolute/private/postgres-admin-url \
  --ca-file /absolute/private/postgres-ca.crt \
  --build-record /absolute/private/payment-build-record.json \
  --state-dir /absolute/private/new-payment-acceptance-run
```

The state directory must be new. The runner creates fresh UTF8 databases and
separate migration/runtime roles, starts the actual simulator, Adapter and
Coordinator, and uses loopback relays to lose selected responses after the
upstream effect has happened. It checks original-binding recovery after
configuration changes, exact amount correlation, caller isolation, unpaid
issuance refusal, one receipt and one issuance, and the failed-attempt hold.
It also exercises Coordinator's native `reconcile`, named completion, and
`retry-same` against those processes, and verifies that extending configuration
cannot reopen an expired attempt's original replay window.
Two further fresh Adapter databases use the same provider namespace, payer
and amount for distinct BReg bills. The runner requires two provider requests,
distinct transfers and references, and separate authoritative receipts.

The private build record is an operator-supplied attestation, not independent
source-to-binary verification. It must contain a `binaries` object with `adapter`,
`adapterctl`, `coordinator`, and `coordinatorctl` entries, each with its actual
`sha256`. Include the source revision/content identity, Cargo command, features,
profile and toolchain used for each build; Cargo JSON compiler-artifact output
provides the actual profile and enabled features. Put the common build command
in `command`, the compiler details in `toolchain`, and `head` plus `patchSha256`
under `source`; each binary entry also records its `features` and `profile`.
Stage new source files before
running. The runner retains the current Git base, binary patch and per-file
source hashes, including the harness and simulator, for dirty-tree provenance.
It verifies the simulator's imported Python package content and retains the
BReg fixture's binary hashes and declared feature profiles separately. The
run-time source snapshot does not establish the build source of preserved
fixture binaries.

The runner stops its own services on exit. The BReg process remains owned by
its fixture launcher. Databases, roles, simulator state and private evidence
are retained for inspection. Only after all behavior and shutdown assertions
pass does the runner write `acceptance.json` with checks, source and binary
identities, command hashes and the synthetic provider ledger.
Tokens and database passwords are not included in that report. Logs and
credential files remain private under the supplied directory. This is a
synthetic integration proof. PostgreSQL uses TLS; service HTTP is numeric
loopback. It does not establish production transport, live-provider behavior
or full GovStack Payments conformance.
`progress.json` also preserves completed checks and safe command metadata
when a run fails, after the runner attempts to stop all its owned processes.
