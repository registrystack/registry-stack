# Durable webhook acceptance example

This receiver uses the Python standard library, the public
[BReg webhook contract](../../EVENTS-AND-WEBHOOKS.md), and
`registry_client.breg.verify_webhook_delivery` from the `registry-stack-client`
package. That function authenticates the signed CloudEvents with the shared
Rust verifier. The receiver then checks the expected registry/instance/event
contract and delivery-time bound, and commits exact event content and the
delivery binding to its own SQLite inbox before returning `204`. Storage
failure returns `503` for retry.

Install a `registry-stack-client` release whose `breg` namespace provides
`verify_webhook_delivery`. Set the registry, instance, Record type, event ID and
repeated `--field` names to those of your configured webhook. Supply the same
raw HMAC key bytes used by the runtime destination in an owner-only key file.
Use an owner-only directory for the inbox, then run:

```sh
python3 products/breg/examples/webhook-receiver/receiver.py \
  --registry-id example-registry --instance-id local --record-type contact \
  --event-id contact-created-v1 --field name --key /path/to/key \
  --inbox /path/to/private-state/inbox.sqlite3 --port 8090
```

The listener binds only `127.0.0.1`; its destination path is `/events` and
readiness path is `/ready`. Configure the BReg destination separately. This
example does not provision a registry, issuer, runtime, or destination.

CloudEvents source and event ID identify one accepted work item across receiver
restart. A retry preserves that identity. Operator replay preserves the event
but uses a new delivery generation and idempotency key, so acceptance records
the delivery without duplicating work. Changed content or a rebound delivery
key returns `409`. Distinct events describing the same business effect still
need application-level operation identity and deduplication.

The inbox contains projected values. This example retains them until you
remove the inbox, so use synthetic data. Adopting services own processing,
retention, reconciliation and monitoring. Durable acceptance does not prove
completion of an external effect. Delivery grants no registry authority and
may arrive out of order; read or write current records with a separately
authorized client through the ordinary API.

Run the behavioral tests from a source checkout with:

```sh
python3 products/breg/examples/webhook-receiver/test_receiver.py -v
```

The tests build the in-tree `registry-breg-client-py` binding with Cargo and
load it as `registry_client.breg`, so they need no installed package. On macOS,
first prepare the AWS-LC FIPS runtime library path as
[`crates/CLIENTS.md`](../../../../crates/CLIENTS.md) describes for Python
bindings. `sign_delivery.py` is the standard-library sender side of the
signature, used only to produce synthetic requests. The tests send signed
requests through a temporary loopback listener and exercise durable acceptance,
retry across restart, replay identity, conflicting duplicates,
authentication/time/source refusals and storage recovery.
