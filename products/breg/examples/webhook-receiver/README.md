# Durable webhook acceptance example

This receiver uses the Python standard library, the public
[BReg webhook contract](../../EVENTS-AND-WEBHOOKS.md), and
`registry_client.breg.verify_hook_delivery` from the `registry-stack-client`
package. That function authenticates the signed CloudEvents with the shared
Rust verifier. The receiver then checks the expected registry/instance/event
contract and delivery-time bound, and commits exact event content and the
delivery binding to its own SQLite inbox before returning `204`. Storage
failure returns `503` for retry.

Install a `registry-stack-client` release whose `breg` namespace provides
`verify_hook_delivery`. Set the registry, instance, Record type, event ID and
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

## Forward a change to an external refresh plan

`refresh_hints.py` is an optional bridge for a receiving BReg deployment with a
managed external refresh plan. It uses the same signature verifier and checks
the exact compiled event schema, source registry and instance, event ID,
trigger, and projected field names before opening an outbound connection.
Use one listener per reviewed event contract. Approve the event's subject
scope and selector disclosure at the source, and authorize the bridge's own
service client on the receiving plan and projection.

For a Person correction, place this hook under the source Person Record type.
The acquisition operation must accept the projected `person-key` in the
configured selector scheme.

```yaml
hooks:
  - id: person-corrected-v1
    phase: after
    trigger: patched
    projection: [person-key]
    when:
      type: fields
      changed: [family-name]
    handler:
      type: url
      destinationId: person-refresh-notifier
```

Run `bregctl hook sample PROJECT --event person-corrected-v1` and take the
schema digest from the end of the `ce-dataschema` header. Bind the source
destination to the listener's `/events` path. The listener uses loopback, so
deployments with a remote source need their own ingress with a bounded
request timeout.

```sh
python3 products/breg/examples/webhook-receiver/refresh_hints.py \
  --registry-id example-registry --instance-id local --record-type person \
  --event-id person-corrected-v1 --trigger patched --schema-digest SCHEMA_DIGEST \
  --selector-field person-key --key /path/to/webhook-key \
  --destination-origin https://receiving-registry.example \
  --plan licensing-holders --projection person-indexed \
  --selector-scheme urn:example:person-number \
  --token-file /path/to/notifier-token --hint-id-key /path/to/hint-id-key \
  --port 8090
```

Use owner-only files for the source signing key, the receiving service's
bearer token, and a separate random key of at least 32 bytes for deriving
hint IDs. Keep the hint ID key stable across receiver restarts and source key
rotation. The bridge reads the token on each delivery so the operator can
renew it by replacing the owner-only file. HTTPS uses the system trust store.
Plain HTTP is supported for a numeric loopback origin in a local test.

The bridge forwards the plan's projection, selector scheme, approved
selector and opaque hint ID to the receiving BReg. It keeps no event inbox
and returns `204` only after every hint receives `202 Accepted`. If a request
fails, the bridge returns `503` and the source can retry with the same hint
IDs, including after a response is lost. The receiving BReg deduplicates
accepted IDs within its replay retention window. Acknowledgement confirms
queue admission. The plan worker independently checks eligibility and
acquires the current source value. Monitor source dead letters when
admission failures outlast the source's retry window.

For a holding move, configure two `--selector-field` options only when the
approved event explicitly projects both previous and current parent
selectors. The bridge submits one hint per distinct parent. An ordinary
BReg Record webhook projects post-change values. Use the current parent
field for that contract and let the scheduled sweep reconcile the previous
parent. Send events when the change is visible through the acquisition
operation, and retain scheduled sweeps to reconcile missed notifications.

The same test command exercises the bridge with a signed Person correction
and a two-parent move against a loopback admission fixture. It covers
signature and schema refusal, field allowlisting, partial delivery, lost
responses, and redaction.
