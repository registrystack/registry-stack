# Durable webhook acceptance example

Run the existing [webhook demo](../README.md) with
`products/breg/demo/run.sh --webhook --smoke`. Its loopback receiver uses the
Python standard library and the public
[BREG webhook contract](../../EVENTS-AND-WEBHOOKS.md). The implementation is in
[`demo.py`](demo.py), in `WebhookInbox`, `WebhookReceiver`, and
`serve_webhook_receiver`.

The receiver verifies the exact signed request and delivery-time bound before
acceptance. For an accepted request it commits the immutable CloudEvents
attributes and exact projected body to a receiver-owned SQLite inbox, together
with a delivery-key and generation binding, before returning `204`. A storage
failure returns `503`, leaving BREG responsible for its bounded delivery
retries. The existing synthetic
refusals still demonstrate automatic retry, dead-letter inspection, and replay.

The CloudEvents source and event ID identify one accepted work item, including
after receiver restart. `Idempotency-Key` separately identifies one delivery
generation. BREG operator replay keeps the event identity but supplies a new
generation and key. The receiver records that delivery binding and acknowledges
the existing work item, preventing duplicate work when earlier acceptance
responses were lost. A replay that was never accepted creates its first work
item. Changed event content or a reused delivery key with a different binding
is refused with `409`. Distinct events that describe the same business effect
still require the application's own operation identity and deduplication.

The inbox is `webhook-inbox.sqlite3` inside the demo run directory and has
owner-only file permissions. Unlike the value-free JSON attempt report, this
file contains the event's projected values. Both files survive receiver
restart. This disposable example retains its inbox until the run directory is
removed or replaced by the next demo run; it has no payload expiry or background
processing. Use synthetic records and follow the demo's
[disposable-state lifecycle](../README.md#disposable-state). BREG's
successful-delivery payload erasure does not erase the recipient's copy.

An acknowledgement demonstrates durable acceptance by the recipient. It does
not demonstrate completion of an external effect. An adopting service owns
processing, retention, monitoring, reconciliation, and any downstream
idempotency. Before acknowledging, it can instead durably enqueue the verified
event in a queue or workflow service it already operates. Do not acknowledge
first and enqueue later.

The event neither grants registry access nor carries approval authority. If
the recipient later needs current records or writes a result back, use a
separately authorized BREG client and the ordinary public API with its current
authorization, revision, and idempotency requirements. Delivery can be out of
order, so captured state is not a current-state check. The receiver does not
access BREG's database or private outbox.

Verify the acceptance boundary with:

```bash
python3 products/breg/demo/support/test_demo.py WebhookAcceptanceTests -v
```

These tests use temporary loopback listeners and disposable SQLite files. They
exercise authenticated acceptance, duplicate delivery across process restart,
operator replay identity, conflicting duplicates, invalid authentication, and
storage refusal followed by recovery.
