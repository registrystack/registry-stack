# Registry Platform Ops

Shared public operations contracts for Registry runtimes.

This crate packages versioned JSON Schemas, valid examples, redaction fixtures,
and the shared emit-only sensitivity-tier filter for admin-scoped posture
documents. It does not implement Relay or Notary endpoints and does not depend
on private control-plane or internal planning repositories.

Runtime services currently emit the default posture projection. The restricted
tier is a schema and fixture contract for future/admin-gated posture surfaces;
it documents fields that are valid in the contract but excluded from default
runtime output.

## Assets

- `schemas/registry.ops.posture.v1.schema.json` defines the shared posture
  envelope, artifact reference shape, finding shape, and `posture.audit`
  summary shape.
- `examples/registry-relay.posture.valid.json` is a valid default Relay posture.
- `examples/registry-notary.posture.valid.json` is a valid default Notary
  posture.
- `fixtures/posture/default-allowlist.json` lists default-tier JSON pointers
  used by runtime emit-only posture generation.
- `fixtures/posture/redaction-input-sensitive.json` contains sensitive runtime
  source material used only to prove that default posture is built by allowlist.
- `fixtures/posture/default-redacted.posture.valid.json` is the expected
  default-tier emitted posture for the sensitive fixture.
- `fixtures/posture/restricted-posture.valid.json` is a valid restricted-tier
  fixture showing topology fields that must not appear in default posture.
- `schemas/registry.audit.ack_cursor.v1.schema.json` defines the local state
  file an off-host audit shipper writes on each successful hand-off
  (`acked_at`, `last_acked_hash`, optional `writer`). `evaluate_ack_health`
  safely reads and validates freshness; a runtime then calls
  `AckObservation::bind_to_audit_tail` before it may report `ok`. Fresh but
  unbound cursors remain `unverified`; stale, missing, unsafe, malformed, or
  mismatched cursors fail closed.
- `fixtures/audit/ack-cursor.valid.json` is a valid ack cursor fixture.
