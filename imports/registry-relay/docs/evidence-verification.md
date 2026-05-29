# Registry Notary Discovery

Registry Relay no longer verifies claims or evidence. Relay exposes registry data from configured file and PostgreSQL sources and publishes evidence offering metadata for discovery.

The only evidence offering routes in Relay are:

```http
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
```

Evidence offering metadata must point to Registry Notary with `access.kind: registry-notary`. Clients submit claims and evidence to the advertised Notary endpoint or discovery document. Relay does not compute claim hashes, make verification decisions, issue evidence verification receipts, or expose `POST /evidence-offerings/{offering_id}/verifications`.

The `evidence_verification` scope remains available as a distinct label for standards adapters and integrations that need evidence-oriented access. It does not grant metadata, rows, aggregates, admin reload, or a Relay-local verification endpoint.
