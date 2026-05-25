# Registry Witness Discovery

Registry Relay no longer verifies claims or evidence. Relay exposes registry data from configured spreadsheet-backed sources and publishes evidence offering metadata for discovery.

The only evidence offering routes in Relay are:

```http
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
```

Evidence offering metadata must point to Registry Witness with `access.kind: registry-witness`. Clients submit claims and evidence to the advertised Witness endpoint or discovery document. Relay does not compute claim hashes, make verification decisions, issue evidence verification receipts, or expose `POST /evidence-offerings/{offering_id}/verifications`.
