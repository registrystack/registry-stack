# Relay credential issuance migration

Registry Relay no longer issues response credentials, hosts DID documents, publishes credential schemas or JSON-LD contexts, or manages issuer signing keys. Registry Evidence is where a caller gets a signed, minimum-disclosure answer it can verify later.

Remove these legacy Relay settings before upgrading:

- Top-level `provenance:` blocks.
- Entity-level `publicschema:` blocks.
- Relay runtime secrets that only fed response credential signing.
- Monitoring or smoke tests that fetch `/.well-known/did.json`, `/schemas/{claim_type}/{version}`, or `/contexts/{vocab}/{version}` from Relay.
- Client requests that send `Accept: application/vc+jwt` to Relay.

Relay now returns ordinary negotiated data formats for entity and aggregate reads. If a workflow needs a signed answer, use Registry Evidence and its discovery metadata. Relay can still publish evidence offerings with `access.kind: registry-evidence` so clients can find the Evidence endpoint that owns the assertion.

If signed provenance over Relay responses is required again, the design should delegate signing to Evidence rather than reintroducing Relay-local signing keys.
