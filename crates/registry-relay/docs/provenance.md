# Relay credential issuance migration

Registry Relay no longer issues response credentials, hosts DID documents, publishes credential schemas or JSON-LD contexts, or manages issuer signing keys. Registry Notary is the sole credential issuance and verification surface.

Remove these legacy Relay settings before upgrading:

- Top-level `provenance:` blocks.
- Entity-level `publicschema:` blocks.
- Relay runtime secrets that only fed response credential signing.
- Monitoring or smoke tests that fetch `/.well-known/did.json`, `/schemas/{claim_type}/{version}`, or `/contexts/{vocab}/{version}` from Relay.
- Client requests that send `Accept: application/vc+jwt` to Relay.

Relay now returns ordinary negotiated data formats for entity and aggregate reads. If a workflow needs a signed credential, use Registry Notary and its discovery metadata. Relay can still publish evidence offerings with `access.kind: registry-notary` so clients can find the Notary endpoint that owns issuance or verification.

If signed provenance over Relay responses is required again, the design should delegate issuance to Notary rather than reintroducing Relay-local signing keys.
