# Registry Evidence OID4VP

`registry-evidence-oid4vp` is a supporting service beside Registry Evidence. It runs the wallet-facing OpenID4VP 1.0 exchange and holds a received presentation in memory until Evidence reads it; Evidence verifies the credential and signs the assertion (`products/evidence/CONCEPT.md` section 15.10).

## Reads consume the result

`POST /v1/presentations/read` releases a terminal result, a presentation or a wallet error, once. The first successful read (200, or the 422 that reports a wallet error) consumes it and releases its held bytes; any later read of the reference is the same 404 as an unknown or expired reference. A read that does not succeed (authentication, rate limit, unknown reference, principal mismatch, session still pending, audit unavailable) consumes nothing. Two concurrent reads yield exactly one result. A read is not retried safely after delivery: if Evidence loses the response, the portal creates a new session. The audit record of a delivering read has the outcome `delivered_and_consumed` (`failed_and_consumed` for a wallet error).

## Readiness and the client identifier certificate

`/ready` reports not ready (503) when the audit destination is unavailable or a client identifier certificate is past its `notAfter` by the service clock, because wallets refuse every request object signed under it. The service logs one warning per identifier at that transition, naming the identifier and nothing of the certificate. Replace the certificate and restart; the leaf is checked for validity at load only.

## Rate limiting per source

The limiters for `GET /v1/requests/{request_id}` and `POST /v1/responses/{request_id}` use one key for all wallets, so they bound the service as a whole and cannot tell one client from another: one source can exhaust the budget for everyone. A deployment must rate limit per source address at its ingress in front of those two paths. The service sees no stable wallet identity to key on.
