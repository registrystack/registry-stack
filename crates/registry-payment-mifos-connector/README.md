# Mifos Payment Hub EE legacy connector

This crate is a bounded HTTP client for one explicit legacy Payment Hub EE
profile:

- P2G collection: `ph-ee-connector-channel` v1.12.2
- G2P raw batch submission: `ph-ee-bulk-processor` v1.12.1
- authoritative provider observations: `ph-ee-operations-app` v1.17.1

These components are independently versioned. The profile does not mean that a
deployment called “PH-EE 2.0” implements the same wire contract. In particular,
the unreleased `paymenthub-ee-*` development branches changed bulk fields from
`subType` to `paymentMode` and added other fields. Operators must pin and verify
the deployed component images or source commits.

## Boundary

The public client supports:

- `POST /channel/collection`, with the released two-payer collection body;
- `GET /api/v1/transactionRequests`, read directly from operations rather than
  the channel `txnState` adapter that collapses most states to `RECEIVED`;
- `POST /batchtransactions` with `Type: raw` and exactly one v1.12.1
  instruction;
- `GET /api/v1/batch/detail` with a page size of two, requiring exactly one
  operation whose batch, correlation, funding party, recipient, exact amount,
  and currency match the submitted instruction.

Amounts remain decimal strings. Comparisons normalize only decimal spelling,
without binary floating-point conversion. A future or unrecognized provider
state becomes `PaymentState::Unknown`, never success or failure. Missing or
changed identity, amount, currency, or G2P destination fails closed as a
protocol error.

Submission is asynchronous. `SubmissionState::Accepted` means only that the
provider returned the pinned acknowledgement. `PaymentState::ProviderConfirmed`
means only that operations reported `SUCCESS` for a collection or `COMPLETED`
for a transfer. The inspected source does not prove inter-provider settlement,
beneficiary credit, or end-to-end reconciliation, so this crate makes none of
those claims.

Every mutation is attempted once. A timeout, connection failure, oversized
answer, unexpected status, or malformed acknowledgement after dispatch returns
`ConnectorError::OutcomeUnknown`. The connector never automatically submits a
replacement. PH-EE's optional bulk deduplication worker removes duplicate
instructions within a batch. It is not strong request-level idempotency for a
repeated `X-CorrelationID`, and the inspected operations schema does not impose
a uniqueness constraint on client correlation.

## Offline fixture replay

The crate exposes pure `build_*` and `parse_*` functions for an operator CLI to
replay provider-pack fixtures without making a network call:

- `build_collection_request` and `parse_collection_acceptance`;
- `parse_collection_status`;
- `build_batch_request` and `parse_batch_acceptance`;
- `parse_batch_status`.

A fixture should pin `CONNECTOR_PROFILE`, name direction as `p2gCollection` or
`g2pDisbursement`, carry the typed command, provider HTTP status where the
acknowledgement has multiple released forms, provider body, and exact expected
request body and state. Replay should compare request JSON structurally, reject
another profile rather than guessing a compatible version, and compare the
closed `PaymentState`. Fixture bodies are provider data and must remain
synthetic and non-secret.

## Authentication and deployment inputs

Released PH-EE deployments differ:

- channel and operations have authorization disabled by default in their
  released configuration, but can be placed behind bearer-JWT authorization;
- bulk uses connector-common JWS in the released configuration and receives a
  tenant-specific `X-SIGNATURE`;
- ingress TLS, tenant routing, BPMN workflows, scheme connectors, and internal
  component authorization are deployment configuration.

The crate therefore accepts only a bounded bearer token and/or precomputed
`X-SIGNATURE` at the individual send boundary. It does not hold signing keys,
mint tokens, accept arbitrary headers, persist credentials, or infer that
header presence proves authentication. Production endpoints must use HTTPS;
cleartext HTTP is allowed only for loopback protocol doubles. Response bodies
are limited to 64 KiB, redirects are disabled by the shared outbound client,
and errors contain no response, credential, party, or endpoint values.

The released bulk processor v1.12.1 depends on connector-common
`1.8.1-SNAPSHOT`; the matching connector-common v1.8.1 source is pinned here
as the `ph-ee-connector-common/v1.8.1:rsa-cipher-sha3-256/v1` profile. Despite
the upstream “JWS” name, this is not JOSE, compact JWS, or RS256. The released
code joins the values of present headers in configured order with `:`, appends
the exact UTF-8 body, hashes that string with SHA3-256, renders lowercase hex,
then passes those 64 ASCII bytes to Java's default RSA cipher with a private
PKCS#8 key. Its configured header order is `X-BatchID`, `X-CorrelationID`,
`Platform-TenantId`. This connector's raw batch request has no `X-BatchID`, so
the request input is correlation, tenant, and exact request body in that order.

`legacy_signature_preimage`, `legacy_signature_digest`, and
`legacy_batch_request_signature_digest` expose that exact pure boundary.
`LegacyWebSignatureSigner` and `LegacyWebSignatureVerifier` let the host bind
an audited secret-backed raw-RSA implementation without giving this connector
key custody. A normal Registry Stack `SigningProvider` is not compatible: it
produces standards-based signatures with a named digest and encoding. The
legacy provider must perform the exact released private-key operation and emit
standard padded Base64. A signer must sign the digest derived from the same
bytes sent on the wire. A verifier must derive the response digest from the
exact bounded response bytes and only the response headers actually present,
then require exactly one `X-SIGNATURE` and a matching tenant header.

The built-in client presents a request signature but does not verify PH-EE's
optional response `X-SIGNATURE`. HTTPS server authentication is therefore part
of this profile's trust boundary. A deployment that requires application-layer
response-signature verification must verify the exact response bytes and its
configured signed-header order before calling the pure parsers. This limitation
must not be described as end-to-end JWS protection.

The released response filter catches signing failures and still copies the
body to the response. A deployment configured to require response signatures
must therefore fail closed on an absent, repeated, malformed, or mismatched
signature. The pure verifier interface does not change the current client's
request-only behavior until the embedding host wires such a required verifier.

## Primary sources and evidence limits

Pinned interfaces and models:

- [channel collection API v1.12.2](https://github.com/openMF/ph-ee-connector-channel/blob/v1.12.2/src/main/java/org/mifos/connector/channel/api/definition/CollectionApi.java)
- [channel collection DTO v1.12.2](https://github.com/openMF/ph-ee-connector-channel/blob/v1.12.2/src/main/java/org/mifos/connector/channel/model/CollectionRequestDTO.java)
- [channel workflow route v1.12.2](https://github.com/openMF/ph-ee-connector-channel/blob/v1.12.2/src/main/java/org/mifos/connector/channel/camel/routes/ChannelRouteBuilder.java)
- [bulk API v1.12.1](https://github.com/openMF/ph-ee-bulk-processor/blob/v1.12.1/src/main/java/org/mifos/processor/bulk/api/definition/BatchTransactions.java)
- [bulk raw request DTO v1.12.1](https://github.com/openMF/ph-ee-bulk-processor/blob/v1.12.1/src/main/java/org/mifos/processor/bulk/schema/BatchRequestDTO.java)
- [operations transaction requests v1.17.1](https://github.com/openMF/ph-ee-operations-app/blob/v1.17.1/src/main/java/org/apache/fineract/api/OperationsDetailedApi.java)
- [operations batch detail v1.17.1](https://github.com/openMF/ph-ee-operations-app/blob/v1.17.1/src/main/java/org/apache/fineract/api/BatchApi.java)
- [operations transfer entity v1.17.1](https://github.com/openMF/ph-ee-operations-app/blob/v1.17.1/src/main/java/org/apache/fineract/operations/Transfer.java)
- [operations transaction-request states v1.17.1](https://github.com/openMF/ph-ee-operations-app/blob/v1.17.1/src/main/java/org/apache/fineract/operations/TransactionRequestState.java)
- [connector-common v1.8.1 request interceptor](https://github.com/openMF/ph-ee-connector-common/blob/v1.8.1/src/main/java/org/mifos/connector/common/interceptor/WebSignatureInterceptor.java)
- [connector-common v1.8.1 signing input](https://github.com/openMF/ph-ee-connector-common/blob/v1.8.1/src/main/java/org/mifos/connector/common/interceptor/JWSUtil.java)
- [connector-common v1.8.1 hash and RSA cipher](https://github.com/openMF/ph-ee-connector-common/blob/v1.8.1/src/main/java/org/mifos/connector/common/util/SecurityUtil.java)
- [connector-common v1.8.1 signer/verifier service](https://github.com/openMF/ph-ee-connector-common/blob/v1.8.1/src/main/java/org/mifos/connector/common/interceptor/service/JsonWebSignatureService.java)
- [connector-common v1.8.1 response filter](https://github.com/openMF/ph-ee-connector-common/blob/v1.8.1/src/main/java/org/mifos/connector/common/interceptor/JWSFilterStrategy.java)
- [bulk processor v1.12.1 dependency pin](https://github.com/openMF/ph-ee-bulk-processor/blob/v1.12.1/build.gradle)
- [bulk processor v1.12.1 signature enablement](https://github.com/openMF/ph-ee-bulk-processor/blob/v1.12.1/src/main/resources/application.yaml)

The crate tests protocol mapping with loopback doubles only. They do not call a
money-moving provider, execute BPMN, prove a deployed image matches its claimed
source, prove an ingress or certificate configuration, or prove beneficiary
credit. Before operating a deployment, verify its exact image digests, enabled
authentication and JWS rules, tenant and workflow configuration, scheme
connector, operations ingestion, and status behavior with synthetic accounts.

The v1.12.1 build uses the mutable Maven coordinate
`ph-ee-connector-common:1.8.1-SNAPSHOT`, and connector-common calls
`Cipher.getInstance("RSA")` without naming the transformation. The v1.8.1 tag
and a Temurin Java 17 synthetic vector pin source-compatible behavior, but they
do not prove which connector-common artifact or JVM provider a particular
deployment ran. Verify one synthetic signed request and response against the
exact deployed image before enabling this legacy profile.
