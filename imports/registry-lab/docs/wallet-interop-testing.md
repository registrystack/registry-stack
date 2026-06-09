# Wallet interop testing

Page type: how-to guide
Product: Registry Lab, Registry Notary, OID4VCI
Layer: credential
Audience: integrators testing wallet interoperability

This guide explains how to test the citizen self-attestation OID4VCI facade
with real wallet software after the scripted Registry Lab probe passes.

The lab probe is still the first check:

```bash
just citizen-oid4vci-login
just citizen-oid4vci-code
```

or, with existing eSignet tokens:

```bash
ESIGNET_CITIZEN_ACCESS_TOKEN="<jwt-access-token>" \
ESIGNET_CITIZEN_ID_TOKEN="<jwt-id-token>" \
just citizen-oid4vci-token
```

That probe proves the wallet-neutral protocol surface: issuer metadata,
credential offer, nonce, holder proof, credential endpoint, source read,
credential issuance, and local evidence artifacts.

The OID4VCI facade currently targets Draft 13-style credential offers and
credential responses for wallet compatibility, plus a Final-style nonce endpoint
for wallets that require nonce retrieval before the credential request.

The lab intentionally writes raw demo evidence under `output/`, including
tokens, proof JWTs, issued credentials, and seeded civil identifiers such as
`NID-2001`. Treat those files as sensitive local replay/debug artifacts. They
are useful for learning and troubleshooting, but they must not be committed,
shared, or copied into public issue reports.

Real wallet testing adds wallet-specific behavior: offer parsing, holder DID
selection, authorization redirect handling, proof generation, credential
storage, and display.

## Preconditions

- Local eSignet is running and can authenticate the seeded adult citizen
  `NID-2001`, Maria Santos.
- Registry Relay civil fixtures are running.
- Registry Notary is started through the citizen OID4VCI flow.
- The wallet can reach the Notary issuer URL and eSignet authorization URL.
- The configured `credential_issuer`, `credential_endpoint`,
  `offer_endpoint`, and `nonce_endpoint` use the same externally reachable
  origin.

For a wallet running outside the host network, do not use `127.0.0.1` or
`localhost` in the issuer metadata. Use a stable HTTPS URL, for example a local
tunnel, and pass the matching issuer URLs into the lab:

```bash
CITIZEN_OID4VCI_CREDENTIAL_ISSUER="https://your-tunnel.example" \
CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT="https://your-tunnel.example/oid4vci/credential" \
CITIZEN_OID4VCI_OFFER_ENDPOINT="https://your-tunnel.example/oid4vci/credential-offer" \
CITIZEN_OID4VCI_NONCE_ENDPOINT="https://your-tunnel.example/oid4vci/nonce" \
just citizen-oid4vci-code
```

The generated Notary config is written to
`output/citizen-self-attestation/citizen-civil-notary.yaml`. Inspect it when a
wallet cannot discover or call the issuer.

## Offer URI

Registry Notary exposes the offer object directly at:

```text
GET /oid4vci/credential-offer
```

Many wallets ingest an `openid-credential-offer://` URI whose
`credential_offer` query parameter contains the JSON offer. Generate one from a
running Notary:

```bash
OFFER_JSON="$(curl -s http://127.0.0.1:4325/oid4vci/credential-offer)"

OFFER_URI="$(python3 - "$OFFER_JSON" <<'PY'
import sys
import urllib.parse

offer = sys.argv[1]
print(
    "openid-credential-offer://registry-notary/?credential_offer="
    + urllib.parse.quote(offer, safe="")
)
PY
)"

printf '%s\n' "$OFFER_URI"
```

If the wallet runs on another device or in Docker, generate the offer from the
same externally reachable issuer origin that appears in
`/.well-known/openid-credential-issuer`.

## Walt Wallet API

Walt Wallet API can receive credentials by posting an OID4VCI offer URI to:

```text
POST /wallet-api/wallet/{walletId}/exchange/useOfferRequest?did={did}
```

with `Content-Type: text/plain` and a bearer token for the Walt API.

Example:

```bash
curl -X POST \
  "$WALT_URL/wallet-api/wallet/$WALT_WALLET_ID/exchange/useOfferRequest?did=$WALT_DID" \
  -H "authorization: Bearer $WALT_TOKEN" \
  -H "Content-Type: text/plain" \
  --data "$OFFER_URI"
```

Expected result:

- Walt parses the offer.
- Walt discovers `/.well-known/openid-credential-issuer`.
- Walt obtains or is given a citizen authorization token through the configured
  eSignet authorization flow.
- Walt requests a nonce.
- Walt submits a proof JWT with `typ=openid4vci-proof+jwt`.
- Notary issues an SD-JWT VC with `format=dc+sd-jwt`.

If Walt stops before issuance, capture:

- Walt image tag or version.
- The exact `useOfferRequest` command.
- HTTP status and body from Walt.
- Notary `output/citizen-oid4vci/report.md`.
- Notary log or audit line for `/oid4vci/credential`, if reached.
- Whether the blocker was offer parsing, issuer metadata, authorization,
  nonce, proof, credential response, or credential storage.
- Redact raw tokens, proof JWTs, issued credentials, and seeded civil IDs before
  sharing artifacts outside the local demo workspace.

## Inji and Mimoto

Inji Wallet supports OpenID4VCI and SD-JWT credential download. In the Inji
mobile architecture, new OpenID4VCI providers are commonly configured through
Mimoto issuer configuration.

Testing path:

1. Expose Registry Notary at a stable HTTPS issuer URL.
2. Add a Mimoto issuer/provider entry that points to:
   - `https://your-notary/.well-known/openid-credential-issuer`
   - credential configuration id `person_is_alive_sd_jwt`
   - format `dc+sd-jwt`
3. Register the Mimoto/Inji client with the eSignet issuer used by the lab.
4. Ensure eSignet returns `individual_id=NID-2001` through signed UserInfo, or
   another configured subject-binding claim.
5. Authenticate as the seeded `NID-2001` citizen, Maria Santos.
6. In Inji, use the configured provider from the add-card flow.
7. Download and inspect the credential.

Expected result:

- Inji shows the configured provider.
- Inji completes eSignet authentication.
- Notary audit records `access_mode=self_attestation`.
- The issued credential is holder-bound to the wallet key.
- No raw civil identifier appears in Notary audit artifacts.

If Inji does not complete the flow, capture:

- Inji Wallet version or commit.
- Mimoto version or commit.
- Relevant Mimoto issuer config entry with secrets removed.
- eSignet client id used by Mimoto/Inji.
- The first incompatible request or response field.
- Notary `output/citizen-oid4vci/report.md`.
- A scripted partial-path result from `just citizen-oid4vci-code`.
- Redact raw tokens, proof JWTs, issued credentials, and seeded civil IDs before
  sharing artifacts outside the local demo workspace.

## Evidence checklist

For each wallet run, save a short note beside the lab output:

```text
wallet:
wallet_version:
wallet_command_or_config:
issuer_url:
credential_configuration_id: person_is_alive_sd_jwt
result: passed | blocked | failed
first_blocker:
notary_report: output/citizen-oid4vci/report.md
notary_audit_excerpt:
notes:
```

The run is considered passed when:

- The wallet obtains and stores a credential.
- The credential response uses `format=dc+sd-jwt`.
- Notary audit shows `access_mode=self_attestation`.
- `NID-2001` is the token-bound subject.
- An attempted other-person flow remains denied by the base citizen smoke.

## Known boundaries

- V1 proves wallet key possession, not wallet certification or wallet instance
  attestation.
- V1 does not prove the holder DID is the civil subject.
- V1 is authorization-code oriented for real wallets. The lab script can use
  pre-supplied tokens, but that is a test convenience, not the normal wallet
  UX.
- V1 targets Draft 13-style offer and credential response compatibility, while
  also exposing a Final-style nonce endpoint.
- If a wallet requires a different OpenID4VCI field name or response shape,
  record the mismatch before adding a wallet-specific workaround.
