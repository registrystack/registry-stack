# Wallet Interop Testing

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
credential issuance, and redacted evidence artifacts.

Real wallet testing adds wallet-specific behavior: offer parsing, holder DID
selection, authorization redirect handling, proof generation, credential
storage, and display.

## Preconditions

- Local eSignet is running and can authenticate the seeded citizen `NID-1001`.
- Registry Relay civil fixtures are running.
- Registry Witness is started through the citizen OID4VCI flow.
- The wallet can reach the Witness issuer URL and eSignet authorization URL.
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

The generated Witness config is written to
`output/citizen-self-attestation/citizen-civil-witness.yaml`. Inspect it when a
wallet cannot discover or call the issuer.

## Offer URI

Registry Witness exposes the offer object directly at:

```text
GET /oid4vci/credential-offer
```

Many wallets ingest an `openid-credential-offer://` URI whose
`credential_offer` query parameter contains the JSON offer. Generate one from a
running Witness:

```bash
OFFER_JSON="$(curl -s http://127.0.0.1:4325/oid4vci/credential-offer)"

OFFER_URI="$(python3 - "$OFFER_JSON" <<'PY'
import sys
import urllib.parse

offer = sys.argv[1]
print(
    "openid-credential-offer://registry-witness/?credential_offer="
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
- Witness issues an SD-JWT VC with `format=dc+sd-jwt`.

If Walt stops before issuance, capture:

- Walt image tag or version.
- The exact `useOfferRequest` command.
- HTTP status and body from Walt.
- Witness `output/citizen-oid4vci/report.md`.
- Witness log or audit line for `/oid4vci/credential`, if reached.
- Whether the blocker was offer parsing, issuer metadata, authorization,
  nonce, proof, credential response, or credential storage.

## Inji and Mimoto

Inji Wallet supports OpenID4VCI and SD-JWT credential download. In the Inji
mobile architecture, new OpenID4VCI providers are commonly configured through
Mimoto issuer configuration.

Testing path:

1. Expose Registry Witness at a stable HTTPS issuer URL.
2. Add a Mimoto issuer/provider entry that points to:
   - `https://your-witness/.well-known/openid-credential-issuer`
   - credential configuration id `person_is_alive_sd_jwt`
   - format `dc+sd-jwt`
3. Register the Mimoto/Inji client with the eSignet issuer used by the lab.
4. Ensure eSignet returns `individual_id=NID-1001` through signed UserInfo, or
   another configured subject-binding claim.
5. In Inji, use the configured provider from the add-card flow.
6. Authenticate as the seeded citizen.
7. Download and inspect the credential.

Expected result:

- Inji shows the configured provider.
- Inji completes eSignet authentication.
- Witness audit records `access_mode=self_attestation`.
- The issued credential is holder-bound to the wallet key.
- No raw civil identifier appears in Witness audit artifacts.

If Inji does not complete the flow, capture:

- Inji Wallet version or commit.
- Mimoto version or commit.
- Relevant Mimoto issuer config entry with secrets removed.
- eSignet client id used by Mimoto/Inji.
- The first incompatible request or response field.
- Witness `output/citizen-oid4vci/report.md`.
- A scripted partial-path result from `just citizen-oid4vci-code`.

## Evidence Checklist

For each wallet run, save a short note beside the lab output:

```text
wallet:
wallet_version:
wallet_command_or_config:
issuer_url:
credential_configuration_id: person_is_alive_sd_jwt
result: passed | blocked | failed
first_blocker:
witness_report: output/citizen-oid4vci/report.md
witness_audit_excerpt:
notes:
```

The run is considered passed when:

- The wallet obtains and stores a credential.
- The credential response uses `format=dc+sd-jwt`.
- Witness audit shows `access_mode=self_attestation`.
- `NID-1001` is the token-bound subject.
- An attempted other-person flow remains denied by the base citizen smoke.

## Known Boundaries

- V1 proves wallet key possession, not wallet certification or wallet instance
  attestation.
- V1 does not prove the holder DID is the civil subject.
- V1 is authorization-code oriented for real wallets. The lab script can use
  pre-supplied tokens, but that is a test convenience, not the normal wallet
  UX.
- If a wallet requires a different OpenID4VCI draft field name, record the
  mismatch before adding a wallet-specific workaround.
