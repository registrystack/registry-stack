# Issue a DHIS2 programme participation credential

Page type: tutorial
Product: Registry Lab, Registry Notary, OpenFn sidecar
Layer: evaluation and credential
Audience: integrators testing Registry Notary with DHIS2

Use this tutorial to run the live DHIS2 demo and issue SD-JWT verifiable
credentials from public DHIS2 sandbox data. The main demo credential is a
holder-bound programme participation VC that can be shared offline for up to one
year, while still carrying a reconciliation reference that can be used later to
fetch fresh Notary evidence from DHIS2.

The demo starts two local services:

- `openfn-dhis2-sidecar`: a private sidecar that calls the DHIS2 Tracker API.
- `dhis2-health-notary`: a Registry Notary service on `http://127.0.0.1:4326`.

The smoke first checks the configured health predicates. Then it issues two
`application/dc+sd-jwt` credentials:

- `dhis2_child_program_sd_jwt`: compatibility credential with first name, last
  name, and child programme status.
- `dhis2_programme_participation_sd_jwt`: one-year holder-bound credential with
  first name, last name, child age band, programme code, programme status, and a
  reconciliation reference.

```text
dhis2_programme_participation_sd_jwt
```

The public DHIS2 child programme used by the smoke does not expose date of birth
on the tracked entity. For the lab demo, the sidecar therefore emits
`child_age_band: "5_to_17"` when the entity has an active child programme
enrollment. Treat this as lab-derived programme context, not a clinical age
calculation.

## Before you start

Run from the Registry Lab directory:

```bash
cd /path/to/registry-lab
```

You need:

- Docker running.
- Network access to `https://play.im.dhis2.org/stable-2-43-0`.
- Demo secrets generated in `.env`.

Generate local demo secrets if you have not already:

```bash
just generate
```

Build the local demo images if they are stale:

```bash
just build
```

## Run the demo

```bash
just dhis2-openfn
```

The script will:

1. Start the DHIS2 OpenFn sidecar and Notary services.
2. Wait for Notary discovery on port `4326`.
3. Evaluate positive and negative DHIS2 health predicate claims.
4. Evaluate the compatibility child programme credential claims.
5. Evaluate the programme participation credential claims for tracked entity
   `PQfMcpmXeFE`.
6. Generate a `did:jwk` holder proof of possession.
7. Issue a one-year holder-bound SD-JWT VC.
8. Reuse the VC reconciliation reference to fetch fresh programme status proof.

Expected ending:

```text
DHIS2 OpenFn health evidence and VC smoke passed
```

## Inspect the credential

The smoke writes files under:

```text
output/dhis2-openfn/
```

Useful files:

- `smoke-dhis2-child-program-vc-evaluation.json`: evaluation results prepared
  for the compatibility credential.
- `smoke-dhis2-child-program-credential-summary.json`: safe credential response
  summary for the compatibility credential.
- `smoke-dhis2-child-program-credential.json`: full SD-JWT VC issuance
  response for the compatibility credential.
- `smoke-dhis2-programme-participation-evaluation.json`: evaluation results for
  the one-year programme participation credential.
- `smoke-dhis2-programme-participation-holder.json`: generated holder DID and
  proof used for issuance.
- `smoke-dhis2-programme-participation-credential-summary.json`: safe redacted
  summary for the programme participation credential.
- `smoke-dhis2-programme-participation-credential.json`: full SD-JWT VC issuance
  response for the programme participation credential.
- `smoke-dhis2-programme-participation-followup.json`: fresh evidence fetched by
  using the reconciliation reference from the VC.

Example summary shape:

```json
{
  "credential_id": "urn:ulid:...",
  "credential_profile": "dhis2_programme_participation_sd_jwt",
  "format": "application/dc+sd-jwt",
  "issuer": "did:web:dhis2-health-notary.demo.example.gov",
  "vct": "https://demo.example.gov/credentials/dhis2/programme-participation/v1",
  "expires_at": "2027-06-01T00:00:00Z",
  "validity_seconds": 31536000,
  "holder_bound": true,
  "holder_binding": "did:jwk",
  "holder_id_prefix": "did:jwk:...",
  "disclosure_count": 6,
  "disclosure_claim_ids": [
    "dhis2-child-age-band",
    "dhis2-child-program-active",
    "dhis2-programme-code",
    "dhis2-reconciliation-ref",
    "dhis2-tracked-entity-first-name",
    "dhis2-tracked-entity-last-name"
  ],
  "child_age_band": "5_to_17",
  "programme_code": "DHIS2_CHILD_PROGRAM",
  "programme_active": true,
  "reconciliation_ref_available": true,
  "reconciliation_ref_redacted": "dhis2:tracked-entity:<redacted>",
  "followup_satisfied": true,
  "credential_compact_length": 2600
}
```

The full credential and holder files are useful for local debugging. Do not copy
them into public docs or tickets. The summary intentionally redacts the
reconciliation reference and avoids printing the holder proof.

## Hand the VC to a wallet

The hosted citizen wallet demo uses an OID4VCI offer flow: the wallet consumes
an `openid-credential-offer://` URI, chooses its holder DID, signs the proof, and
receives the credential. See `docs/wallet-interop-testing.md` for that path.

The DHIS2 programme participation demo is one layer lower today. It issues the
same kind of `application/dc+sd-jwt` credential, but through the Notary
`/v1/evaluations` and `/v1/credentials` APIs rather than through an OID4VCI
offer endpoint. That means there are two distinct wallet handoff modes:

- **Demo storage/import:** run the Bruno `31 - DHIS2 Programme VC` folder or the
  curl flow below, then copy the `credential` field from the credential response
  into a wallet that supports raw SD-JWT VC import. This lets the wallet store or
  display the issued VC, but the holder key is the temporary `did:jwk` generated
  by Bruno or `scripts/generate-holder-proof.js`, not a key generated by the
  wallet.
- **Wallet-owned issuance:** use a wallet flow that can generate the holder DID
  and proof itself, equivalent to the citizen OID4VCI demo. DHIS2 does not expose
  this offer-to-wallet facade yet. To make the DHIS2 demo fully match the hosted
  wallet demo, add an OID4VCI configuration for
  `dhis2_programme_participation_sd_jwt` so the wallet signs the proof and
  receives the one-year credential directly.

Hosted manual handoff:

1. Open the Bruno workspace in `requests/registry-lab`.
2. Select the `Hosted Lab` environment.
3. Run `31 - DHIS2 Programme VC` in order.
4. In request `02 - Issue holder-bound programme participation VC`, copy the
   response `credential` value. It is the compact SD-JWT VC.
5. In the wallet, choose its raw credential or SD-JWT import action and paste the
   compact credential.

For a demo where the wallet must prove possession of its own key, use the
citizen OID4VCI wallet flow as the reference behavior and treat DHIS2 OID4VCI as
the follow-up integration point.

## Try the evaluation manually

Keep the services running after the smoke, then evaluate the programme
participation credential claims:

```bash
source .env

curl -fsS -X POST http://127.0.0.1:4326/v1/evaluations \
  -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
  -H "content-type: application/json" \
  -H "data-purpose: https://demo.example.gov/purpose/dhis2-openfn-health-evidence" \
  -d '{
    "target": {
      "type": "TrackedEntity",
      "identifiers": [
        {
          "scheme": "dhis2_tracked_entity",
          "value": "PQfMcpmXeFE"
        }
      ]
    },
    "claims": [
      "dhis2-tracked-entity-first-name",
      "dhis2-tracked-entity-last-name",
      "dhis2-child-age-band",
      "dhis2-programme-code",
      "dhis2-child-program-active",
      "dhis2-reconciliation-ref"
    ],
    "disclosure": "value",
    "format": "application/dc+sd-jwt"
  }' | jq .
```

Use the returned `evaluation_id` to generate a holder proof and issue a
credential:

```bash
EVAL_ID="$(
  jq -r '.results[0].evaluation_id' \
    output/dhis2-openfn/smoke-dhis2-programme-participation-evaluation.json
)"

CLAIMS='[
  "dhis2-tracked-entity-first-name",
  "dhis2-tracked-entity-last-name",
  "dhis2-child-age-band",
  "dhis2-programme-code",
  "dhis2-child-program-active",
  "dhis2-reconciliation-ref"
]'

scripts/generate-holder-proof.js \
  --audience dhis2-health-notary \
  --evaluation-id "$EVAL_ID" \
  --credential-profile dhis2_programme_participation_sd_jwt \
  --disclosure value \
  --claims-json "$CLAIMS" \
  > output/dhis2-openfn/manual-programme-holder.json

curl -fsS -X POST http://127.0.0.1:4326/v1/credentials \
  -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
  -H "content-type: application/json" \
  -d "$(jq -nc \
    --arg evaluation_id "$EVAL_ID" \
    --argjson claims "$CLAIMS" \
    --slurpfile holder output/dhis2-openfn/manual-programme-holder.json \
    '{
    evaluation_id: $evaluation_id,
    credential_profile: "dhis2_programme_participation_sd_jwt",
    format: "application/dc+sd-jwt",
    claims: $claims,
    disclosure: "value",
    holder: $holder[0].holder
  }')" | jq .
```

## Troubleshooting

If `just dhis2-openfn` fails while contacting DHIS2, rerun it once. The source
is a public sandbox and can be slow or reset.

If Notary returns `401`, regenerate `.env`:

```bash
just generate
```

If the sample tracked entity no longer has the expected data, choose another
tracked entity from the public DHIS2 sandbox and update the smoke subject IDs in
`scripts/smoke-dhis2-openfn.sh`.
