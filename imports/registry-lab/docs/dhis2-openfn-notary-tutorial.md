# Issue a DHIS2 child programme credential

Page type: tutorial
Product: Registry Lab, Registry Notary, OpenFn sidecar
Layer: evaluation and credential
Audience: integrators testing Registry Notary with DHIS2

Use this tutorial to run the live DHIS2 demo and issue one SD-JWT verifiable
credential from public DHIS2 sandbox data.

The demo starts two local services:

- `openfn-dhis2-sidecar`: a private sidecar that calls the DHIS2 Tracker API.
- `dhis2-health-notary`: a Registry Notary service on `http://127.0.0.1:4326`.

The smoke first checks the configured health predicates. Then it evaluates one
tracked entity for first name, last name, and child programme status, and issues
an `application/dc+sd-jwt` credential with profile:

```text
dhis2_child_program_sd_jwt
```

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
4. Evaluate the credential claims for tracked entity `PQfMcpmXeFE`.
5. Issue an SD-JWT VC with first name, last name, and child programme status.

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
  for credential issuance.
- `smoke-dhis2-child-program-credential-summary.json`: safe credential response
  summary.
- `smoke-dhis2-child-program-credential.json`: full SD-JWT VC issuance
  response.

Example summary shape:

```json
{
  "credential_id": "urn:ulid:...",
  "credential_profile": "dhis2_child_program_sd_jwt",
  "format": "application/dc+sd-jwt",
  "issuer": "did:web:dhis2-health-notary.demo.example.gov",
  "expires_at": "2026-06-01T00:00:00Z",
  "disclosure_count": 3,
  "credential_compact_length": 1800
}
```

## Try the evaluation manually

Keep the services running after the smoke, then evaluate the credential claims:

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
      "dhis2-child-program-active"
    ],
    "disclosure": "value",
    "format": "application/dc+sd-jwt"
  }' | jq .
```

Use the returned `evaluation_id` to issue a credential:

```bash
EVAL_ID="$(
  jq -r '.results[0].evaluation_id' \
    output/dhis2-openfn/smoke-dhis2-child-program-vc-evaluation.json
)"

curl -fsS -X POST http://127.0.0.1:4326/v1/credentials \
  -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
  -H "content-type: application/json" \
  -d "$(jq -nc --arg evaluation_id "$EVAL_ID" '{
    evaluation_id: $evaluation_id,
    credential_profile: "dhis2_child_program_sd_jwt",
    format: "application/dc+sd-jwt",
    claims: [
      "dhis2-tracked-entity-first-name",
      "dhis2-tracked-entity-last-name",
      "dhis2-child-program-active"
    ],
    disclosure: "value"
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
