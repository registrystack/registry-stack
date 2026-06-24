# Issue an OpenFn civil credential

Page type: tutorial
Product: Registry Lab, Registry Notary, OpenFn sidecar
Layer: evaluation and credential
Audience: integrators testing Registry Notary with an OpenFn source adapter

Use this tutorial to run the local OpenFn sidecar demo and issue one SD-JWT
verifiable credential from the sidecar-backed civil lookup.

The demo starts three local services:

- `openfn-mock-registry`: a private registry-like HTTP API.
- `openfn-civil-sidecar`: a private OpenFn adaptor sidecar.
- `openfn-civil-notary`: a Registry Notary service on `http://127.0.0.1:4324`.

The Notary calls only the sidecar. The sidecar and mock registry are not
published on host ports.

## Before you start

Run from the Registry Lab directory:

```bash
cd /path/to/registry-lab
```

You need:

- Docker running.
- Demo secrets generated in `.env`.

Generate local demo secrets if you have not already:

```bash
just generate
```

Build and start the default lab services:

```bash
just build
just up
```

## Run the smoke

```bash
just openfn
```

The script will:

1. Recreate the OpenFn mock registry, sidecar, and Notary containers.
2. Wait for Notary discovery on port `4324`.
3. Evaluate `date-of-birth` for `person-123`.
4. Issue `openfn_civil_sd_jwt` from the successful evaluation.
5. Write a safe credential summary to
   `output/smoke-openfn-credential-summary.json`.

Expected ending:

```text
OpenFn sidecar Registry Notary smoke passed
```

Inspect the safe summary:

```bash
jq . output/smoke-openfn-credential-summary.json
```

## Issue the credential

The OpenFn Notary config includes credential profile:

```text
openfn_civil_sd_jwt
```

Create an SD-JWT evaluation and capture its `evaluation_id`:

```bash
set -a
. ./.env
set +a

EVAL_ID="$(
  curl -fsS -X POST http://127.0.0.1:4324/v1/evaluations \
    -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
    -H "content-type: application/json" \
    -H "data-purpose: https://demo.example.gov/purpose/openfn-sidecar-demo" \
    -d '{
      "target": {
        "type": "Person",
        "identifiers": [
          {
            "scheme": "national_id",
            "value": "person-123"
          }
        ]
      },
      "claims": ["date-of-birth"],
      "disclosure": "value",
      "format": "application/dc+sd-jwt"
    }' |
    jq -r '.results[0].evaluation_id'
)"

printf '%s\n' "$EVAL_ID"
```

Issue the credential:

```bash
curl -fsS -X POST http://127.0.0.1:4324/v1/credentials \
  -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
  -H "content-type: application/json" \
  -d "$(jq -nc --arg evaluation_id "$EVAL_ID" '{
    evaluation_id: $evaluation_id,
    credential_profile: "openfn_civil_sd_jwt",
    format: "application/dc+sd-jwt",
    claims: ["date-of-birth"],
    disclosure: "value"
  }')" |
  jq '{
    credential_id,
    format,
    issuer,
    expires_at,
    disclosure_count: (.disclosures | length),
    has_credential: (.credential | type == "string")
  }'
```

Expected result:

```json
{
  "credential_id": "urn:ulid:...",
  "format": "application/dc+sd-jwt",
  "issuer": "did:web:openfn-civil-notary.demo.example",
  "expires_at": "...",
  "disclosure_count": 1,
  "has_credential": true
}
```

## Troubleshooting

If Notary discovery on port `4324` fails, rerun:

```bash
just openfn
```

If the credential request returns `401`, regenerate `.env` and restart the
services:

```bash
just generate
just up
just openfn
```

If `evaluation_id` is empty, inspect the evaluation response:

```bash
jq . output/smoke-openfn-notary-evaluation.json
```

The successful demo value is `1990-01-01` for `person-123`.
