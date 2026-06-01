# Issue an OpenCRVS birth attributes credential

Page type: tutorial
Product: Registry Lab, Registry Notary, OpenCRVS DCI
Layer: evaluation and credential
Audience: integrators testing Registry Notary with OpenCRVS

This tutorial shows how to configure the Registry Lab OpenCRVS DCI demo, verify
evidence from OpenCRVS, and issue a demo SD-JWT VC from that evidence.

It is written for operators and demo users. You do not need to write Rust code.

## What you will run

The lab starts one local Registry Notary service:

```text
http://127.0.0.1:4352
```

That service calls the OpenCRVS DCI API:

```text
https://dci-crvs-api.farajaland-integration.opencrvs.dev
```

The demo verifies birth-record evidence for a seeded OpenCRVS record:

- `opencrvs-birth-record-exists`
- `opencrvs-date-of-birth`
- `opencrvs-sex`
- `opencrvs-age-band`
- `opencrvs-child-given-name`
- `opencrvs-child-family-name`
- `opencrvs-child-date-of-birth`
- `opencrvs-child-place-of-birth`

The smoke also attempts the demographic lookup path without UIN, using child
given name, family name, and date of birth. It then issues an
`application/dc+sd-jwt` VC using credential profile:

```text
opencrvs_birth_attributes_sd_jwt
```

This profile is intentionally machine-to-machine for the lab. It does not bind
the credential to a citizen wallet holder.

## Before you start

Install or have access to:

- Docker Desktop, running
- `git`
- `just`
- `curl`
- `jq`

From the lab directory, you can check the basics:

```bash
cd /Users/jeremi/Projects/204-programs-delivery-commons/apps/registry-lab
docker version
just --list
curl --version
jq --version
```

## Step 1: Generate local lab secrets

If this is a fresh checkout, generate the lab's local `.env` file:

```bash
just generate
```

This creates demo-only Registry Notary secrets in `.env`. Do not edit `.env`
by hand for long-lived OpenCRVS credentials, because `just generate` can
rewrite it.

## Step 2: Create `.env.local`

Create a local-only file for OpenCRVS credentials:

```bash
cat > .env.local <<'EOF'
OPENCRVS_DCI_BASE_URL=https://dci-crvs-api.farajaland-integration.opencrvs.dev
OPENCRVS_DCI_CLIENT_ID=<your OpenCRVS DCI client id>
OPENCRVS_DCI_CLIENT_SECRET=<your OpenCRVS DCI client secret>
OPENCRVS_DCI_SHA_SECRET=<your OpenCRVS DCI sha secret>
OPENCRVS_EVIDENCE_CLIENT_TOKEN=api-token
OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH=sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51
OPENCRVS_DCI_NOTARY_PORT=4352
EOF
chmod 600 .env.local
```

Replace the three `<...>` values with the credentials you received from
OpenCRVS.

`.env.local` is ignored by Git. Keep it local to your machine and do not paste
it into tickets, commits, screenshots, or chat.

`OPENCRVS_DCI_SHA_SECRET` is recorded for later signed-request testing. The
current OpenCRVS DCI smoke uses OAuth bearer-token authentication and unsigned
DCI requests.

## Step 3: Run the OpenCRVS demo

Run:

```bash
just opencrvs-dci
```

The script will:

1. Read `.env` and `.env.local`.
2. Fetch a fresh OpenCRVS OAuth access token for seeded-subject discovery.
3. Let Registry Notary fetch its own OpenCRVS source tokens with OAuth
   client credentials.
4. Discover one seeded OpenCRVS demo UIN if `OPENCRVS_DEMO_SUBJECT_UIN` is not
   already set.
5. Start `opencrvs-dci-notary` on port `4352`.
6. Evaluate OpenCRVS evidence claims by UIN.
7. Attempt a no-UIN lookup by child given name, family name, and date of birth.
8. Issue an SD-JWT VC with child name, date of birth, and place of birth.

Expected ending:

```text
Issued OpenCRVS birth attribute SD-JWT VC
```

## Step 4: Inspect the output

The smoke writes artifacts under:

```text
output/opencrvs-dci/
```

Useful files:

- `summary.json`: evidence claim summary
- `evaluation.json`: full JSON evidence evaluation response
- `demographic-evaluation.json`: no-UIN lookup result or problem response
- `vc-evaluation.json`: evaluation response prepared for VC issuance
- `credential-summary.json`: safe credential response summary
- `credential.json`: full SD-JWT VC issuance response

To see the safe VC summary:

```bash
jq . output/opencrvs-dci/credential-summary.json
```

Example shape:

```json
{
  "credential_id": "urn:ulid:...",
  "credential_profile": "opencrvs_birth_attributes_sd_jwt",
  "format": "application/dc+sd-jwt",
  "issuer": "did:web:opencrvs-dci.demo.example.gov",
  "expires_at": "2026-05-30T07:42:38Z",
  "disclosure_count": 4,
  "credential_compact_length": 2056
}
```

## Step 5: Test evidence manually

The smoke script stores a discovered seeded UIN in `.env.local` as
`OPENCRVS_DEMO_SUBJECT_UIN`. Load it:

```bash
source ./.env.local
```

Evaluate evidence:

```bash
curl -fsS -X POST http://127.0.0.1:4352/v1/evaluations \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-api-token}" \
  -H "content-type: application/json" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci-lab" \
  -d "$(jq -nc --arg subject "$OPENCRVS_DEMO_SUBJECT_UIN" '{
    target: {
      type: "Person",
      identifiers: [{ scheme: "UIN", value: $subject, issuer: "opencrvs" }]
    },
    claims: [
      "opencrvs-birth-record-exists",
      "opencrvs-date-of-birth",
      "opencrvs-sex",
      "opencrvs-age-band",
      "opencrvs-child-given-name",
      "opencrvs-child-family-name",
      "opencrvs-child-date-of-birth",
      "opencrvs-child-place-of-birth"
    ],
    disclosure: "value",
    format: "application/vnd.registry-notary.claim-result+json"
  }')" | jq .
```

If this succeeds, you should see eight `results`.

You can also test the no-UIN demographic lookup path after the smoke has
written `summary.json`:

```bash
GIVEN_NAME="$(jq -r '.claims[] | select(.claim_id == "opencrvs-child-given-name") | .value' output/opencrvs-dci/summary.json)"
FAMILY_NAME="$(jq -r '.claims[] | select(.claim_id == "opencrvs-child-family-name") | .value' output/opencrvs-dci/summary.json)"
BIRTHDATE="$(jq -r '.claims[] | select(.claim_id == "opencrvs-child-date-of-birth") | .value' output/opencrvs-dci/summary.json)"

curl -fsS -X POST http://127.0.0.1:4352/v1/evaluations \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-api-token}" \
  -H "content-type: application/json" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci-lab" \
  -d "$(jq -nc \
    --arg given_name "$GIVEN_NAME" \
    --arg family_name "$FAMILY_NAME" \
    --arg birthdate "$BIRTHDATE" '{
      target: {
        type: "Person",
        attributes: {
          given_name: $given_name,
          family_name: $family_name,
          birthdate: $birthdate
        }
      },
      claims: ["opencrvs-birth-record-exists-by-demographics"],
      disclosure: "value",
      format: "application/vnd.registry-notary.claim-result+json"
    }')" | jq .
```

On the current Farajaland integration data this may return `409` when the live
OpenCRVS search endpoint does not produce a unique match. That does not block
the VC path, which uses the UIN-backed evidence evaluation.

## Step 6: Issue a VC manually

First create an evaluation in SD-JWT VC format and capture its `evaluation_id`:

```bash
EVAL_ID="$(
  curl -fsS -X POST http://127.0.0.1:4352/v1/evaluations \
    -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-api-token}" \
    -H "content-type: application/json" \
    -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci-lab" \
    -d "$(jq -nc --arg subject "$OPENCRVS_DEMO_SUBJECT_UIN" '{
      target: {
        type: "Person",
        identifiers: [{ scheme: "UIN", value: $subject, issuer: "opencrvs" }]
      },
      claims: [
        "opencrvs-child-given-name",
        "opencrvs-child-family-name",
        "opencrvs-child-date-of-birth",
        "opencrvs-child-place-of-birth"
      ],
      disclosure: "value",
      format: "application/dc+sd-jwt"
    }')" |
    jq -r '.results[0].evaluation_id'
)"
echo "$EVAL_ID"
```

Then issue the credential:

```bash
curl -fsS -X POST http://127.0.0.1:4352/v1/credentials \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-api-token}" \
  -H "content-type: application/json" \
  -d "$(jq -nc --arg evaluation_id "$EVAL_ID" '{
    evaluation_id: $evaluation_id,
    credential_profile: "opencrvs_birth_attributes_sd_jwt",
    format: "application/dc+sd-jwt",
    claims: [
      "opencrvs-child-given-name",
      "opencrvs-child-family-name",
      "opencrvs-child-date-of-birth",
      "opencrvs-child-place-of-birth"
    ],
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
  "issuer": "did:web:opencrvs-dci.demo.example.gov",
  "expires_at": "...",
  "disclosure_count": 4,
  "has_credential": true
}
```

## Troubleshooting

### `source.not_found`

If you send this:

```json
"target": {
  "type": "Person",
  "identifiers": [{ "scheme": "UIN", "value": "<UIN>", "issuer": "opencrvs" }]
}
```

you are sending the literal string `<UIN>`. OpenCRVS will not have a record for
that placeholder.

Fix:

```bash
source ./.env.local
echo "$OPENCRVS_DEMO_SUBJECT_UIN"
```

Then use the `jq --arg subject "$OPENCRVS_DEMO_SUBJECT_UIN"` examples above.

### `missing .env`

Run:

```bash
just generate
```

### `missing .env.local`

Create `.env.local` using Step 2.

### Token expired or authentication failed

Run the smoke again:

```bash
just opencrvs-dci
```

The script and Registry Notary fetch fresh OpenCRVS OAuth tokens from the
configured client credentials. Re-check `OPENCRVS_DCI_CLIENT_ID` and
`OPENCRVS_DCI_CLIENT_SECRET` in `.env.local` if authentication still fails.

### Port 4352 is already in use

Set another local port in `.env.local`:

```bash
OPENCRVS_DCI_NOTARY_PORT=4452
```

Then run:

```bash
just opencrvs-dci
```

Use the new port in manual curl commands.

### Docker is not running

Start Docker Desktop, then rerun:

```bash
just opencrvs-dci
```

## Security notes

- `.env.local` contains live OpenCRVS client credentials and should stay local.
- `output/opencrvs-dci/credential.json` contains a full demo credential
  response. Treat it as sensitive demo data.
- The current VC profile uses `holder_binding.mode: none` so the credential is
  not wallet-bound.
- For citizen-wallet issuance, create a holder-bound profile with
  `holder_binding.mode: did`, require proof-of-possession, and issue only after
  validating a holder proof such as `did:jwk`.
