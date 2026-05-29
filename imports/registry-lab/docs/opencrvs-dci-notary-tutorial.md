# OpenCRVS DCI Registry Notary Tutorial

This tutorial shows how to configure the Registry Lab OpenCRVS DCI demo, verify
evidence from OpenCRVS, and issue a demo SD-JWT VC from that evidence.

It is written for operators and demo users. You do not need to write Rust code.

## What You Will Run

The lab starts one local Registry Notary service:

```text
http://127.0.0.1:4352
```

That service calls the OpenCRVS DCI API:

```text
https://dci-crvs-api.farajaland-integration.opencrvs.dev
```

The demo verifies four pieces of evidence for a seeded OpenCRVS birth record:

- `opencrvs-birth-record-exists`
- `opencrvs-date-of-birth`
- `opencrvs-sex`
- `opencrvs-age-band`

The demo can also issue an `application/dc+sd-jwt` VC using credential profile:

```text
opencrvs_birth_summary_sd_jwt
```

This profile is intentionally machine-to-machine for the lab. It does not bind
the credential to a citizen wallet holder.

## Before You Start

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

## Step 1: Generate Local Lab Secrets

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

## Step 3: Run The OpenCRVS Demo

Run:

```bash
just opencrvs-dci
```

The script will:

1. Read `.env` and `.env.local`.
2. Fetch a fresh OpenCRVS OAuth access token.
3. Store the short-lived access token in `.env.local` as
   `OPENCRVS_DCI_TOKEN`.
4. Discover one seeded OpenCRVS demo UIN if `OPENCRVS_DEMO_SUBJECT_UIN` is not
   already set.
5. Start `opencrvs-dci-notary` on port `4352`.
6. Evaluate the four OpenCRVS evidence claims.
7. Issue an SD-JWT VC from those evidence results.

Expected ending:

```text
OpenCRVS DCI Registry Notary smoke passed
```

## Step 4: Inspect The Output

The smoke writes artifacts under:

```text
output/opencrvs-dci/
```

Useful files:

- `summary.json`: evidence claim summary
- `evaluation.json`: full JSON evidence evaluation response
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
  "format": "application/dc+sd-jwt",
  "issuer": "did:web:opencrvs-dci.demo.example.gov",
  "expires_at": "2026-05-30T07:42:38Z",
  "disclosure_count": 4,
  "credential_compact_length": 2056
}
```

## Step 5: Test Evidence Manually

The smoke script stores a discovered seeded UIN in `.env.local` as
`OPENCRVS_DEMO_SUBJECT_UIN`. Load it:

```bash
source ./.env.local
```

Evaluate evidence:

```bash
curl -fsS -X POST http://127.0.0.1:4352/claims/evaluate \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-api-token}" \
  -H "content-type: application/json" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci-lab" \
  -d "$(jq -nc --arg subject "$OPENCRVS_DEMO_SUBJECT_UIN" '{
    subject: { id: $subject, id_type: "UIN" },
    claims: [
      "opencrvs-birth-record-exists",
      "opencrvs-date-of-birth",
      "opencrvs-sex",
      "opencrvs-age-band"
    ],
    disclosure: "value",
    format: "application/vnd.registry-notary.claim-result+json"
  }')" | jq .
```

If this succeeds, you should see four `results`.

## Step 6: Issue A VC Manually

First create an evaluation in SD-JWT VC format and capture its `evaluation_id`:

```bash
EVAL_ID="$(
  curl -fsS -X POST http://127.0.0.1:4352/claims/evaluate \
    -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-api-token}" \
    -H "content-type: application/json" \
    -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci-lab" \
    -d "$(jq -nc --arg subject "$OPENCRVS_DEMO_SUBJECT_UIN" '{
      subject: { id: $subject, id_type: "UIN" },
      claims: [
        "opencrvs-birth-record-exists",
        "opencrvs-date-of-birth",
        "opencrvs-sex",
        "opencrvs-age-band"
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
curl -fsS -X POST http://127.0.0.1:4352/credentials/issue \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-api-token}" \
  -H "content-type: application/json" \
  -d "$(jq -nc --arg evaluation_id "$EVAL_ID" '{
    evaluation_id: $evaluation_id,
    credential_profile: "opencrvs_birth_summary_sd_jwt",
    format: "application/dc+sd-jwt",
    claims: [
      "opencrvs-birth-record-exists",
      "opencrvs-date-of-birth",
      "opencrvs-sex",
      "opencrvs-age-band"
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

## Common Problems

### `source.not_found`

If you send this:

```json
"subject": { "id": "<UIN>", "id_type": "UIN" }
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

### Token Expired Or Authentication Failed

Run the smoke again:

```bash
just opencrvs-dci
```

The script fetches and stores a fresh `OPENCRVS_DCI_TOKEN`.

### Port 4352 Is Already In Use

Set another local port in `.env.local`:

```bash
OPENCRVS_DCI_NOTARY_PORT=4452
```

Then run:

```bash
just opencrvs-dci
```

Use the new port in manual curl commands.

### Docker Is Not Running

Start Docker Desktop, then rerun:

```bash
just opencrvs-dci
```

## Security Notes

- `.env.local` contains live OpenCRVS client credentials and should stay local.
- `output/opencrvs-dci/credential.json` contains a full demo credential
  response. Treat it as sensitive demo data.
- The current VC profile uses `holder_binding.mode: none` so the credential is
  not wallet-bound.
- For citizen-wallet issuance, create a holder-bound profile with
  `holder_binding.mode: did`, require proof-of-possession, and issue only after
  validating a holder proof such as `did:jwk`.

