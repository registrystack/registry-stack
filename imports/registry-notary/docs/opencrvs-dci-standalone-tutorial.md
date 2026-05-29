# OpenCRVS DCI Standalone Tutorial

This tutorial starts from a generic DCI Registry Notary starter config, then
adds the OpenCRVS-specific DCI filters in YAML. OpenCRVS is not a built-in
Registry Notary runtime mode or code preset.

## What You Will Run

You will run Registry Notary locally:

```text
http://127.0.0.1:4255
```

Registry Notary will call the OpenCRVS DCI API:

```text
https://dci-crvs-api.farajaland-integration.opencrvs.dev
```

You will evaluate this claim:

```text
opencrvs-birth-record-exists
```

## Prerequisites

- Git
- Rust and Cargo, unless you already have a `registry-notary` binary
- `curl`
- `jq`

Build from this repository when needed:

```bash
cargo build --release -p registry-notary-bin
export PATH="$PWD/target/release:$PATH"
registry-notary --help
```

The binary must support:

- `registry-notary init dci`
- `registry-notary doctor`
- `registry-notary explain-config`
- `registry-notary hash-api-key`
- `registry-notary demo-issuer-key`
- `--env-file`
- `source_auth.type = oauth2_client_credentials`

## Step 1: Create A Working Folder

```bash
mkdir -p "$HOME/opencrvs-notary-demo"
cd "$HOME/opencrvs-notary-demo"
```

## Step 2: Generate A Generic DCI Starter For OpenCRVS

```bash
registry-notary init dci \
  --with-env-file \
  --demo-issuer \
  --base-url https://dci-crvs-api.farajaland-integration.opencrvs.dev \
  --token-url https://dci-crvs-api.farajaland-integration.opencrvs.dev/oauth2/client/token \
  --lookup-field UIN \
  --claim-id opencrvs-birth-record-exists \
  --claim-title "OpenCRVS birth record exists"
```

This writes:

- `dci-notary.yaml`
- `.env.local.example`
- `.env.local`
- `README.dci.md`

The generated files use generic names such as `dci_registry`,
`dci_record_sd_jwt`, `DCI_CLIENT_ID`, and `DCI_CLIENT_SECRET`. The generated
YAML is intentionally explicit; it does not use `preset: opencrvs_birth_dci`.

## Step 3: Add The OpenCRVS Birth-Record Filters

The initializer already wrote the OpenCRVS base URL, OAuth token URL, lookup
field, and claim id from the command above. Open `dci-notary.yaml` and add the
OpenCRVS registry filters under `evidence.source_connections.dci_registry.dci`:

```yaml
dci:
  search_path: /registry/sync/search
  sender_id: registry-notary
  query_type: idtype-value
  registry_type: ns:org:RegistryType:Civil
  registry_event_type: birth
  records_path: /message/search_response/0/data/reg_records
```

After the edit, the generated source binding should still contain:

```yaml
lookup:
  input: subject_id
  field: UIN
  op: eq
  cardinality: one
```

That is the OpenCRVS-specific subject lookup used by the demo environment.

## Step 4: Add OpenCRVS OAuth Credentials

Edit `.env.local`:

```dotenv
DCI_CLIENT_ID=paste-client-id-here
DCI_CLIENT_SECRET=paste-client-secret-here
```

Keep the file private:

```bash
chmod 600 .env.local
```

Do not add an OpenCRVS bearer token. Registry Notary fetches and refreshes
source tokens from the configured OAuth client-credentials endpoint.

## Step 5: Inspect And Diagnose

```bash
registry-notary explain-config \
  --config dci-notary.yaml \
  --env-file .env.local
```

Then run local diagnostics:

```bash
registry-notary doctor \
  --config dci-notary.yaml \
  --env-file .env.local
```

Run the live OAuth and endpoint probe:

```bash
registry-notary doctor \
  --config dci-notary.yaml \
  --env-file .env.local \
  --live
```

If you have a known test UIN, run the record-level probe:

```bash
export OPENCRVS_TEST_UIN='<known test UIN>'

registry-notary doctor \
  --config dci-notary.yaml \
  --env-file .env.local \
  --live \
  --subject-id "$OPENCRVS_TEST_UIN"
```

The subject id and source token must not appear in diagnostic output.

## Step 6: Start Registry Notary

```bash
registry-notary \
  --config dci-notary.yaml \
  --env-file .env.local
```

In another terminal, load the local API key from `.env.local`:

```bash
set -a
. ./.env.local
set +a
```

## Step 7: Evaluate Evidence As JSON

Use a known test UIN from the OpenCRVS environment owner:

```bash
curl -fsS http://127.0.0.1:4255/claims/evaluate \
  -H "content-type: application/json" \
  -H "x-api-key: $REGISTRY_NOTARY_API_KEY" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci" \
  -d '{
    "subject": { "id": "'"$OPENCRVS_TEST_UIN"'" },
    "claims": ["opencrvs-birth-record-exists"],
    "disclosure": "value",
    "format": "application/vnd.registry-notary.claim-result+json"
  }' | jq .
```

Expected result shape:

```json
{
  "results": [
    {
      "claim_id": "opencrvs-birth-record-exists",
      "value": true
    }
  ]
}
```

## Step 8: Issue A Demo VC

When `--demo-issuer` was used, the generated config includes a local
`dci_record_sd_jwt` credential profile. Credential issuance uses a stored
evaluation, so first evaluate the claim in SD-JWT VC format and capture the
returned `evaluation_id`:

```bash
EVALUATION_ID="$(
  curl -fsS http://127.0.0.1:4255/claims/evaluate \
    -H "content-type: application/json" \
    -H "x-api-key: $REGISTRY_NOTARY_API_KEY" \
    -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci" \
    -d '{
      "subject": { "id": "'"$OPENCRVS_TEST_UIN"'" },
      "claims": ["opencrvs-birth-record-exists"],
      "disclosure": "value",
      "format": "application/dc+sd-jwt"
    }' | jq -r '.results[0].evaluation_id'
)"
```

Then issue the demo credential:

```bash
curl -fsS http://127.0.0.1:4255/credentials/issue \
  -H "content-type: application/json" \
  -H "x-api-key: $REGISTRY_NOTARY_API_KEY" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci" \
  -d '{
    "evaluation_id": "'"$EVALUATION_ID"'",
    "credential_profile": "dci_record_sd_jwt",
    "claims": ["opencrvs-birth-record-exists"],
    "disclosure": "value",
    "format": "application/dc+sd-jwt"
  }' | jq .
```

The response includes the selected credential profile and a verifiable
credential payload. The demo issuer key is local Registry Notary material. It
is not an OpenCRVS credential.

## Troubleshooting

If `doctor` reports missing `DCI_CLIENT_ID` or `DCI_CLIENT_SECRET`, check that
`.env.local` exists, has non-placeholder values, and is passed through
`--env-file`.

If OpenCRVS returns HTTP 400, check the DCI block:

- `query_type: idtype-value`
- `lookup.field: UIN`
- `registry_type: ns:org:RegistryType:Civil`
- `registry_event_type: birth`
- `records_path: /message/search_response/0/data/reg_records`

If OpenCRVS returns no records, the redacted sample UIN may not exist in that
test environment.

## Security Notes

- Do not commit `.env.local`.
- Do not commit OpenCRVS client credentials, bearer tokens, subject UINs, or
  generated issuer private keys.
- Do not store OpenCRVS access tokens in the config or env file.
