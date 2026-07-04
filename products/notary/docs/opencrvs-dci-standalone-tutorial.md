# Issue a demo credential from OpenCRVS

> **Page type:** Tutorial · **Product:** Registry Notary · **Layer:** evaluation, credential · **Audience:** integrator

Use this tutorial to run Registry Notary locally, query OpenCRVS for a test
birth record, and issue a local demo Selective Disclosure JSON Web Token
Verifiable Credential (SD-JWT VC).

This tutorial does not cover JSON claim results or batch evaluation. Those are
system-to-system evaluation topics.

## What you will test

You will:

- Generate a local Registry Notary config for OpenCRVS.
- Add OpenCRVS birth-record query settings.
- Add OpenCRVS OAuth client credentials.
- Check the live OpenCRVS connection with a known test UIN.
- Issue a demo SD-JWT VC from the OpenCRVS evidence result.

Registry Notary runs locally at:

```text
http://127.0.0.1:4255
```

Registry Notary calls the OpenCRVS API at:

```text
https://dci-crvs-api.farajaland-integration.opencrvs.dev
```

The tutorial evaluates this claim:

```text
opencrvs-birth-record-exists
```

## Before you start

You need:

- A `registry-notary` binary built from this repository.
- `curl`.
- `jq`.
- An OpenCRVS OAuth client ID and client secret.
- A known test UIN from the OpenCRVS environment owner.

From the `registry-notary` repository root, build the binary when you do not
already have one:

```bash
export REGISTRY_NOTARY_REPO="$PWD"
cargo build --release -p registry-notary
export PATH="$PWD/target/release:$PATH"
registry-notary --help
```

## Create the local config

Create a working folder:

```bash
mkdir -p "$HOME/opencrvs-notary-demo"
cd "$HOME/opencrvs-notary-demo"
```

Generate a generic DCI starter config:

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

The command writes `dci-notary.yaml`, `.env.local`, `.env.local.example`, and
`README.dci.md`.

`--demo-issuer` creates local Registry Notary signing material for the demo
credential. It does not create an OpenCRVS credential.

## Configure the OpenCRVS query

Open `dci-notary.yaml`.

Under `evidence.source_connections.dci_registry.dci`, add the OpenCRVS registry
filters:

```yaml
dci:
  search_path: /registry/sync/search
  sender_id: registry-notary
  query_type: idtype-value
  registry_type: ns:org:RegistryType:Civil
  registry_event_type: birth
  records_path: /message/search_response/0/data/reg_records
```

In the generated source binding, change the lookup to read the UIN from the
request identifier:

```yaml
lookup:
  input: target.identifiers.UIN
  field: UIN
  op: eq
  cardinality: one
```

## Add OpenCRVS credentials

Edit `.env.local`:

```dotenv
DCI_CLIENT_ID=paste-client-id-here
DCI_CLIENT_SECRET=paste-client-secret-here
```

Keep `.env.local` private:

```bash
chmod 600 .env.local
```

Do not add an OpenCRVS bearer token. Registry Notary fetches and refreshes the
source token from the configured OAuth client-credentials endpoint.

## Check the OpenCRVS connection

Run local config checks:

```bash
registry-notary doctor \
  --config dci-notary.yaml \
  --env-file .env.local
```

Set the known test UIN:

```bash
export OPENCRVS_DEMO_SUBJECT_UIN='<known test UIN>'
```

Run the live OAuth and record probe:

```bash
registry-notary doctor \
  --config dci-notary.yaml \
  --env-file .env.local \
  --live \
  --target-id "$OPENCRVS_DEMO_SUBJECT_UIN"
```

`doctor` must not print the source token or target UIN.

## Start Registry Notary

Start the server:

```bash
registry-notary \
  --config dci-notary.yaml \
  --env-file .env.local
```

In another terminal, load the local API key from `.env.local`:

```bash
cd "$HOME/opencrvs-notary-demo"
set -a
. ./.env.local
set +a
```

## Evaluate the OpenCRVS claim

Evaluate the claim in SD-JWT VC format and capture the stored evaluation ID:

```bash
EVALUATION_ID="$(
  curl -fsS http://127.0.0.1:4255/v1/evaluations \
    -H "content-type: application/json" \
    -H "x-api-key: $REGISTRY_NOTARY_API_KEY" \
    -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci" \
    -d '{
      "target": {
        "type": "Person",
        "identifiers": [
          {
            "scheme": "UIN",
            "value": "'"$OPENCRVS_DEMO_SUBJECT_UIN"'",
            "issuer": "opencrvs"
          }
        ]
      },
      "relationship": { "type": "service_delivery" },
      "claims": ["opencrvs-birth-record-exists"],
      "disclosure": "value",
      "format": "application/dc+sd-jwt"
    }' | jq -r '.results[0].evaluation_id'
)"

test -n "$EVALUATION_ID"
```

## Issue the demo credential

Issue the demo credential from the stored evaluation:

```bash
curl -fsS http://127.0.0.1:4255/v1/credentials \
  -H "content-type: application/json" \
  -H "x-api-key: $REGISTRY_NOTARY_API_KEY" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci" \
  -d '{
    "evaluation_id": "'"$EVALUATION_ID"'",
    "credential_profile": "dci_record_sd_jwt",
    "claims": ["opencrvs-birth-record-exists"],
    "disclosure": "value",
    "format": "application/dc+sd-jwt"
  }' | jq '{
    credential_profile,
    format,
    credential_present: (.credential != null)
  }'
```

Expected result:

```json
{
  "credential_profile": "dci_record_sd_jwt",
  "format": "application/dc+sd-jwt",
  "credential_present": true
}
```

The credential is a demo SD-JWT VC issued by Registry Notary from OpenCRVS
evidence. It is not an OpenCRVS-issued credential.
The generated `dci_record_sd_jwt` profile sets `holder_binding.mode: none`, so
this direct demo request does not require wallet holder material.

## Issue a birth-attributes credential

Now issue a second credential from the same OpenCRVS record. This credential
discloses the child's given name, family name, date of birth, and place of
birth. Use it only when the relying party needs those attributes, because it
exposes more personal data than the boolean existence credential.

Copy the provided config into your demo folder:

```bash
cd "$HOME/opencrvs-notary-demo"
cp "$REGISTRY_NOTARY_REPO/demo/config/opencrvs-dci-birth-attributes-registry-notary.yaml" \
  ./opencrvs-birth-attributes-notary.yaml
```

The config uses these live-tested OpenCRVS record paths:

```yaml
field_paths:
  child_given_name: /name/given_name
  child_family_name: /name/surname
  child_birth_date: /birth_date
  child_place_of_birth: /birth_place
```

It models each attribute as an `extract` claim, then issues one SD-JWT VC
profile named `opencrvs_birth_attributes_sd_jwt` that allows those claims.

Run the checks:

```bash
registry-notary doctor \
  --config opencrvs-birth-attributes-notary.yaml \
  --env-file .env.local \
  --live \
  --target-id "$OPENCRVS_DEMO_SUBJECT_UIN"
```

Stop the first Registry Notary process, then start the attribute config:

```bash
registry-notary \
  --config opencrvs-birth-attributes-notary.yaml \
  --env-file .env.local
```

Evaluate and issue the attribute credential:

```bash
ATTRIBUTE_EVALUATION_ID="$(
  curl -fsS http://127.0.0.1:4255/v1/evaluations \
    -H "content-type: application/json" \
    -H "x-api-key: $REGISTRY_NOTARY_API_KEY" \
    -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci" \
    -d '{
      "target": {
        "type": "Person",
        "identifiers": [
          {
            "scheme": "UIN",
            "value": "'"$OPENCRVS_DEMO_SUBJECT_UIN"'",
            "issuer": "opencrvs"
          }
        ]
      },
      "relationship": { "type": "service_delivery" },
      "claims": [
        "opencrvs-child-given-name",
        "opencrvs-child-family-name",
        "opencrvs-child-date-of-birth",
        "opencrvs-child-place-of-birth"
      ],
      "disclosure": "value",
      "format": "application/dc+sd-jwt"
    }' | jq -r '.results[0].evaluation_id'
)"

curl -fsS http://127.0.0.1:4255/v1/credentials \
  -H "content-type: application/json" \
  -H "x-api-key: $REGISTRY_NOTARY_API_KEY" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci" \
  -d '{
    "evaluation_id": "'"$ATTRIBUTE_EVALUATION_ID"'",
    "credential_profile": "opencrvs_birth_attributes_sd_jwt",
    "claims": [
      "opencrvs-child-given-name",
      "opencrvs-child-family-name",
      "opencrvs-child-date-of-birth",
      "opencrvs-child-place-of-birth"
    ],
    "disclosure": "value",
    "format": "application/dc+sd-jwt"
  }' | jq '{
    credential_profile,
    format,
    credential_present: (.credential != null)
  }'
```

Expected result:

```json
{
  "credential_profile": "opencrvs_birth_attributes_sd_jwt",
  "format": "application/dc+sd-jwt",
  "credential_present": true
}
```

## Optional: use name and date of birth instead of UIN

If your OpenCRVS environment supports expression search over birth-record
fields, use the demographic demo config instead of the UIN lookup config:

```text
demo/config/opencrvs-dci-demographic-registry-notary.yaml
```

That config queries OpenCRVS with these target attributes:

```yaml
dci:
  query_type: expression

source_bindings:
  birth_record:
    lookup:
      input: target.attributes.given_name
      field: given_name
      op: eq
      cardinality: one
    query_fields:
      - input: target.attributes.given_name
        field: given_name
        op: eq
      - input: target.attributes.family_name
        field: surname
        op: eq
      - input: target.attributes.birthdate
        field: birth_date
        op: eq
```

The evaluation request uses attributes instead of identifiers:

```json
{
  "target": {
    "type": "Person",
    "attributes": {
      "given_name": "Amina",
      "family_name": "Diallo",
      "birthdate": "2020-01-02"
    }
  },
  "relationship": { "type": "service_delivery" },
  "claims": ["opencrvs-birth-record-exists-by-demographics"],
  "disclosure": "value",
  "format": "application/dc+sd-jwt"
}
```

Use it when the tester knows the exact first name, last name, and date of birth
in the OpenCRVS test environment. If the same demographic combination can match
more than one birth record, Registry Notary rejects the result as ambiguous.

The same binding-level `query_fields` shape is available for
`registry_data_api`. Use
`demo/config/opencrvs-rda-demographic-registry-notary.yaml` when the source is a
Registry Relay endpoint instead of a DCI endpoint. Relay must allow filters on
`given_name`, `surname`, and `birth_date`.

## Known limitations

- The supported DCI query shape is `idtype-value` with `query.type = UIN`.
- The birth-attributes credential uses UIN lookup. The supported OpenCRVS
  record paths are `/name/given_name`, `/name/surname`, `/birth_date`, and
  `/birth_place`.
- The demographic demo config uses DCI `expression` query fields for OpenCRVS
  deployments that expose first-name, last-name, and date-of-birth search. The
  Farajaland integration endpoint does not narrow expression searches (this is
  an external endpoint limitation), so the UIN path is the supported credential
  path for that environment.
- The supported event filter is `registry_event_type: birth`.
- The OpenCRVS middleware accepts unsigned requests.
- Death record checks require a separate source connection or claim with
  `registry_event_type: death`.

## Troubleshooting

If `doctor` reports a missing `DCI_CLIENT_ID` or `DCI_CLIENT_SECRET`, check that
`.env.local` contains non-placeholder values and that you passed
`--env-file .env.local`.

If the live OAuth check fails, check the OpenCRVS client ID, client secret, and
token URL.

If OpenCRVS returns HTTP 400, check these values in `dci-notary.yaml`:

- `query_type: idtype-value`
- `lookup.input: target.identifiers.UIN`
- `lookup.field: UIN`
- `registry_type: ns:org:RegistryType:Civil`
- `registry_event_type: birth`
- `records_path: /message/search_response/0/data/reg_records`

If OpenCRVS returns no records, ask the OpenCRVS environment owner to confirm
that the test UIN exists in that environment.

## Security notes

- Do not commit `.env.local`.
- Do not commit OpenCRVS client credentials, bearer tokens, test UINs, or
  generated issuer private keys.
- Do not store OpenCRVS access tokens in the config or env file.
- The generated demo credential profile uses `holder_binding.mode: none` for
  direct local issuance. For citizen-wallet issuance, create a profile with
  `holder_binding.mode: did`, `proof_of_possession: required`, and
  `allowed_did_methods: [did:jwk]`.
