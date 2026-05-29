# OpenCRVS DCI Demo Notes

OpenCRVS is configured through normal DCI source settings. Registry Notary does
not contain an OpenCRVS-specific initializer or built-in source preset.

For the full standalone flow, see
[`opencrvs-dci-standalone-tutorial.md`](opencrvs-dci-standalone-tutorial.md).

## Generic Starter

Start with the generic DCI initializer:

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

Then edit `dci-notary.yaml` to include the OpenCRVS DCI filters:

```yaml
dci:
  search_path: /registry/sync/search
  sender_id: registry-notary
  query_type: idtype-value
  registry_type: ns:org:RegistryType:Civil
  registry_event_type: birth
  records_path: /message/search_response/0/data/reg_records
```

Use `.env.local` for the OpenCRVS OAuth client credentials:

```dotenv
DCI_CLIENT_ID=<OpenCRVS DCI client id>
DCI_CLIENT_SECRET=<OpenCRVS DCI client secret>
```

Do not fetch or store an OpenCRVS bearer token manually. The generated
`source_auth.type = oauth2_client_credentials` config handles token fetch and
refresh.

## Current Interop Boundaries

- The tested query shape is DCI `idtype-value` with `query.type = UIN`.
- The tested event filter is `registry_event_type = birth`.
- The OpenCRVS DCI middleware currently accepts unsigned requests. If request
  signatures become mandatory, Registry Notary needs DCI request signing and a
  discoverable JWKS for the configured `sender_id`.
- Death record checks should use a separate DCI source connection or claim with
  `registry_event_type: death`.
