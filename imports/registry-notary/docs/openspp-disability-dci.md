# OpenSPP Disability DCI Demo

This note documents the local Registry Witness demo config for using the
OpenSPP Disability Registry DCI API as an evidence source.

## Scope

The demo config is:

`demo/config/openspp-disability-registry-witness.yaml`

It targets:

`https://openspp-dci-demo-dr.genete.acn.fr/dci_api/v1/disability/registry/sync/search`

The tested query shape is DCI `idtype-value` with `query.type = NATIONAL_ID`.
The OpenSPP Disability test endpoint rejected `expression` and `predicate`
queries during integration testing.

## Environment

Set these environment variables before starting Registry Witness:

```bash
export REGISTRY_WITNESS_API_KEY_HASH='sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51'
export REGISTRY_WITNESS_AUDIT_HASH_SECRET='dev-registry-witness-audit-hash-secret'
export OPENSPP_DCI_TOKEN='<OpenSPP bearer token>'
export REGISTRY_WITNESS_ISSUER_JWK='<Ed25519 issuer private JWK for demo VC issuance>'
```

Then run:

```bash
cargo run -p registry-witness-bin -- \
  --config demo/config/openspp-disability-registry-witness.yaml
```

The API key hash above is for local key `api-token`.

## Claims

The demo exposes:

- `disability-registry-record-exists`
- `disability-has-disability`
- `disability-review-category`
- `disability-severity-code`
- `disability-next-review`

`disability-review-category` is typed as a string because the OpenSPP demo
returned values such as `mip`. `disability-severity-code` and
`disability-next-review` may be `null`.

## VC Profile

The demo profile is `openspp_disability_sd_jwt` and issues
`application/dc+sd-jwt` credentials for the five disability claims.

This profile uses `holder_binding.mode = none`. It is suitable only for local
machine-to-machine demo issuance. Do not treat it as a wallet-bound or
citizen-bound credential profile. A production or wallet flow should use
holder proof-of-possession, for example a `did:jwk` holder binding or the
OpenID4VCI credential endpoint.

## Current Interop Boundaries

- The OpenSPP test server currently accepts an empty DCI envelope `signature`.
  The demo config uses `signature: ""` only for that server. If OpenSPP starts
  enforcing DCI signatures, Registry Witness needs real DCI request signing for
  this connector.
- `receiver_id: openspp` is required by the OpenSPP request schema.
- `bulk_mode` is pinned to `none` because multi-item Disability DCI search
  returned HTTP 500 during testing. Keep DCI batched search disabled until the
  upstream endpoint returns one DCI response item per request item or a clean
  validation error.
- `/.well-known/jwks.json` returned an empty key set during testing, so
  response-signature verification could not be exercised.
