# Hosted Registry Lab Coolify Runbook

Visibility: internal operations note, not public documentation.

## Applications

Create two Coolify Docker Compose applications in the `registry-lab` project:

```text
Registry Lab       compose.coolify.yaml
Hosted eSignet     compose.esignet-hosted.yaml
```

Do not use the local `compose.yaml` or `compose.esignet-live.yaml` for hosted
Coolify apps.

## Domains

Assign domains in the Coolify UI, not through host ports:

```text
citizen-civil-notary              citizen-notary.lab.registrystack.org
civil-registry-relay              civil-relay.lab.registrystack.org
social-protection-registry-relay  social-relay.lab.registrystack.org
health-registry-relay             health-relay.lab.registrystack.org
static-metadata-publisher         metadata.lab.registrystack.org
zitadel                           zitadel.lab.registrystack.org
dhis2-health-notary               dhis2-notary.lab.registrystack.org
opencrvs-dci-notary               opencrvs-notary.lab.registrystack.org
esignet                           esignet.lab.registrystack.org
esignet-ui                        esignet-ui.lab.registrystack.org
```

Cloudflare DNS is already set up with `lab.registrystack.org` and
`*.lab.registrystack.org` in DNS-only mode. Before first certificate issuance,
confirm there is no effective `AAAA` record unless the host is reachable over
IPv6, and that any CAA policy permits Let's Encrypt.

## Required Registry Lab Secrets

Set these in the Registry Lab Coolify app before deploy:

```text
REGISTRY_LAB_POSTGRES_PASSWORD
ZITADEL_MASTERKEY
REGISTRY_NOTARY_AUDIT_HASH_SECRET
REGISTRY_NOTARY_ISSUER_JWK
CIVIL_EVIDENCE_SOURCE_RAW
OPENFN_SIDECAR_TOKEN_HASH
OPENFN_SIDECAR_TOKEN_RAW
OPENFN_DHIS2_HOST_URL
OPENFN_DHIS2_USERNAME
OPENFN_DHIS2_PASSWORD
DHIS2_EVIDENCE_CLIENT_TOKEN_HASH
DHIS2_EVIDENCE_CLIENT_BEARER_HASH
OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH
OPENCRVS_DCI_BASE_URL
OPENCRVS_DCI_CLIENT_ID
OPENCRVS_DCI_CLIENT_SECRET
OPENCRVS_DCI_SHA_SECRET
```

Set relay token hashes required by the mounted relay configs:

```text
REGISTRY_RELAY_AUDIT_HASH_SECRET
CIVIL_METADATA_CLIENT_HASH
CIVIL_EVIDENCE_SOURCE_HASH
CIVIL_EVIDENCE_ONLY_HASH
CIVIL_ROW_READER_HASH
SHARED_CIVIL_EVIDENCE_SOURCE_HASH
SOCIAL_METADATA_CLIENT_HASH
SOCIAL_EVIDENCE_SOURCE_HASH
SOCIAL_EVIDENCE_ONLY_HASH
SOCIAL_ROW_READER_HASH
SOCIAL_AGGREGATE_READER_HASH
SHARED_SOCIAL_EVIDENCE_SOURCE_HASH
HEALTH_METADATA_CLIENT_HASH
HEALTH_EVIDENCE_SOURCE_HASH
HEALTH_EVIDENCE_ONLY_HASH
HEALTH_ROW_READER_HASH
SHARED_HEALTH_EVIDENCE_SOURCE_HASH
```

For `registry-stack-technical-preview-2026-06-04`, the hosted compose files pin
the product images directly by digest:

```text
ghcr.io/jeremi/registry-relay@sha256:d3637632aec717b8212ae3a4f2dc0d59d581ad0b9b52bddc4bac1019977b5f3e
ghcr.io/jeremi/registry-notary@sha256:4705721671235e12ddcbd3cc6b2c8bc71f40764cca17599c2a7dbb25aa544137
ghcr.io/jeremi/registry-notary-openfn-sidecar@sha256:28b6c8f3673a12b45cfae97ed5d1c82505ed9eaccf7ee699c396eab7c0987d3f
```

The hosted config loaders also pin `CONFIG_REPO_REF` to
`registry-stack-technical-preview-2026-06-04`. Do not set Coolify overrides for
`REGISTRY_RELAY_IMAGE`, `REGISTRY_NOTARY_IMAGE`,
`REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE`, or `CONFIG_REPO_REF` for this release
unless you are deliberately rolling forward or rolling back and recording the
override.

For future release trains, use product-owned images published by the
corresponding product repositories:

```text
REGISTRY_RELAY_IMAGE=<product-owned-registry-relay-image>
REGISTRY_NOTARY_IMAGE=<product-owned-registry-notary-image-with-registry-notary-cel-and-pkcs11>
REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE=<product-owned-openfn-sidecar-image>
```

Pin by digest when available:

```text
REGISTRY_RELAY_IMAGE=<product-owned-registry-relay-image>@sha256:...
REGISTRY_NOTARY_IMAGE=<product-owned-registry-notary-image>@sha256:...
REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE=<product-owned-openfn-sidecar-image>@sha256:...
```

If product images are not published yet and Coolify is used to build locally,
use lab-local image tags such as `registry-relay:hosted`,
`registry-notary:hosted`, and `registry-notary-openfn-sidecar:hosted`. Do not
publish lab-built wrapper images under the canonical product image names. While
using those local tags, treat digest rollback as not yet satisfied and record
the selected Git revisions instead. The notary image used by the lab must be
built with `REGISTRY_NOTARY_FEATURES=registry-notary-cel,pkcs11`.

## Required eSignet Secrets

Set these in the hosted eSignet Coolify app before deploy:

```text
REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD
REGISTRY_LAB_ESIGNET_CLIENT_REDIRECT_URIS_JSON
```

`REGISTRY_LAB_ESIGNET_CLIENT_REDIRECT_URIS_JSON` must be a non-empty JSON array
of public HTTPS redirect URIs. The default hosted fallback is:

```json
["https://esignet-ui.lab.registrystack.org/callback"]
```

## Persistent Volumes

Registry Lab:

```text
postgres-data
redis-data
zitadel-seed
civil-registry-cache
social-protection-registry-cache
health-registry-cache
```

Hosted eSignet:

```text
esignet-postgres-data
esignet-redis-data
esignet-seed-data
```

Never mount eSignet seed output under repository `./output` in hosted mode.

## CI And Deploy

Configure this GitHub repository secret:

```text
COOLIFY_API_TOKEN
```

The `hosted-lab` workflow validates the hosted compose files and mounted hosted
configs. On `main`, after validation passes, it calls the Coolify REST API to
redeploy the registry-lab, hosted-esignet, and hosted-walt applications.

Local preflight:

```sh
just hosted-validate
just hosted-validate-test
```

Strict preflight from an environment that has the Coolify secret values:

```sh
just hosted-validate-strict
```

## Runtime Pitfalls

- The citizen notary `auth.oidc.issuer` must exactly match the hosted eSignet
  discovery document's `issuer`. Verify with:

  ```sh
  curl -fsS https://esignet.lab.registrystack.org/v1/esignet/oidc/.well-known/openid-configuration | jq -r .issuer
  ```

- The deployed `registry-notary` image must include the product-owned
  `registry-notary healthcheck` subcommand. The hosted compose intentionally
  uses that subcommand instead of `curl` so the distroless image can report
  health without a shell or package manager.
- The OpenCRVS notary config uses product-owned `${OPENCRVS_DCI_BASE_URL:?...}`
  expansion inside `registry-notary`; do not add a shell entrypoint wrapper for
  that service.
- The hosted eSignet compose corrects the seeded client redirect URIs after the
  local seed script runs. Check `esignet-seed` logs first if hosted login fails.
- The validator proves hosted artifacts are deploy-safe, but it cannot inspect
  Coolify UI domain assignments or Cloudflare settings. Verify those separately
  before phone-wallet testing.
