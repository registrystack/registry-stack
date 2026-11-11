# Reference ThunderID identity prerequisite

This reference pins the upstream ThunderID 1.0.1 OCI chart and image and
prepares them for Restricted admission and recovery. It qualifies one synthetic
App Kit human sign-in and one machine token against the same-release BReg.

## Fixed qualification identity

| Input | Value |
| --- | --- |
| Namespace | `registry-identity-qualification` |
| OIDC issuer | `https://identity.registry-qualification.test` |
| App Kit origin | `https://app.registry-qualification.test` |
| Browser client | `app-kit`, confidential, exact callback `/auth/callback` |
| Synthetic user | `qualification-officer` |
| Machine client | `qualification-client`, ES256 `private_key_jwt` |
| Chart | `oci://ghcr.io/thunder-id/helm-charts/thunderid`, version `1.0.1` |
| Chart manifest | `sha256:f54599dc3715fe054576c4a8351b7346f153205d17f6b553f82fab11c4536218` |
| Image | `ghcr.io/thunder-id/thunderid@sha256:d3c0613ff447a551fd440768a15bdfb6668948e80809cbb50f82d6752f22ab3e` |
| PostgreSQL role | `registry_identity` |
| PostgreSQL databases | `thunderid_config`, `thunderid_runtime_transient`, `thunderid_entity`, `thunderid_runtime_persistent` |

The issuer string is an identity key. Do not change its spelling, port, or
trailing slash after generation without treating every generated `sub` as a
migration.

## Environment prerequisites

These objects must already exist in the qualification namespace. The chart
references them and never creates their values.

- `registry-identity-postgres`, key `password`, for the dedicated
  `registry_identity` role. The four databases are owned by that role.
- `registry-identity-admin`, keys `username` and `password`.
- `registry-identity-fixture-credentials`, keys `app-kit-client-secret` and
  `qualification-officer-password`. Use synthetic values only.
  File-backed values must not contain a trailing newline or other surrounding
  whitespace. Kubernetes preserves those bytes in an environment variable,
  while an HTML password input cannot submit a newline. Normalize and compare
  byte digests before creating both the identity and App Kit Secrets.
- `registry-identity-tls`, keys `tls.crt` and `tls.key`. The leaf must have the
  issuer DNS SAN, critical `CA:FALSE`, and `serverAuth`, and must be signed by
  a private qualification CA. Do not use a self-signed leaf as its own trust
  anchor.
- The corresponding pure CA certificate, without the leaf or private key,
  available as `qualification-root-ca.pem` to Registry Stack workloads and
  local qualification clients.
- PostgreSQL serving a certificate for
  `registry-postgres.registry-k3s-proof.svc.cluster.local`. Its CA becomes the
  `postgres-ca.pem` member of `registry-identity-material`.
- The database owner has applied each matching upstream schema from ThunderID
  commit `12f517c4384004e360e26eb7eb1ab0501b678bb2`: `backend/dbscripts/configdb/postgres.sql`
  to `thunderid_config`, `backend/dbscripts/runtime_transient/postgres.sql` to
  `thunderid_runtime_transient`, `backend/dbscripts/entitydb/postgres.sql` to
  `thunderid_entity`, and `backend/dbscripts/runtime_persistent/postgres.sql`
  to `thunderid_runtime_persistent`. The ThunderID 1.0.1 chart's database
  init container covers SQLite. Apply the PostgreSQL schemas separately.
- DNS, or qualification-only hosts entries, mapping both stable hostnames to
  the K3s Traefik endpoint.

`values.reference.yaml` uses `sslmode=verify-full` for every database. lib/pq
reads `PGSSLROOTCERT`, and the upstream chart's declarative-resource ConfigMap
volume places the CA at the named path in setup and runtime. There is no
`require` or plaintext fallback.

## Generate exact identity resources

Create an owner-only synthetic machine key directory. It must not exist.

```bash
node deploy/identity/generate-qualification-key.mjs /absolute/private/qualification-key
mkdir -p deploy/identity/keys
cp /absolute/private/qualification-key/qualification-client.jwks.json deploy/identity/keys/
```

Do not commit the generated `keys/` directory or private JWK. Configure BReg
with the exact HTTPS issuer, its resource audience, and
`allowedClients: [app-kit, qualification-client]`. The example deployment uses
the `directory-editor` profile from `products/breg/examples/minimal`:
`registry:directory:write`, purpose `directory-administration`, and the literal
`jurisdiction` row claim.

Run the same-release generator. The output directory must not exist.

```bash
rstack identity check deploy/identity/identity-deployment.yaml
rstack identity generate thunderid \
  --deployment deploy/identity/identity-deployment.yaml \
  --output /absolute/private/identity-out \
  --breg-project /absolute/breg/project \
  --breg-runtime-config /absolute/breg/runtime.yaml \
  --breg-production
node deploy/identity/augment-app-kit-resources.mjs \
  /absolute/private/identity-out/resources/resources.yaml \
  /absolute/private/identity-out/resources/resources.app-kit.yaml
```

Use `resources.app-kit.yaml` as the `resources` key prepared below. The narrow
augmentation adds the App Kit-only `registry_role=contact-editor` and
`registry_scopes=registry:directory:write` user attributes to ThunderID's
upstream declarative input and token attributes. App Kit v0.44 selects the
configured role from the former and checks the configured BReg scope against
the latter. BReg facts remain the authority for principal, purpose, scope and
row claims.

`identity-receipt.json` must pin the beta-58 image digest and list only
`APP_KIT_CLIENT_SECRET` and `QUALIFICATION_OFFICER_PASSWORD` under
`requiredEnvironment`. Preserve the receipt as deployment evidence. The
database, TLS and key custody remain environment-owned.

Prepare Kubernetes material from the generated public resources and PostgreSQL
CA. This command prints no value. Treat its output as private deployment
material even though the generated identities contain only public keys and
secret placeholders.

```bash
deploy/identity/prepare-material.sh \
  /absolute/private/identity-out \
  /absolute/private/postgres-ca.pem \
  /absolute/private/identity-k8s-material
```

## Render and install in the isolated namespace

Verify the exact OCI chart content before rendering:

```bash
helm pull oci://ghcr.io/thunder-id/helm-charts/thunderid \
  --version 1.0.1 --destination /absolute/private/chart
printf '%s  %s\n' \
  f6fd424047932405d3d8f50d6ef69798f10626563828c1d1bed186efba99dc4d \
  /absolute/private/chart/thunderid-1.0.1.tgz | shasum -a 256 -c -
helm template thunderid /absolute/private/chart/thunderid-1.0.1.tgz \
  --namespace registry-identity-qualification \
  --values deploy/identity/values.reference.yaml \
  >/absolute/private/thunderid-rendered.yaml
```

ThunderID chart 1.0.1 spells the dropped capability as lowercase `all`.
Restricted Pod Security requires canonical `ALL`. Helm 4 no longer accepts an
executable post-renderer, so prepare a reviewed local chart directory. The
script first verifies the exact upstream content digest, then changes only the
two lowercase scalars in the Deployment and setup Job templates.

```bash
deploy/identity/prepare-restricted-chart.sh \
  /absolute/private/chart/thunderid-1.0.1.tgz \
  /absolute/private/chart-restricted
helm template thunderid /absolute/private/chart-restricted/thunderid \
  --namespace registry-identity-qualification \
  --values deploy/identity/values.reference.yaml \
  >/absolute/private/thunderid-rendered-restricted.yaml
```

Review the restricted render, then apply only inside the new namespace:

```bash
sudo -n k3s kubectl apply -f /absolute/private/identity-k8s-material/
helm install thunderid /absolute/private/chart-restricted/thunderid \
  --namespace registry-identity-qualification \
  --values deploy/identity/values.reference.yaml \
  --values deploy/identity/values.bootstrap-defaults.yaml \
  --wait --wait-for-jobs --timeout 10m
helm upgrade thunderid /absolute/private/chart-restricted/thunderid \
  --namespace registry-identity-qualification \
  --values deploy/identity/values.reference.yaml \
  --wait --timeout 10m
```

The first install deliberately requests zero serving replicas, disables
declarative resources, makes the explicit stores mutable, and mounts only the
PostgreSQL CA into the setup Job. This creates ThunderID's built-in password
flow before the upgrade starts the declarative App Kit application. Combining
both stages on a fresh database fails because the application references that
flow before it exists.

The generator's `registry-schema/` output needs one additional stateful setup
that the 1.0.1 chart does not run. Stop serving, mount the generated agent
documents alongside ThunderID's shipped bootstrap bundle, run the pinned
upstream `setup.sh` Job once, then resume one replica. Do not rerun it against
retained state without reviewing upstream bootstrap semantics.

```bash
sudo -n k3s kubectl -n registry-identity-qualification scale deployment/thunderid-deployment --replicas=0
sudo -n k3s kubectl -n registry-identity-qualification rollout status deployment/thunderid-deployment --timeout=2m
sudo -n k3s kubectl apply -f deploy/identity/schema-bootstrap-job.yaml
sudo -n k3s kubectl -n registry-identity-qualification wait \
  --for=condition=complete job/thunderid-registry-schema --timeout=5m
sudo -n k3s kubectl -n registry-identity-qualification scale deployment/thunderid-deployment --replicas=1
sudo -n k3s kubectl apply -f deploy/identity/edge.yaml
sudo -n k3s kubectl -n registry-identity-qualification rollout status deployment/thunderid-deployment --timeout=5m
```

## Qualify a real token and browser session

The token driver signs a one-minute client assertion, requests a resource-bound
token, verifies its JWT signature, issuer, audience and expiry, then discards
it. It never prints the assertion, key, bearer token or response body.

```bash
NODE_EXTRA_CA_CERTS=/absolute/private/qualification-root-ca.pem \
IDENTITY_ISSUER=https://identity.registry-qualification.test \
IDENTITY_CLIENT_ID=qualification-client \
IDENTITY_PRIVATE_JWK_FILE=/absolute/private/qualification-key/qualification-client.private.jwk \
IDENTITY_RESOURCE=urn:registry:qualification:breg \
IDENTITY_SCOPES='registry:directory:write' \
deploy/identity/qualify-oidc.sh
```

When qualification DNS must remain unchanged, set
`IDENTITY_CONNECT_ADDRESS` and optionally `IDENTITY_CONNECT_PORT`. The driver
still sends and verifies TLS for the stable issuer hostname. The override
selects the test socket. Port 80 must not serve issuer discovery.

The browser driver uses App Kit's installed Playwright. It opens App Kit,
follows its real Authorization Code with PKCE redirect, signs in the synthetic
officer, waits for the callback, and confirms App Kit created a server session.
The password stays in an owner-only file.

```bash
NODE_EXTRA_CA_CERTS=/absolute/private/qualification-root-ca.pem \
APPKIT_PROJECT=/absolute/registry-app-kit/project \
APPKIT_LIVE_URL=https://app.registry-qualification.test \
APPKIT_EXPECTED_ISSUER=https://identity.registry-qualification.test \
APPKIT_SYNTHETIC_USERNAME=qualification-officer \
APPKIT_SYNTHETIC_PASSWORD_FILE=/absolute/private/qualification-officer-password \
node deploy/identity/browser-login.mjs
```

For a private lab reachable only through SSH, start a scoped SOCKS proxy and
set `APPKIT_PROXY_SERVER`, `APPKIT_HOST_RESOLVER_RULES`, and
`APPKIT_TLS_SPKI`. The SPKI value is the base64 SHA-256 digest of the exact
qualification leaf public key. Chromium then accepts only that pinned private
certificate, rather than disabling certificate validation globally. The
driver first proves an anonymous `/api/model` request is refused with 401,
then proves the authenticated session and model read are allowed. It performs
no application write by default.

For restored-state acceptance, set `APPKIT_RETAINED_RECORD_IDS` to the
comma-separated synthetic contact UUIDs that must survive. After sign-in the
same browser session reads every retained record, creates and reads one new
`zone-a` contact, and requires a `403` for an otherwise identical `zone-b`
create. This mode intentionally writes one synthetic permitted record. Its
diagnostics contain only the retained and created record IDs and fixed phase
results, never URLs, cookies, authorization codes, state, tokens, response
bodies or raw Playwright errors.

## Backup and restore inputs

A clean-target restore needs a transactionally consistent backup of all four
ThunderID PostgreSQL databases and both chart PVCs. The certificates PVC owns
ThunderID encryption and signing keys. The secrets PVC owns the direct-auth
secret. The certs archive contains `crypto.key`, `ecdsa-signing.cert`,
`ecdsa-signing.key`, `server.cert`, `server.key`, `signing.cert` and
`signing.key`. The secrets archive contains `direct_auth_secret`. Also retain
the ingress TLS leaf, key and pure CA, the generated
declarative bundle and receipt, the registry schema, the public client JWK,
and the external admin, App Kit, synthetic user, PostgreSQL and CA inputs. The
machine client's private JWK is needed only when that synthetic client must
retain its identity.

A matching signing-key JWK thumbprint plus a fresh login proves signing-key
continuity and new authentication. When session retention is required, verify
that a pre-backup browser cookie resolves against the restored ThunderID and
App Kit state before performing the fresh login.

### Clean-target restored-state sequence

Wait until the PostgreSQL owner confirms all four identity databases are
restored and reachable with `sslmode=verify-full`. Recreate the referenced
Secrets and ConfigMaps from normalized fixture inputs, the PostgreSQL CA, the
augmented declarative bundle and the CA-signed issuer leaf. Preserve the
issuer hostname and callback exactly.

Prepare the digest-verified Restricted chart as above, then make a restore-only
copy. This prepares both durable claims and their runtime mounts independently
of `setup.enabled`. Keep the setup Job disabled during recovery.

```bash
deploy/identity/prepare-restored-state-chart.sh \
  /absolute/private/chart-restricted/thunderid \
  /absolute/private/chart-restored-state
```

Install the restore-only chart with zero serving replicas and setup disabled.
Its pre-install hooks create the two empty claims without changing restored
database state:

```bash
helm install thunderid /absolute/private/chart-restored-state \
  --namespace registry-identity-qualification \
  --values deploy/identity/values.reference.yaml \
  --values deploy/identity/values.restore-create.yaml \
  --wait --timeout 5m
```

With the Deployment still at zero, restore the complete certs archive into
`thunderid-certs-pvc` and the complete secrets archive into
`thunderid-secrets-pvc`, preserving ownership and mode. Confirm the expected
filenames listed above. Keep `setup.sh` and the fresh schema Job disabled
against restored state.

Start the retained state with setup still disabled, then expose only the
HTTPS Ingress:

```bash
helm upgrade thunderid /absolute/private/chart-restored-state \
  --namespace registry-identity-qualification \
  --values deploy/identity/values.reference.yaml \
  --values deploy/identity/values.restored-state.yaml \
  --wait --timeout 5m
sudo -n k3s kubectl apply -f deploy/identity/edge.yaml
```

Before connecting App Kit, verify HTTPS discovery, the exact issuer, HTTP
refusal, and the signing JWK thumbprint. Then issue a fresh synthetic machine
token and run the real browser driver. Prove a pre-backup browser cookie
separately when session retention is a restore acceptance criterion.
