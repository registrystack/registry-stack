# Coolify Hosted Lab Deployment Spec

Page type: deployment spec
Product: Registry Lab, Registry Notary, Registry Relay, eSignet, Coolify
Layer: deployment, credential, wallet interop
Audience: maintainers, demo operators, wallet integrators
Visibility: internal planning note, not public documentation

## Purpose

Define the hosted Registry Lab deployment for phone wallet and live-service
testing on `*.lab.registrystack.org`.

The first deployment should let a real phone wallet discover the Registry Notary
OID4VCI issuer, authenticate through a reachable eSignet deployment, request a
nonce, submit a holder proof, and store a `dc+sd-jwt` credential. The same
hosted lab should also support the live DHIS2/OpenFn Notary and OpenCRVS DCI
Notary as public HTTPS evidence services once the wallet-critical path is
stable.

The hosted lab should be durable enough for repeated demos and integration
testing. It should not depend on local-only scripts, localhost URLs, or secrets
that change on every deploy.

## Design Thesis

Registry Lab has two different operating modes:

- Local lab: developer-oriented, script-driven, disposable, and optimized for
  `just generate`, `just up`, and smoke checks.
- Hosted lab: public-origin, long-running, stable, and optimized for real
  wallet, eSignet, and integrator traffic.

The hosted lab should use the same product surfaces as the local lab, but it
should promote the wallet-facing flow into normal services and stable
deployment config. `just citizen-oid4vci-code` remains a probe, not the hosting
mechanism.

Coolify should run the hosted environment. GitHub Actions should gate and build
deployable revisions before Coolify updates the public lab.

## Deployment Target

The hosted lab runs on the existing shared Coolify host that already serves a
production stack. Capacity is not the primary constraint; isolation and blast
radius are.

Host facts that shape this spec:

- Published container ports bypass the host firewall. Docker's DNAT routes
  published ports before the firewall's INPUT chain, so a `ports:` mapping is
  public on the host IP regardless of firewall rules. `compose.coolify.yaml`
  must therefore publish no host ports at all (see Coolify Deployment Model).
- TLS is Let's Encrypt over HTTP-01 only; no DNS-01 resolver is configured. Each
  subdomain gets its own per-host certificate automatically. There is no single
  wildcard certificate; `*.lab.registrystack.org` here means wildcard DNS plus
  per-host certs.
- HTTP-01 validates over port 80, so every subdomain A record must resolve to
  the host before Coolify can issue its certificate. DNS is a hard prerequisite
  for first deploy, not a parallel task.
- The box is shared with production. Prefer product-owned pre-built images so
  the host does not spend CPU or disk on lab builds, and run the lab as its own
  Coolify project (`registry-lab`, separate from the production project) for
  isolation.

## Goals

- Deploy Registry Lab as a Coolify-managed Docker Compose application.
- Use stable HTTPS origins under `*.lab.registrystack.org`.
- Make the citizen OID4VCI Notary a long-running service.
- Include hosted DHIS2/OpenFn and OpenCRVS DCI Notaries as public HTTPS
  evidence services after the wallet-critical path.
- Keep OID4VCI issuer metadata, endpoint URLs, signing material, and eSignet
  client configuration stable across deploys.
- Support automatic deployment from GitHub after CI passes.
- Support rollback by redeploying a known image tag or revision.
- Provide a simple phone-wallet test path: scan offer, authenticate, download
  credential, inspect Notary audit.

## Non-Goals

- Do not make Coolify deployment depend on interactive `just` commands.
- Do not use `localhost`, `127.0.0.1`, or host-only callback URLs in public
  issuer metadata.
- Do not regenerate OID4VCI signing keys, eSignet client material, or seeded
  demo identities on every deploy.
- Do not expose internal databases, Redis, sidecars, or one-shot demo clients to
  the public internet.
- Do not implement full production hardening, certification, wallet instance
  attestation, or a general-purpose issuer product in this deployment wave.
- Do not present the DHIS2 and OpenCRVS live demos as production integrations;
  they remain hosted evidence-service demos against their configured live
  sources.
- Do not use path-based routing for wallet issuer discovery unless a specific
  wallet proves it works. Prefer dedicated subdomains.

## Public Origins

Use dedicated origins for externally consumed services:

```text
citizen-notary.lab.registrystack.org
civil-relay.lab.registrystack.org
social-relay.lab.registrystack.org
health-relay.lab.registrystack.org
metadata.lab.registrystack.org
esignet.lab.registrystack.org
esignet-ui.lab.registrystack.org
zitadel.lab.registrystack.org
dhis2-notary.lab.registrystack.org
opencrvs-notary.lab.registrystack.org
```

Each origin resolves to the shared host (one wildcard DNS record
`*.lab.registrystack.org` is simplest) and receives its own Let's Encrypt
certificate over HTTP-01. There is no single wildcard certificate; see
Deployment Target.

The wallet-facing issuer origin is:

```text
https://citizen-notary.lab.registrystack.org
```

It must serve:

```text
/.well-known/openid-credential-issuer
/oid4vci/credential-offer
/oid4vci/nonce
/oid4vci/credential
```

The issuer metadata must advertise public HTTPS URLs only:

```text
CITIZEN_OID4VCI_CREDENTIAL_ISSUER=https://citizen-notary.lab.registrystack.org
CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT=https://citizen-notary.lab.registrystack.org/oid4vci/credential
CITIZEN_OID4VCI_OFFER_ENDPOINT=https://citizen-notary.lab.registrystack.org/oid4vci/credential-offer
CITIZEN_OID4VCI_NONCE_ENDPOINT=https://citizen-notary.lab.registrystack.org/oid4vci/nonce
```

## Cloudflare Configuration

Cloudflare is the DNS authority for `registrystack.org`. The lab subdomain must
be configured so Coolify can complete HTTP-01 certificate issuance and phone
wallets can reach unauthenticated OIDC/OID4VCI endpoints.

Required Cloudflare DNS records:

```text
Type  Name   Target
A     *.lab  <coolify-host-ipv4>
A     lab    <coolify-host-ipv4>      optional, only if lab.registrystack.org is used
```

Use `CNAME *.lab <coolify-hostname>` instead of `A *.lab <ip>` only if the
host has a stable DNS name controlled outside the lab deployment. Do not add an
`AAAA` record unless the host has working public IPv6 and Coolify is reachable
on IPv6 port 80 and 443.

Required Cloudflare record mode for first deploy:

- Set `*.lab` to DNS only, not proxied, until Coolify has issued certificates
  for the public origins.
- Keep TTL at Auto unless a planned host migration needs a shorter explicit
  value.

Current DNS status, verified externally on 2026-06-01:

- `lab.registrystack.org` has a DNS-only `A` record to the Coolify host.
- `*.lab.registrystack.org` has a DNS-only `CNAME` to
  `lab.registrystack.org`.
- Representative hostnames including `citizen-notary`, `esignet`,
  `dhis2-notary`, and `opencrvs-notary` resolve to the Coolify host.
- No effective `AAAA` record is published for the lab hostnames.
- No CAA record was returned for `lab.registrystack.org` or
  `registrystack.org`, so no zone CAA policy currently blocks Let's Encrypt.

If the team later enables the Cloudflare proxy for `*.lab`, the following
settings are mandatory before treating the lab as healthy:

- SSL/TLS mode is `Full (strict)`. Never use `Flexible`.
- Port 80 and 443 both reach the Coolify host from Cloudflare.
- No Cloudflare Access, WAF challenge, bot fight mode, mTLS requirement, or
  browser integrity check applies to:
  `/.well-known/*`, `/oid4vci/*`, `/v1/esignet/*`, `/auth/*`, `/oauth2/*`,
  `/v1/certs`, or the DHIS2/OpenCRVS notary evidence endpoints.
- Cache is bypassed for all wallet, OIDC, OID4VCI, eSignet, DHIS2, and OpenCRVS
  notary endpoints.
- No Transform Rule, Page Rule, redirect rule, minification rule, or header
  rewrite changes issuer URLs, discovery JSON, callback URLs, content types, or
  authorization headers.
- Either Cloudflare does not force HTTP to HTTPS for `*.lab`, or there is an
  explicit exception for `/.well-known/acme-challenge/*` so Let's Encrypt
  HTTP-01 can reach Coolify during new certificate issuance.

If the zone has CAA records, `letsencrypt.org` must be allowed to issue
certificates for `lab.registrystack.org` and its subdomains before Coolify
deployment starts.

## Coolify Deployment Model

The host runs Coolify v4 (currently `4.0.0-beta.462`). The existing production
apps are deployed as individual Coolify Application resources, one per repo, with
no host ports and Coolify-generated Traefik labels routing to them over the
internal `coolify` network. Registry Lab instead uses a single Docker Compose
resource, which Coolify v4 supports and which fits a stack whose services share
DNS, Postgres, and Redis. Domains are assigned per service in the Coolify UI; the
compose file itself carries no routing config (no `ports:`, no Traefik labels).

Use a hosted compose file separate from the local developer compose:

```text
compose.yaml
compose.coolify.yaml
```

`compose.yaml` remains the source of truth for local demos.
`compose.coolify.yaml` is the hosted lab contract. It is a dedicated,
hand-authored file, not an overlay or a copy of `compose.yaml`. The local
compose publishes a host port on every service and builds from sibling vendor
repos, neither of which is valid here, so the hosted file is written from
scratch to the constraints below.

The Coolify application should consume product-owned pre-built images when they
exist, not lab-built images published under product names. If images are not
published yet, a host build is possible only as an explicit fallback after
confirming Coolify checks out submodules and supports the named build contexts
required by the product Dockerfiles. Coolify supports Docker Compose as a build
pack, GitHub App auto-deploy, GitHub Actions-triggered deploys, and
webhook-triggered deploys; this spec uses the validation + webhook path and
leaves image ownership to the product repositories or explicit Coolify-local
builds.

References:

- https://coolify.io/docs/applications/build-packs/docker-compose
- https://coolify.io/docs/applications/ci-cd/github/auto-deploy
- https://coolify.io/docs/applications

Coolify-specific compose constraints:

- Publish no host ports. Remove every `ports:` mapping, including Postgres and
  Redis. On this host a published port is public because it bypasses the
  firewall (see Deployment Target). The local `compose.yaml` publishes a port on
  every service; none of those mappings may carry over.
- Expose HTTP services through Coolify domains, not host ports. Coolify
  generates the Traefik labels and certificate from the assigned domain and
  reaches the container over the internal app network; use `expose:` for the
  container port. Databases, Redis, sidecars, and one-shot tools get no domain
  and no port, so they stay private on the app network.
- Do not define custom Docker networks in `compose.coolify.yaml`; Coolify
  creates the application network and connects its proxy to it. The local
  compose's `internal: true` openfn network needs an explicit decision if any
  openfn service joins the hosted wave.
- Use Coolify environment variables, secrets, and persistent volumes for hosted
  state.

## Hosted Services

All services are in scope; they are brought up in the order given in Rollout
Priority, not cut. A single Postgres and a single Redis serve the whole lab:
Zitadel, the relays, and the notaries share them through separate databases and
key namespaces, so a new service does not get its own database container. The
services below are reconciled against the local `compose.yaml`.

Already in compose (carry over, strip ports):

```text
civil-registry-relay
social-protection-registry-relay
health-registry-relay
static-metadata-publisher
zitadel              (needs hosted-domain config; see Service Config Corrections)
postgres             (internal only)
redis                (internal only)
```

Net-new, must be added as a long-running service (see Citizen OID4VCI Service):

```text
citizen-civil-notary
```

Separate Coolify app from `compose.esignet-hosted.yaml`, not folded into
`compose.coolify.yaml` (see eSignet Contract):

```text
esignet
esignet-ui
```

Later-priority services (profile-gated locally, still in hosted scope):

```text
openfn-civil-notary
openfn-civil-sidecar
openfn-mock-registry
dhis2-health-notary
openfn-dhis2-sidecar
opencrvs-dci-notary
agri-registry-relay
nagdi-agriculture-notary
agri-static-metadata-publisher
```

Public exposure:

```text
citizen-civil-notary              citizen-notary.lab.registrystack.org
civil-registry-relay              civil-relay.lab.registrystack.org
social-protection-registry-relay  social-relay.lab.registrystack.org
health-registry-relay             health-relay.lab.registrystack.org
static-metadata-publisher         metadata.lab.registrystack.org
esignet                           esignet.lab.registrystack.org
esignet-ui                        esignet-ui.lab.registrystack.org
zitadel                           zitadel.lab.registrystack.org
dhis2-health-notary               dhis2-notary.lab.registrystack.org
opencrvs-dci-notary               opencrvs-notary.lab.registrystack.org
```

`esignet` and `esignet-ui` are hosted as a separate Coolify app from
`compose.esignet-hosted.yaml`, not in `compose.coolify.yaml` (see eSignet
Contract). The hosted eSignet compose may derive from the colleague-owned
`compose.esignet-live.yaml`, but the deployed artifact must be the hosted-safe
variant. The `citizen-civil-notary` row is the net-new OID4VCI service (see
Citizen OID4VCI Service). `openfn-dhis2-sidecar` stays internal even when
`dhis2-health-notary` is public.

Internal only:

```text
postgres
redis
openfn sidecars
demo clients
smoke runners
fixture generators
```

## Rollout Priority

All services above are in scope. Bring them up in this order; each step is
independently demoable and does not block planning the next.

1. Wallet critical path. Postgres, Redis, the three relays and
   `static-metadata-publisher` (running, internal), and the net-new
   `citizen-civil-notary` exposed at `citizen-notary.lab.registrystack.org`,
   against the external eSignet app. Goal: a phone wallet stores a credential.
2. Public read surfaces. Give the three relays and `static-metadata-publisher`
   their public domains once a consumer needs them browsable.
3. Zitadel. Bring up with hosted-domain config (Service Config Corrections) and
   settle its role relative to eSignet before exposing it.
4. Extended notaries and integrations. The profile-gated services (openfn,
   agri), each exposed only as its own wallet or integration path requires.
5. Live service notaries. Bring up `dhis2-health-notary` with its internal
   `openfn-dhis2-sidecar`, and `opencrvs-dci-notary` with live OpenCRVS
   credentials, as public HTTPS evidence services.

## Citizen OID4VCI Service

The hosted deployment must add a normal long-running service for the citizen
OID4VCI Notary. It should not be started by
`scripts/smoke-citizen-self-attestation.sh`.

This service does not exist in `compose.yaml` today. The citizen OID4VCI flow is
exercised only by `scripts/smoke-citizen-self-attestation.sh`,
`scripts/smoke-citizen-oid4vci.sh`, and the `just citizen-*` targets, all of
which point at a local eSignet on `http://localhost:8088`. Promoting it to a
service is net-new config work: a long-running notary process whose OID4VCI and
OIDC config resolve to public HTTPS URLs (hosted eSignet, not localhost:8088).

Recommended service name:

```text
citizen-civil-notary
```

(`citizen-civil-notary` reads close to the existing `civil-notary` service,
which is a separate SP-DCI notary. Pick a name that cannot be confused with it,
or keep this one only if the distinction is obvious to operators.)

Recommended command shape:

```text
registry-notary --config /etc/registry-notary/citizen-civil-notary.yaml
```

The binary is `registry-notary` (not `registry-notary-bin`); the existing notary
services mount their config under `/etc/registry-notary/` and pass only
`--config`. Match that pattern. The config should be rendered from hosted
environment variables or mounted as a Coolify-managed file. It must configure:

- OIDC issuer, discovery, JWKS, authorization server, token endpoint, and
  UserInfo endpoint for public eSignet.
- self-attestation subject binding for the seeded demo citizen.
- OID4VCI issuer URL and endpoints under
  `https://citizen-notary.lab.registrystack.org`.
- credential configuration id `person_is_alive_sd_jwt`.
- credential format `dc+sd-jwt`.
- proof type `jwt`.
- proof algorithm `EdDSA`.
- holder binding method `did:jwk`.
- nonce support.
- Redis replay storage when more than one Notary process can receive traffic.

## eSignet Contract

eSignet is not part of the main Registry Lab `compose.yaml`. The local lab uses
`compose.esignet-live.yaml` as a separate MOSIP eSignet Compose project with
Postgres, Redis, mock identity, eSignet, eSignet UI, and an `esignet-seed`
one-shot. That Compose file is ready as the source surface for the separate
Coolify eSignet app.

Run eSignet as its own Coolify Docker Compose app, pinned to MOSIP's published
images, and point the citizen notary at its public URL. Do not fold eSignet into
`compose.coolify.yaml` in the first wave. This gates the entire wallet path and
must be resolved before the wallet critical path deploy (Implementation Plan
Wave 2).

Hosted eSignet must customize the local `compose.esignet-live.yaml` defaults:

- remove every `ports:` mapping and assign Coolify domains instead;
- replace `localhost:8088`, `localhost:3000`, and local callback assumptions
  with public `esignet.lab.registrystack.org` and
  `esignet-ui.lab.registrystack.org` origins;
- rotate Postgres and service secrets away from local demo defaults;
- persist the eSignet Postgres volume and seeded client material;
- keep the `registry-lab-live-client` equivalent stable across deploys;
- write or mount the private key material needed for private-key-jwt token
  exchange without storing it under public `output/`.

The phone wallet must be able to reach the same authorization server that the
issuer metadata advertises. Hosted wallet testing therefore requires public
eSignet URLs, not local eSignet URLs.

Hosted eSignet must provide:

- public discovery URL;
- public browser authorization URL;
- public JWKS URL;
- public token endpoint;
- public UserInfo endpoint when subject binding uses UserInfo;
- registered client id for the wallet or Mimoto/Inji path;
- redirect URIs accepted by the wallet flow;
- seeded user whose bound identifier matches the lab fixtures.

Seeded citizen:

```text
identifier: NID-1001
name: Miguel Santos
credential configuration: person_is_alive_sd_jwt
expected claim: person-is-alive = true
```

Negative control:

```text
identifier: NID-1002
expected result: denied for self-attestation subject mismatch
```

## Live Service Notaries

The hosted lab should include the DHIS2 and OpenCRVS Notaries as public HTTPS
evidence services after the phone-wallet path is stable. These are not wallet
issuers in the first wave; they are live-source credential and evidence demos.

### DHIS2/OpenFn

Hosted services:

```text
dhis2-health-notary      public at https://dhis2-notary.lab.registrystack.org
openfn-dhis2-sidecar     internal only
```

The sidecar calls the configured DHIS2 Tracker API. The Notary exposes the
existing DHIS2 claims and credential profiles:

```text
claims:
  dhis2-child-program-active
  dhis2-maternal-pnc-active
  dhis2-child-health-visit-recorded
  dhis2-tb-program-active
  dhis2-tracked-entity-first-name
  dhis2-tracked-entity-last-name

credential profiles:
  dhis2_health_status_sd_jwt
  dhis2_child_program_sd_jwt
```

Hosted config changes from local:

- remove `ports:` from `openfn-dhis2-sidecar` and `dhis2-health-notary`;
- expose only `dhis2-health-notary` through Coolify;
- keep `openfn-dhis2-sidecar` private on the app network;
- move `OPENFN_DHIS2_USERNAME`, `OPENFN_DHIS2_PASSWORD`,
  `OPENFN_DHIS2_HOST_URL`, sidecar token material,
  `DHIS2_EVIDENCE_CLIENT_TOKEN_HASH`, and
  `DHIS2_EVIDENCE_CLIENT_BEARER_HASH` into Coolify secrets;
- update `api_base_url`, issuer DID, `kid`, and credential profile issuers away
  from `demo.example.gov` to hosted `did:web` values where credential
  verification depends on public resolution;
- add a Notary healthcheck and a hosted smoke that evaluates at least one
  positive and one negative DHIS2 claim.

### OpenCRVS DCI

Hosted service:

```text
opencrvs-dci-notary      public at https://opencrvs-notary.lab.registrystack.org
```

The Notary calls the configured OpenCRVS DCI API and exposes the existing
OpenCRVS claims and credential profiles:

```text
claims:
  opencrvs-birth-record-exists
  opencrvs-date-of-birth
  opencrvs-sex
  opencrvs-age-band
  opencrvs-birth-record-exists-by-demographics
  opencrvs-child-given-name
  opencrvs-child-family-name
  opencrvs-child-date-of-birth
  opencrvs-child-place-of-birth

credential profiles:
  opencrvs_birth_summary_sd_jwt
  opencrvs_birth_attributes_sd_jwt
```

Hosted config changes from local:

- remove the `ports:` mapping and expose only through Coolify;
- move `OPENCRVS_DCI_CLIENT_ID`, `OPENCRVS_DCI_CLIENT_SECRET`,
  `OPENCRVS_DCI_SHA_SECRET`, `OPENCRVS_DCI_BASE_URL`, and evidence client token
  material into Coolify secrets;
- do not rely on `.env.local`;
- update `api_base_url`, issuer DID, `kid`, and credential profile issuers away
  from `demo.example.gov` to hosted `did:web` values where credential
  verification depends on public resolution;
- add a Notary healthcheck and a hosted smoke that evaluates a live seeded UIN
  and issues `opencrvs_birth_attributes_sd_jwt`.

## Service Config Corrections (from local compose)

The local `compose.yaml` carries settings that break in a hosted, public-origin
deployment. The dedicated `compose.coolify.yaml` must not reproduce them:

- Zitadel is configured for localhost: `ZITADEL_EXTERNALDOMAIN: localhost`,
  `ZITADEL_EXTERNALSECURE: "false"`, `ZITADEL_EXTERNALPORT: 4380`, TLS disabled,
  and `zitadel-init.sh` receives `ZITADEL_PUBLIC_URL: http://localhost:4380`.
  Zitadel bakes the external domain and secure flag into its OIDC issuer and
  discovery, so hosted it must use
  `ZITADEL_EXTERNALDOMAIN=zitadel.lab.registrystack.org`,
  `ZITADEL_EXTERNALPORT=443`, `ZITADEL_EXTERNALSECURE=true`, running h2c behind
  Traefik. Left unchanged it emits exactly the localhost URLs this spec forbids.
  Zitadel is also the one exception to the "domains via the Coolify UI, no
  Traefik labels in the compose file" rule: its upstream speaks HTTP/2 cleartext,
  so it needs a custom Traefik label (`loadbalancer.server.scheme=h2c`) that a
  plain UI domain assignment does not set. Coolify allows per-service custom
  labels for exactly this. Confirm whether Zitadel is the IdP behind eSignet or
  unrelated to the wallet path; if unrelated, it does not belong in the first
  wave.
- Postgres SSL support is forward-compatible rather than currently
  load-bearing for the shipped hosted relay configs. The hosted relays are
  file-backed today, while Zitadel connects with
  `ZITADEL_DATABASE_POSTGRES_*_SSL_MODE: disable`. Keep the self-signed
  startup certificate support so future Postgres-backed relay configs can use
  `sslmode=require`, but do not treat relay Postgres SSL as proof that the
  current hosted relays exercise a database path. Confirm any future hosted
  relay Postgres usage with the relay team before making it a readiness gate.
- Every service in the local compose publishes a host port; none may carry over
  (see Coolify Deployment Model).
- `openfn-mock-registry`, `openfn-civil-sidecar`, and `openfn-civil-notary` run
  in the default profile locally (no `profiles:` guard), so a naive port of the
  compose would start them. Exclude them from the hosted wave or gate them
  behind a profile.
- `dhis2-health-notary`, `openfn-dhis2-sidecar`, and `opencrvs-dci-notary` are
  profile-gated locally, but they are explicitly in hosted scope. When added to
  `compose.coolify.yaml`, strip host ports, keep the DHIS2 sidecar private, and
  patch public `api_base_url` and credential issuer values.
- The local notary services (`x-notary-common`) define no healthcheck, unlike
  the relays, even though the notary binary already serves `/healthz` (the same
  endpoint the relay healthcheck probes). Hosted notaries use the product-owned
  `registry-notary healthcheck` subcommand instead of `curl`, so health gating
  works with the distroless product image.
- Redis runs as a pure cache locally (`--save "" --appendonly no`, and the
  declared `redis-data` volume is never mounted). That is fine for a single
  notary's in-memory nonce. If nonce or replay state must survive a Redis
  restart, or the notary is scaled, enable AOF and mount a persistent volume;
  make the compose match whichever the spec commits to.
- `compose.esignet-live.yaml` is a separate local Compose project and currently
  publishes eSignet, eSignet UI, mock identity, and Postgres ports. The deployed
  `compose.esignet-hosted.yaml` variant must remove those mappings, use public
  eSignet origins, keep the seed output private, and ensure the discovery
  document's `issuer` exactly matches the citizen notary `auth.oidc.issuer`.

## State And Secrets

Hosted auto-deploy must not rewrite identity-critical material.

Stable across deploys:

- OID4VCI issuer signing keys.
- Notary issuer JWK and JWKS material.
- eSignet client registration and client secrets.
- eSignet demo identity seed.
- DHIS2 sidecar credentials and evidence client token material.
- OpenCRVS DCI credentials and evidence client token material.
- Relay and Notary API credentials used by public demos.
- Postgres data volume.
- Redis state when required for nonce or replay continuity.
- public origins and redirect URLs.

May be regenerated intentionally:

- disposable smoke output;
- local-only `output/` artifacts;
- demo reports;
- generated static metadata when the source config changes.

The local compose ships demo defaults that must be rotated before a public
origin: Postgres `postgres/postgres`, the literal Zitadel masterkey
`MasterkeyNeedsToHave32Characters` (passed on the command line, where it is
visible in `docker inspect`; use the `ZITADEL_MASTERKEY` secret instead), and
the `generate-demo-secrets.py` tokens. Generate real values once, store them as
Coolify secrets, and keep them stable thereafter.

Hosted config should not use `.env` rewritten by `just generate` as the only
state source. Coolify should hold environment variables and secrets. Persistent
files or volumes should hold keys and seeded service data.

Enable Coolify's scheduled backups for the Postgres volume so seeded identities,
keys, and Zitadel state survive volume loss, not just redeploys.

## Image And Release Strategy

Preferred long-term deployment path:

```text
push to main
  -> product repository CI tests and publishes product-owned images
  -> Registry Lab CI validates hosted compose/config against selected image refs
  -> trigger Coolify deploy webhook
  -> Coolify pulls exact product image tags or digests
```

The hosted compose consumes image refs from environment variables:

```text
REGISTRY_RELAY_IMAGE=<product-owned-registry-relay-image>
REGISTRY_NOTARY_IMAGE=<product-owned-registry-notary-image>
REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE=<product-owned-openfn-sidecar-image>
```

Pin each product image explicitly where possible:

```text
REGISTRY_RELAY_IMAGE=<product-owned-registry-relay-image>@sha256:...
REGISTRY_NOTARY_IMAGE=<product-owned-registry-notary-image>@sha256:...
REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE=<product-owned-openfn-sidecar-image>@sha256:...
```

Pin by image digest (`@sha256:...`), not only a moving tag, for the rollback
guarantee. Zitadel is already pinned to `v2.66.4`; do the same for product
images used by the lab.

Canonical image ownership:

- `registry-relay` publishes `ghcr.io/jeremi/registry-relay`.
- `registry-notary` publishes `ghcr.io/jeremi/registry-notary`.
- `registry-notary` publishes a lab-compatible CEL-enabled tag family
  (`main-cel` and `sha-<commit>-cel`) for Registry Lab configs that use CEL
  predicates.
- `registry-notary` also publishes
  `ghcr.io/jeremi/registry-notary-openfn-sidecar`.
- `registry-lab` must not publish lab wrapper images under those canonical
  product names; it only consumes image refs through environment variables.

Acceptable first implementation:

- Coolify pulls product-owned images when available.
- If product images are not available, Coolify may build lab-local image tags
  such as `registry-relay:hosted`, `registry-notary:hosted`, and
  `registry-notary-openfn-sidecar:hosted`. That build must be explicitly tested
  on the Coolify host because the product Dockerfiles use named build contexts
  for `registry-platform`, `registry-manifest`, and `cel-mapping`.
- While using lab-local `:hosted` tags, the digest rollback guarantee is not
  satisfied. Record the exact source revisions used for the Coolify-local build
  and keep this as an interim state only. Any lab-local notary image must be
  built with `REGISTRY_NOTARY_FEATURES=registry-notary-cel`.
- GitHub App auto-deploy is disabled or treated as temporary until CI gating is
  wired.
- GitHub Actions triggers the Coolify deploy webhook only after checks pass.

## GitHub And Coolify Automation

Branch model:

```text
main      -> lab.registrystack.org
staging   -> staging.lab.registrystack.org, optional later
feature/* -> CI only
```

Recommended automation:

1. Push to `main`.
2. GitHub Actions runs hosted-lab checks.
3. Product repository CI builds and publishes canonical images, or Registry Lab
   CI selects already-published image refs.
4. GitHub Actions calls the Coolify deploy webhook.
5. Coolify pulls the referenced images and restarts the compose app.
6. GitHub Actions or a follow-up monitor runs hosted smoke checks against the
   public origins.

CI should fail before deployment when:

- hosted config renders `localhost` or `127.0.0.1` into issuer metadata;
- `compose.coolify.yaml` exposes private services;
- hosted `compose.esignet-hosted.yaml` publishes host ports or advertises
  localhost eSignet origins;
- required environment variables are missing;
- OID4VCI metadata does not advertise `dc+sd-jwt`;
- credential configuration `person_is_alive_sd_jwt` is absent;
- Notary config references a non-public eSignet URL in hosted mode;
- citizen notary `auth.oidc.issuer` does not match the hosted eSignet discovery
  document's `issuer`;
- DHIS2 or OpenCRVS hosted Notary config still advertises `demo.example.gov`
  issuer or API base URLs;
- product images fail to build in their owning repositories, or selected image
  refs cannot be pulled by Coolify.

## Phone Wallet Test Path

After deployment, the operator should verify:

```text
https://citizen-notary.lab.registrystack.org/.well-known/openid-credential-issuer
```

Then generate an offer URI:

```bash
OFFER_JSON="$(
  curl -s 'https://citizen-notary.lab.registrystack.org/oid4vci/credential-offer?credential_configuration_id=person_is_alive_sd_jwt'
)"

python3 - "$OFFER_JSON" <<'PY'
import sys
import urllib.parse

print(
    "openid-credential-offer://registry-notary/?credential_offer="
    + urllib.parse.quote(sys.argv[1], safe="")
)
PY
```

The resulting URI may be rendered as a QR code for the phone wallet.

Pass criteria:

- phone wallet parses the offer;
- phone wallet discovers issuer metadata;
- phone wallet reaches public eSignet authorization;
- eSignet authenticates seeded citizen `NID-1001`;
- wallet requests a nonce;
- wallet submits a JWT proof with `typ=openid4vci-proof+jwt`;
- Notary issues `format=dc+sd-jwt`;
- wallet stores the credential;
- Notary audit records `access_mode=self_attestation`;
- attempted other-person flow remains denied.

## Verification Ladder

Local checks before first hosted deploy:

```text
just generate
just build
just up
just smoke
just citizen-oid4vci-login
just citizen-oid4vci-code
just dhis2-openfn
just opencrvs-dci
```

Hosted config checks:

```text
render compose.coolify.yaml
render citizen-civil-notary hosted config
assert no localhost URLs in OID4VCI metadata
assert public eSignet URLs in auth config
assert public domains match *.lab.registrystack.org
assert DHIS2 and OpenCRVS hosted Notary configs use public api_base_url values
assert hosted eSignet compose uses no host ports and no localhost issuer URLs
```

Hosted smoke checks:

```text
GET https://citizen-notary.lab.registrystack.org/.well-known/openid-credential-issuer
GET https://citizen-notary.lab.registrystack.org/oid4vci/credential-offer?credential_configuration_id=person_is_alive_sd_jwt
POST https://citizen-notary.lab.registrystack.org/oid4vci/nonce
run scripted OID4VCI probe with public issuer URLs and hosted eSignet token
run phone wallet QR test
inspect Notary audit
GET https://dhis2-notary.lab.registrystack.org/.well-known/evidence-service
run hosted DHIS2 positive and negative claim smoke
GET https://opencrvs-notary.lab.registrystack.org/.well-known/evidence-service
run hosted OpenCRVS DCI evidence and credential smoke
```

## Open Questions

- Which wallet is the first target: Inji, Walt Wallet, or another wallet app?
- Should hosted Relay endpoints be publicly browsable, or should only Notary and
  metadata be public for the first wallet milestone?
- If product-owned images are not published in time, which exact Coolify-local
  build process and source revisions are acceptable as an interim deploy path?
- How should stable demo keys be provisioned: Coolify secrets, mounted files, or
  a one-time bootstrap job? (Spec now recommends Coolify secrets, rotated off the
  demo defaults; see State And Secrets.)
- Do we need `staging.lab.registrystack.org` before the first public wallet
  demo, or can `main` deploy directly to the lab environment?
- Should DHIS2 and OpenCRVS Notaries share the main hosted lab deploy cadence, or
  use separate Coolify apps so live-source outages do not block wallet demos?

## Definition Of Done

The hosted lab deployment is complete only when every criterion below is
verified and recorded with command output, HTTP status, artifact path, or
Coolify deployment evidence:

- `compose.coolify.yaml` exists, is the file selected by the Registry Lab
  Coolify app, and contains no `ports:` keys.
- The hosted eSignet Coolify app is deployed from a hosted-safe
  `compose.esignet-hosted.yaml` variant, and that compose file
  contains no `ports:` keys and no `localhost`, `127.0.0.1`, or
  `http://` issuer, authorization, JWKS, token, UserInfo, or callback URLs.
- Cloudflare has a DNS-only `*.lab` record resolving to the Coolify host for
  first deploy, no incorrect `AAAA` record, and any zone CAA policy permits
  `letsencrypt.org` certificate issuance.
- Coolify has HTTPS domains assigned for:
  `citizen-notary.lab.registrystack.org`,
  `esignet.lab.registrystack.org`, `esignet-ui.lab.registrystack.org`,
  `dhis2-notary.lab.registrystack.org`, and
  `opencrvs-notary.lab.registrystack.org`.
- `curl -fsS https://citizen-notary.lab.registrystack.org/.well-known/openid-credential-issuer`
  returns `2xx` JSON with `credential_issuer` equal to
  `https://citizen-notary.lab.registrystack.org`, `format` containing
  `dc+sd-jwt`, `credential_configurations_supported.person_is_alive_sd_jwt`,
  and no URL containing `localhost`, `127.0.0.1`, or `http://`.
- `curl -fsS https://esignet.lab.registrystack.org/v1/esignet/oidc/.well-known/openid-configuration`
  and `curl -fsS https://esignet-ui.lab.registrystack.org/.well-known/openid-configuration`
  both return `2xx` from a phone network or an external runner.
- The hosted eSignet discovery document's `issuer` value exactly equals
  `auth.oidc.issuer` in the citizen notary hosted config.
- `citizen-civil-notary` is a long-running Coolify service, not a process
  launched by `scripts/smoke-citizen-self-attestation.sh`, and Coolify reports
  it healthy after a restart using a healthcheck mechanism available in the
  deployed notary image.
- A forced redeploy with no secret changes preserves the OID4VCI issuer key id,
  the eSignet client id, and the seeded `NID-1001` identity; the before/after
  values are recorded as redacted hashes or non-secret identifiers.
- The hosted OID4VCI probe completes against public origins and writes a report
  showing metadata `2xx`, offer `2xx`, nonce `2xx`, credential `2xx`, requested
  configuration `person_is_alive_sd_jwt`, and response format `dc+sd-jwt`.
- A real phone wallet run stores a credential from
  `person_is_alive_sd_jwt`; the run note records wallet app/version, issuer URL,
  credential configuration id, result `passed`, and a redacted credential
  receipt or screenshot.
- The citizen Notary audit for the phone-wallet run contains
  `access_mode=self_attestation`, and an attempted `NID-1002` self-attestation
  request returns `403`.
- GitHub Actions blocks deploy when hosted config validation fails, and a
  passing `main` workflow triggers exactly one Coolify deploy webhook call for
  the selected image refs. If local `:hosted` image tags are still used instead
  of digest-pinned product refs, the release is explicitly marked interim and
  the exact source revisions are recorded.
- `curl -fsS https://dhis2-notary.lab.registrystack.org/.well-known/evidence-service`
  returns `2xx`, the hosted DHIS2 smoke evaluates at least one positive and one
  negative claim, and credential issuance returns
  `credential_profile=dhis2_child_program_sd_jwt`. The Coolify app has non-empty
  `DHIS2_EVIDENCE_CLIENT_TOKEN_HASH` and
  `DHIS2_EVIDENCE_CLIENT_BEARER_HASH` secrets.
- `curl -fsS https://opencrvs-notary.lab.registrystack.org/.well-known/evidence-service`
  returns `2xx`, the hosted OpenCRVS smoke evaluates a live seeded UIN, and
  credential issuance returns
  `credential_profile=opencrvs_birth_attributes_sd_jwt`.
- No raw bearer tokens, private keys, full SD-JWT VC values, OpenCRVS secrets,
  DHIS2 passwords, or eSignet private keys are printed in CI logs, Coolify logs,
  public docs, or committed files.

## Implementation Notes

Initial hosted deployment artifacts have been implemented:

- `compose.coolify.yaml` defines the Registry Lab Coolify Compose contract with
  no host ports, no host builds, env-driven image references, internal
  Postgres/Redis, hosted Zitadel settings, a long-running
  `citizen-civil-notary`, and hosted DHIS2/OpenCRVS notary surfaces.
- `config/coolify/relay/` contains hosted relay configs derived from the local
  relay configs but with public lab-domain DID and metadata URLs instead of
  `demo.example.gov`.
- `compose.esignet-hosted.yaml` derives the hosted eSignet app from the ready
  local `compose.esignet-live.yaml` source, with no host ports, public eSignet
  origins, persistent database/Redis/seed volumes, and private seed output under
  a named volume.
- `scripts/validate-hosted-deploy.py` and
  `scripts/test_validate_hosted_deploy.py` enforce the hosted deployment
  contract before deploy.
- `.github/workflows/hosted-lab.yml` runs whitespace checks, compose rendering,
  validation tests, hosted artifact validation, and a single
  `COOLIFY_DEPLOY_WEBHOOK_URL` deploy call on pushes to `main`.
- `just hosted-validate` and `just hosted-validate-test` run the focused local
  validation path.
- `just hosted-validate-strict` additionally requires every hosted secret value
  to be present in the caller's environment; use it from a deployment preflight
  shell, not from pull-request CI.

Pitfalls recorded during implementation:

- Docker Compose auto-loads a local `.env`; validation commands must render
  hosted artifacts without relying on developer-local secrets. CI and
  `just hosted-validate` use a non-secret eSignet Postgres placeholder only for
  compose rendering.
- The existing eSignet seed script writes local callback defaults. The hosted
  eSignet compose keeps that script unchanged and applies a post-seed SQL
  correction from `REGISTRY_LAB_ESIGNET_CLIENT_REDIRECT_URIS_JSON`, rejecting
  non-HTTPS or loopback redirect URIs.
- The hosted notary healthchecks use the product-owned
  `registry-notary healthcheck` subcommand. This replaced the earlier `curl`
  plan because the product image is distroless.
- DevOps review found an issuer mismatch between citizen notary auth config and
  hosted eSignet discovery overrides. The intended hosted issuer is the bare
  `https://esignet.lab.registrystack.org` value; verify the live discovery
  document before phone-wallet testing and keep the notary config aligned with
  that exact `issuer`.
- Product `registry-notary` now expands `${VAR}`, `${VAR:-default}`, and
  `${VAR:?message}` expressions in mounted config before parsing. The hosted
  OpenCRVS notary uses that product-owned expansion instead of a shell wrapper,
  so it works with the distroless runtime.
- DHIS2 hosted issuance requires non-empty
  `DHIS2_EVIDENCE_CLIENT_TOKEN_HASH` and
  `DHIS2_EVIDENCE_CLIENT_BEARER_HASH`; an empty default can let deployment
  succeed while all evidence-client authentication fails.
- The workflow requires the repository secret `COOLIFY_DEPLOY_WEBHOOK_URL` for
  `main` deploys. Coolify must still be configured with the selected image refs
  for strict rollout and rollback.
- Registry Lab CI intentionally does not publish canonical product images.
  Relay and Notary images are owned by their source repositories; Registry Lab
  only validates and consumes selected refs. Any Coolify-local `:hosted` build is
  an interim escape hatch, not the final rollback model.

DevOps review disposition:

- Accepted as deploy blockers: eSignet issuer mismatch and notary healthcheck
  runtime mismatch. The hosted citizen notary config now targets the bare
  eSignet issuer, and the live discovery document must be checked before Wave 3.
  The healthcheck fix is implemented through the product-owned
  `registry-notary healthcheck` command, not a lab-published wrapper image.
- Accepted as Wave 6 blocker: DHIS2 evidence-client hash secrets must be
  non-empty in Coolify and listed in the runbook.
- Accepted as CI gaps: hosted validation should add positive checks for
  `dc+sd-jwt`, `person_is_alive_sd_jwt`, required hosted secrets, eSignet issuer
  equality, and recursive mounted config scanning before unattended deploys are
  treated as complete.
- Adapted for Docker ownership: Registry Lab CI should not build or publish
  `ghcr.io/jeremi/registry-relay`,
  `ghcr.io/jeremi/registry-notary`, or
  `ghcr.io/jeremi/registry-notary-openfn-sidecar`. Those are product-repo
  responsibilities. Registry Lab validates and deploys selected refs; local
  `:hosted` tags remain an interim Coolify-local fallback only.
- Deferred but tracked: verify MOSIP 1.8.0 handling of bare
  `MOSIP_ESIGNET_HOST`, decide whether hosted relay configs may still advertise
  `demo.example.gov` before public read surfaces, add CI least-privilege
  `permissions`, reconcile hosted Zitadel bootstrap docs with the actual script,
  remove or justify Redis startup coupling on DHIS2/OpenCRVS notaries, and verify
  Coolify does not rerun eSignet seed in a way that changes stable client data.

## Definition Of Done And Implementation Plan

This work is done only when every item below is true and evidenced in review:

- `compose.coolify.yaml` and the hosted eSignet compose render successfully with
  `docker compose config`, without host `ports:`, local `build:` blocks, public
  `http://` origins, loopback public URLs, or `demo.example.gov` values.
- Cloudflare has `lab.registrystack.org` and `*.lab.registrystack.org` resolving
  to the Coolify host, DNS-only until certificates are issued, and no required
  hosted domain depends on a local tunnel.
- Coolify has separate Registry Lab and eSignet apps with all public domains,
  volumes, secrets, image refs, and deploy webhooks recorded in a redacted
  runbook.
- The live eSignet discovery document's `issuer` exactly matches the citizen
  notary `auth.oidc.issuer`; token issuer validation is not inferred from URL
  shape.
- The citizen wallet critical path works end to end over public HTTPS:
  eSignet discovery returns `2xx`, citizen Notary discovery returns `2xx`, the
  OID4VCI credential endpoint returns `2xx` for `NID-1001`, the issued
  credential has `format=dc+sd-jwt`, and the phone wallet stores
  `person_is_alive_sd_jwt`.
- Negative controls are verified: `NID-1002` returns `403`, hosted validation
  blocks loopback issuers, hosted validation blocks host ports, and hosted
  validation blocks stale `demo.example.gov` URLs.
- DHIS2 and OpenCRVS notary surfaces are either verified or explicitly marked
  blocked by an external dependency: verified means public evidence discovery
  returns `2xx`, DHIS2 evidence-client hashes are non-empty Coolify secrets,
  DHIS2 proves one positive claim, one negative claim, and
  `dhis2_child_program_sd_jwt` issuance, and OpenCRVS proves seeded-UIN
  evaluation plus `opencrvs_birth_attributes_sd_jwt` issuance.
- A forced redeploy preserves persistent identities: the citizen issuer key id,
  eSignet client id, seeded identities, and service database state remain stable
  after redeploy.
- CI runs hosted validation before the Coolify deploy webhook; a failing
  validation case blocks deployment and a passing `main` run triggers exactly
  one deploy of the selected image refs.
- Canonical images are built by `registry-relay` and `registry-notary`, not by
  `registry-lab`; any Coolify-local `:hosted` image tags are recorded as
  interim and do not satisfy digest-pinned rollback.

Use parallel workers only for independent surfaces. Each worker reports scope,
files inspected or changed, commands run, results, blockers, and residual risks.
The parent coordinates integration, resolves conflicts, runs final verification,
and enforces the review checkpoints.

### Wave 1: Hosted Compose Contract

- [ ] Worker A finalizes `compose.coolify.yaml`: no host ports, no local builds,
  selected image refs, persistent volumes, public domains, and long-running
  citizen, DHIS2, and OpenCRVS notary services.
- [ ] Worker B finalizes hosted eSignet compose from the colleague-owned live
  compose source, with public origins, persistent Postgres, stable seed data,
  and no public `output/` secrets.
- [ ] Worker C finalizes hosted validation for compose and mounted configs.
- [ ] Done when both compose config commands pass, hosted validation passes, and
  injected failures for loopback issuer, host ports, `latest` image tags, and
  `demo.example.gov` are rejected by tests.
- [ ] Review checkpoint: review compose diffs, validator tests, and rendered
  config output before any Coolify deployment starts.

### Wave 2: Product Image Ownership

- [ ] Worker A updates `registry-relay` to build the canonical relay image with
  configurable lab feature flags.
- [ ] Worker B updates `registry-notary` to build the canonical notary image and
  the OpenFn sidecar image, with configurable lab feature flags.
- [ ] Worker C resolves hosted healthchecks for distroless notary runtime
  without relying on a tool that is absent from the image.
- [ ] Done when both product repositories build images locally, CI publishes or
  makes available `ghcr.io/jeremi/registry-relay`,
  `ghcr.io/jeremi/registry-notary`, and
  `ghcr.io/jeremi/registry-notary-openfn-sidecar`, and the lab compose consumes
  those refs only through env vars. If Coolify-local `:hosted` tags are used
  before publication exists, the wave remains interim and the exact source
  revisions are recorded.
- [ ] Review checkpoint: review product Dockerfile diffs, image tags or digests,
  and local container health evidence before wiring Coolify to them.

### Wave 3: Coolify And Cloudflare Deploy

- [ ] Worker A configures Cloudflare and the Registry Lab Coolify app domains,
  secrets, volumes, deploy webhook, and image refs.
- [ ] Worker B configures the separate hosted eSignet Coolify app and seeds
  `NID-1001` plus the negative-control identity.
- [ ] Worker C runs external HTTPS checks and the hosted OID4VCI scripted probe.
- [ ] Done when all required public discovery endpoints return `2xx`, issuer
  metadata contains only public HTTPS URLs, eSignet discovery `issuer` equals
  the citizen notary configured issuer, the OID4VCI probe returns credential
  `2xx` with `format=dc+sd-jwt`, and redeploy persistence is demonstrated.
- [ ] Review checkpoint: review redacted Coolify inventory, Cloudflare records,
  OID4VCI probe output, and redeploy evidence before phone-wallet testing.

### Wave 4: Phone Wallet Interop

- [ ] Worker A prepares the hosted credential offer QR or deep-link flow.
- [ ] Worker B tests the real phone wallet and records wallet app, version,
  issuer URL, credential configuration id, and result.
- [ ] Worker C verifies audit evidence and negative controls.
- [ ] Done when the phone wallet stores `person_is_alive_sd_jwt`, the run note
  records result `passed`, notary audit contains
  `access_mode=self_attestation`, and `NID-1002` returns `403`.
- [ ] Review checkpoint: review wallet evidence, redactions, audit excerpt, and
  denial control before marking wallet interop complete.

### Wave 5: Public Read Surfaces And Zitadel

- [ ] Worker A exposes the civil, social, health, and metadata public origins.
- [ ] Worker B configures Zitadel with hosted-domain settings and records
  whether it is IdP-behind-eSignet or out-of-scope for wallet interop.
- [ ] Worker C runs external HTTPS checks for each origin and Zitadel discovery.
- [ ] Done when each origin returns `2xx` over HTTPS, Zitadel discovery contains
  only `https://zitadel.lab.registrystack.org` URLs, and no public response
  advertises loopback or tunnel URLs.
- [ ] Review checkpoint: review public-origin inventory and Zitadel discovery
  before treating these surfaces as supported.

### Wave 6: DHIS2 And OpenCRVS Notaries

- [ ] Worker A deploys `dhis2-health-notary` and private
  `openfn-dhis2-sidecar` with hosted secrets and public `api_base_url`.
- [ ] Worker B deploys `opencrvs-dci-notary` with hosted secrets and public
  `api_base_url`.
- [ ] Worker C runs hosted DHIS2 and OpenCRVS smoke checks, separating external
  service blockers from deployment failures.
- [ ] Done when DHIS2 and OpenCRVS evidence discovery endpoints return `2xx`,
  DHIS2 evidence-client hashes are non-empty Coolify secrets, DHIS2 proves
  positive, negative, and issuance paths, and OpenCRVS proves seeded-UIN
  evaluation plus issuance.
- [ ] Review checkpoint: review smoke artifacts, credential summaries, secret
  redaction, and any external-service blockers before exposing these Notaries as
  supported hosted demo surfaces.

### Wave 7: CI-Gated Auto-Deploy

- [ ] Worker A verifies GitHub Actions runs hosted validation on pull requests
  and before `main` deploys.
- [ ] Worker B wires the Coolify deploy webhook so it runs only after validation
  passes.
- [ ] Worker C verifies negative CI cases and post-deploy hosted smoke checks.
- [ ] Done when failing validation blocks deploy, passing `main` triggers one
  Coolify deploy using the selected image refs, and post-deploy smoke checks
  pass.
- [ ] Review checkpoint: review CI logs, webhook audit, image refs, and hosted
  smoke output before enabling unattended deploys.
