# Decentralized Evidence Demo

This demo runs three independent Registry Relay authorities, three independent
Registry Notary verifiers, a static metadata publisher, and a narrated client.
It uses functional domains only. The services simulate civil, social protection,
and health registry patterns, but they are not real OpenCRVS, OpenSPP, DHIS2,
OpenIMIS, MOSIP, or other product integrations.

## Topology

- `civil-registry-relay`: CSV-backed civil registry authority on host port `4311`.
- `social-protection-registry-relay`: XLSX-backed social protection authority on host port `4312`.
- `health-registry-relay`: Parquet-backed health authority on host port `4313`.
- `civil-registry-notary`: civil Registry Notary verifier on host port `4321`.
- `social-protection-registry-notary`: social protection Registry Notary verifier on host port `4322`.
- `shared-eligibility-registry-notary`: cross-authority civil, social, and health Registry Notary verifier on host port `4323`.
- `static-metadata-publisher`: generated static metadata on host port `4331`.

Inside Compose, services use DNS names like
`http://civil-registry-relay:8080` and
`http://shared-eligibility-registry-notary:8080`. Registry Notary containers do
not mount source data. They read registry facts over HTTP from Relay. The demo
client also has no `data/` mount.

## First Run

From `registry-relay`:

```bash
uv run demo/decentralized/scripts/generate-fixtures.py
demo/decentralized/scripts/generate-demo-secrets.py
demo/decentralized/scripts/publish-static-metadata.sh
docker compose -f demo/decentralized/compose.yaml build
docker compose -f demo/decentralized/compose.yaml up -d
demo/decentralized/scripts/smoke.sh
docker compose -f demo/decentralized/compose.yaml --profile client run --rm demo-client
docker compose -f demo/decentralized/compose.yaml down -v
```

Generated credentials are written under `demo/decentralized/env/`. Generated
artifacts are written to `demo/decentralized/output/`. Generated static
publication files are written under `demo/decentralized/static-metadata/`.
Those directories keep only their `.gitignore` files in git.

## Fixture Data

`scripts/generate-fixtures.py` is the source of truth for the synthetic CSV,
XLSX, and Parquet extracts. It writes a small but non-trivial fixture set:

- civil registry CSV: children, caregivers, living adults, and deceased adults
  across five districts;
- social protection XLSX: households, household members, and enrollments with
  active, inactive, suspended, and review-required cases;
- health registry Parquet: active, suspended, pending-renewal, and
  partially-serviceable facilities.

The generator validates key coverage before writing files so the demo keeps a
successful subject, failed predicates, deceased-member cases, cross-source
subjects, and health-linked support cases.

## Credentials

`scripts/generate-demo-secrets.py` writes scoped local credential files under
`demo/decentralized/env/`. Regenerate them whenever Compose reports a missing
env file.

Generated files:

- `env/civil-registry-relay.env`
- `env/social-protection-registry-relay.env`
- `env/health-registry-relay.env`
- `env/civil-registry-notary.env`
- `env/social-protection-registry-notary.env`
- `env/shared-eligibility-registry-notary.env`
- `env/demo-client.env`

Credential classes:

- metadata client tokens for each Relay;
- evidence source tokens used by Registry Notary when calling Relay;
- evidence-only Relay tokens used to prove verification scope does not imply
  row or aggregate access;
- row-reader tokens for the explicit positive row-read check;
- aggregate-reader tokens for the aggregate consultation;
- separate Registry Notary client API keys and bearer tokens;
- distinct shared Registry Notary source tokens for civil, social, and health.

Relay env files contain only `*_HASH` values plus
`REGISTRY_RELAY_AUDIT_HASH_SECRET`. Registry Notary env files contain only that
service's client credential hashes, source tokens, and issuer key. The demo
client env file contains only walkthrough tokens and no hashes or issuer keys.

The social protection Relay config keeps row and aggregate scopes on separate
credentials so the smoke flow can prove row-reader credentials cannot run the
aggregate endpoint.

Relay configs should reference only `*_HASH` env vars. Registry Notary auth
configs should reference fingerprint hashes; Registry Notary source connections
still use `token_env` names for upstream Relay credentials. No raw token should
be committed.

## Static Metadata

`scripts/publish-static-metadata.sh` wraps
`scripts/run_registry_manifest_cli.sh publish` and publishes the portable
manifest at `config/static-metadata/metadata.yaml` into
`static-metadata/metadata/`. The publisher serves it at paths such as:

- `http://127.0.0.1:4331/metadata/index.json`
- `http://127.0.0.1:4331/metadata/catalog.json`
- `http://127.0.0.1:4331/metadata/evidence-offerings.json`
- `http://127.0.0.1:4331/metadata/policies.jsonld`

The static bundle is generated from portable metadata, not scraped from a
running Relay. It must not include source paths, table ids, scopes, cache paths,
or backend runtime details.

## Demo Flow

`scripts/demo-flow.py` narrates three scenarios:

1. Birth Registration To Child Support: Registry Notary verifies civil facts and
   issues a demo-grade credential without exposing raw civil rows.
2. Household Benefit Review From Registry Data: the client performs a protected
   Relay row read and aggregate consultation with `Data-Purpose`, then writes a
   demo household-benefit decision artifact without writing back to Relay.
3. Cross-Authority Conditional Support: static metadata leads the client to a
   shared Registry Notary claim that depends on civil, social protection, and
   health authorities.

Every client request sends `x-request-id` using
`decentralized-demo-correlation-001` by default and saves JSON artifacts.

## Notes

The Relay demo image is built by `Dockerfile.demo` with
`spdci-api-standards,standards-cel-mapping` so DCI source routes are available.
That image is debug/demo-only and intentionally separate from the production
distroless runtime policy documented in the root README.

The demo configures Relay and Registry Notary to expose API docs at `/docs` and
OpenAPI at `/openapi.json` without credentials. Data, metadata, claim, and
evidence routes still use the configured demo credentials.
