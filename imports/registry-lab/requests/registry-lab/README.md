# Registry Lab API Workspace

This Bruno collection exercises the public Registry Lab demo APIs. The committed
`Hosted Lab` environment includes only public demo caller credentials from
`config/lab-homepage/public-demo-credentials.env`, which are also published at
`lab.registrystack.org`.

Do not add infrastructure secrets, source connector tokens, signing keys,
database credentials, upstream DHIS2/OpenCRVS credentials, eSignet private keys,
or Coolify credentials to this workspace.

## Hosted Lab

Open this folder in Bruno, select the `Hosted Lab` environment, then run folders
in order:

1. `00 - Start Here`
2. `10 - Relay Metadata`
3. `20 - Relay Access Boundaries`
4. `30 - Notary Evaluation`
5. `31 - DHIS2 Programme VC`

The requests are independent unless a request description says otherwise. The
denial probes are expected to return `403` and prove that public tokens cannot
use surfaces outside their intended scope.

The `31 - DHIS2 Programme VC` folder is ordered and stateful. Run request 01
first so its Bruno script can evaluate the six DHIS2 programme claims, generate
a short-lived `did:jwk` holder proof, and store the reconciliation reference for
requests 02 and 03. The holder proof script uses Node `crypto`; if your Bruno
sandbox blocks that module, run the collection in Developer Mode.

## Local Compose

Select the `Local Compose` environment after running the local services. The
core Relay and static metadata requests expect:

```bash
just generate
just build
just up
```

The DHIS2 Notary requests in `30 - Notary Evaluation` additionally require the
DHIS2 profile used by `just dhis2-openfn`. The local homepage request expects
`just lab-homepage` if you want to exercise the homepage service locally.

For the local `31 - DHIS2 Programme VC` walkthrough, start the DHIS2 services
before opening Bruno:

```bash
docker compose -f compose.yaml --profile dhis2 up -d openfn-dhis2-sidecar dhis2-health-notary
```

Token variables intentionally use the same names as the generated `.env` file so
you can paste values directly from local generated credentials when needed.

## Local Lab 2 governed config

The `40 - Lab 2 Governed Config` folder is a step-by-step API walkthrough for
the opt-in governed configuration overlay. It is intentionally local-only
because it exercises admin apply endpoints and generated demo TUF artifacts.

Prepare a clean Lab 2 run first:

```bash
just generate
just lab2-demo-reset
just lab2-generate
just lab2-up
```

Open this folder in Bruno, select the `Local Lab 2` environment, then paste
these values from `.env` into the environment variables:

- `CIVIL_METADATA_CLIENT_RAW`
- `CIVIL_RELAY_OPS_RAW`
- `CIVIL_NOTARY_OPS_BEARER`

Run `40 - Lab 2 Governed Config` in order from request 01 through request 12.
The sequence proves:

- the Lab 2 Relay is serving from generated governed config;
- a signed Relay `public_metadata` bundle applies live;
- unsigned inline apply is rejected;
- an under-quorum signed target is rejected;
- a signed Notary key rotation applies;
- a signed Relay break-glass change is accepted once and then rate-limited.

The sequence mutates Lab 2 runtime state. To run it again from the beginning,
reset only Lab 2 and regenerate/start it:

```bash
just lab2-demo-reset
just lab2-generate
just lab2-up
```
