# Registry Lab API Workspace

This Bruno collection exercises the public Registry Lab demo APIs. The committed
`Hosted Lab` environment includes only public demo caller credentials from
`config/lab-homepage/public-demo-credentials.env`, which are also published at
`lab.registrystack.org`.

Do not add infrastructure secrets, Relay consultation tokens, signing keys,
database credentials, upstream system credentials, eSignet private keys, or
Coolify credentials to this workspace.

## Hosted Lab

Open this folder in Bruno, select the `Hosted Lab` environment, then run folders
in order:

1. `00 - Start Here`
2. `10 - Relay Metadata`
3. `20 - Relay Access Boundaries`
4. `30 - Notary Evaluation`

The requests are independent unless a request description says otherwise. The
denial probes are expected to return `403` and prove that public tokens cannot
use surfaces outside their intended scope.

## Local Compose

Select the `Local Compose` environment after running the local services. The
core Relay and static metadata requests expect:

```bash
just generate
just build
just up
```

The local homepage request expects `just lab-homepage` if you want to exercise
the homepage service locally. Notary evaluation requests use the source-free
self-attested Notary in the default topology.

Token variables intentionally use the same names as the generated `.env` file so
you can paste values directly from local generated credentials when needed.

The committed project workspaces under `lab/projects/` prove Relay-only,
Notary-only, and combined generated deployment shapes. Use
`just project-topologies` to execute those authoring journeys; this Bruno
collection does not assume that generated services are running on fixed ports.

Run request 02 before request 03 because the render request uses the stored
evaluation id from request 02.
