# Registry WG demo

This local demo combines live, read-only DHIS2 Consultation requests with
Create and conditional Update against a disposable local BReg registry. It is
for an authorized Registry WG demonstration, not a production deployment or a
general GovStack conformance claim; the GovStack basis is an unratified draft.

## Requirements

- Docker through OrbStack or another compatible Docker service
- Node.js
- the Rust toolchain and Cargo
- OpenSSL
- npm and internet access for the pinned Bruno CLI bootstrap
- yq version 4
- ports `18109` through `18115` and `19443` free on loopback

From the repository root, start the demo with:

```sh
CARGO_TARGET_DIR=/path/to/cargo-target \
  ./products/adapter/examples/govstack-wg-demo/run.sh start
```

The launcher builds the four required Rust binaries into the existing Cargo
target directory named by `CARGO_TARGET_DIR`, which must be set, then starts
the local services. It explicitly enables the Adapter `postgres-test` feature
for its loopback-only plaintext test database; the public DHIS2 connection
still validates HTTPS certificates normally. Runtime state is retained outside
the repository, by default in
`${XDG_STATE_HOME:-$HOME/.local/state}/registry-adapter/govstack-wg-demo`; set
`WG_DEMO_STATE` to use another state directory.

A restart against retained state needs only the command above. On the first
start of a new state directory, supply one of these inputs:

- `WG_DHIS2_SOURCE_CONFIG`, pointing to an owner-only JSON file with `origin`,
  `program`, `tieBreakerAttribute`, `username`, and `password`; or
- `DHIS2_USERNAME` and `DHIS2_PASSWORD`, using the current credentials from the
  [official DHIS2 demo page](https://dhis2.org/demo/). The controller uses the
  fixed HTTPS demo origin and its known program and tie-breaker identifiers.

The launcher stores the source configuration in the owner-only state directory,
so later starts do not need those bootstrap inputs.

Use the same launcher for the remaining operations:

```sh
./products/adapter/examples/govstack-wg-demo/run.sh status
./products/adapter/examples/govstack-wg-demo/run.sh test
./products/adapter/examples/govstack-wg-demo/run.sh stop
```

Only `start` invokes Cargo. The other commands use the binaries and runtime
library path recorded in the state directory. The commands do not print bearer
tokens or service logs.

When ready, the caller-facing services are:

- synthetic issuer: `http://127.0.0.1:18109`;
- live DHIS2 read facade: `http://127.0.0.1:18110/govstack/registries`;
- local BReg read and write facade: `http://127.0.0.1:18111/govstack/registries`;
- DHIS2 contract: `https://127.0.0.1:19443/contracts/dhis2/1.0.0/openapi.json`;
- BReg contract: `https://127.0.0.1:19443/contracts/breg/1.0.0/openapi.json`.

The two contract URLs use the demo's self-signed certificate.

## Bruno journey

Open or import the [`bruno`](bruno/) folder as a Bruno collection, select the
`LocalExample` environment, and run all 13 requests in their saved order:

1. obtain the synthetic demo token;
2. run live DHIS2 List, Retrieve, Lookup, and Search reads;
3. run local BReg Create, exact replay, companion read, conditional merge
   patch, stale-condition refusal, and final state verification.

The DHIS2 source is read-only. Write requests go only to the local BReg-backed
Adapter. The committed Bruno environment contains loopback origins and
synthetic selectors, never credentials or bearer tokens.

The maintained DHIS2 example uses program `qyVpUaAYv2A`, which returns 404 on
the current 2.43.2.1 public demo. During retained-state bootstrap, the
controller copies the authored project, selects live program `WSGAb5XwJ3Y`, and
sets the project's `tie_breaker_attribute` parameter to `lZGmxYbs97q`, a
required unique program attribute on that deployment (DHIS2 2.43 refuses
`trackedEntity` as a sort key). The shipped pack is used unchanged; the paging
order is `createdAt:desc,<attribute>:asc`. This enables no DHIS2 write
capability.

`stop` preserves state and local BReg data. A fresh state directory is not
required between public rehearsals: every Bruno run creates a unique run ID
and unique quoted idempotency keys, so the 13-request journey can be repeated
against retained state. The issuer is synthetic, and its self-signed TLS trust
is scoped to this demo. Nothing installs a certificate into the operating
system's global trust store. These shortcuts and the local service layout are
not suitable for production.

## Inspect the implementer configuration

The retained state has `projects/dhis2/project.yaml` and
`projects/breg/project.yaml`, with their `scripts/`, `schemas/`, and pinned
`source-pack/` directories. These are the actual authored projects used by the
running services. `contracts/dhis2.json` and `contracts/breg.json` are generated
from them. Credentials stay in the separate private `secrets/` directory.

For a quick contract preview without configuring local TLS trust, open
`http://127.0.0.1:18109/contracts/dhis2/1.0.0/openapi.json` or
`http://127.0.0.1:18109/contracts/breg/1.0.0/openapi.json`. The HTTPS URLs in
response metadata serve the same generated bytes. Use the Bruno environment's
API origins for requests; the generated contract's server path is relative.

Focused launcher and issuer checks, without Docker or the public demo:

```sh
node --test products/adapter/examples/govstack-wg-demo/test_*.mjs
shellcheck products/adapter/examples/govstack-wg-demo/run.sh
shfmt -d products/adapter/examples/govstack-wg-demo/run.sh
```
