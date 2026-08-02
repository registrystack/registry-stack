# Compose deployment

A static reference deployment for the images `docker/README.md` builds:
the `evidence` service, and optionally `mint` beside it. Copy this
directory into your operations tree and edit it there, or run it in place;
either way the files are yours after that, there is no regeneration
contract.

## Layout

- `docker-compose.yaml` wires one user-defined network with a static
  private address for each service, mounts your deployment project
  read-only, and keeps the audit chain in a named volume.
- `runtime.docker.yaml` is the container-shaped runtime file. Compose
  mounts it over your project's host-shaped `runtime.yaml`, so the same
  project directory serves local runs and container runs without edits.
  Both files bind the same bundle bytes; only the environment differs.

## Run

Build the images from the repository root (see `docker/README.md`), then
point the compose file at a provisioned evidencectl project:

```sh
EVIDENCE_PROJECT_DIR=/path/to/project docker compose -f docker-compose.yaml up
```

The project must already hold its bundle and key material
(`evidencectl new`, `evidencectl keygen ...`). The read-only project mount
satisfies the runtime's refusal of writable deployment inputs, so the
container path needs no host-side freeze; freezing the project on disk
remains good practice for the host path.

Neither image declares a Docker `HEALTHCHECK` (distroless, no shell).
Probe over HTTP from your orchestrator: `GET /health` is liveness only,
and `GET /ready` is the gate that fails closed while any required
secret or source credential is absent, so route traffic on `/ready`.
Uncomment the `ports:` lines to reach the listeners from the host.

## Mint

For a project scaffolded with `--with-mint`, start both services:

```sh
EVIDENCE_PROJECT_DIR=/path/to/project docker compose -f docker-compose.yaml --profile mint up
```

Set `listener.address` in the project's `mint/mint.yaml` to `0.0.0.0` (or
the static `172.28.0.11`) first; the scaffolded default of `127.0.0.1` is
unreachable from outside the container. Mint's other values (issuer,
audiences, claim names) already pair with the bundle and need no change.

## What this is not

TLS termination and public exposure stay upstream, behind your operator
network's proxy, which is why nothing here publishes a port by default.
These images and this file are not release artifacts; released images
follow the `release/docker/` reproducible-build path.
