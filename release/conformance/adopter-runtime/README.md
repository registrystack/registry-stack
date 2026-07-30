# Adopter runtime Compose conformance probe

These inert fixtures exercise the current generated-package Compose contract.
They are not a shipped deployment package and contain no credentials.

The checker proves:

- the ordinary package has four workloads plus four lane-owned, networkless
  secret stagers;
- all workloads use one ordinary, non-internal Compose runtime network, with
  no namespace-holder service or shared `network_mode`;
- only Relay public and Notary publish host ports, and both bind IPv4 loopback;
- each stager has only its lane's source secrets and action-specific output
  volumes, while every consumer receives only its own read-only staged volume;
- each product lane reuses one operator-owned environment file for serve,
  preparation, and initialization;
- selecting `compose.initialize.yaml` is required to initialize PostgreSQL and
  exposes the seven initialization services only in that explicit model;
- `docker compose config --no-env-resolution` retains environment-file paths
  without resolving sentinel operator values; and
- one operator-owned parent file can include the generated package using
  ordinary Compose short include syntax.

The former parent-override certification and negative ownership fixtures were
removed with the renderer-owned parent-boundary policy they tested. Registryctl
now verifies the package itself. The parent include fixture only proves Docker
Compose normalization.

Run the current and minimum supported Compose implementations:

```sh
bash release/scripts/check_adopter_compose_contract.sh
```
