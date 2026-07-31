# Adopter runtime Compose conformance probe

These inert fixtures exercise the current generated-package Compose contract.
They are not a shipped deployment package and contain no credentials.

The checker proves:

- the ordinary package has four workloads plus three least-authority,
  networkless secret stagers;
- all workloads use one ordinary, non-internal Compose runtime network, with
  no namespace-holder service or shared `network_mode`;
- only Relay public and Notary publish host ports, and both bind IPv4 loopback;
- product application traffic is plain HTTP within that Compose network, and
  the operator or platform terminates ingress TLS before the loopback boundary;
- Relay public needs no staged listener TLS material, while each remaining
  stager has only its source secrets and action-specific output volumes and
  every consumer receives only its own read-only staged volume;
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

The single first-country release rehearsal supplies the functional proof that
these inert fixtures cannot. It retains the already tested public HTTP demo,
builds and signs its `public-demo` environment, starts the generated governed
package, and sends one authenticated Notary evaluation through the private
consultation Relay to the bounded source. The retained evidence contains only
the HTTP status and minimized claim summary, not the caller token or source
response.

Run the current and minimum supported Compose implementations:

```sh
bash release/scripts/check_adopter_compose_contract.sh
```
