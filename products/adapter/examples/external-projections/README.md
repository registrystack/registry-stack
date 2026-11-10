# Synthetic licensing projections

This pack supplies a licensing registry with Person names and a business's
shareholding rows. Person names are owned by the synthetic Population
Registry. Holdings are owned by the synthetic Business Registry.

| Operation | Input | Source approval |
|---|---|---|
| `person-exact` | One Person key | Live only |
| `person-batch` | Unique Person keys | Indexed acquisition may retain approved fields |
| `holdings-by-business` | One Business key | Live or indexed; retained membership requires one complete snapshot |

The fixture posts the closed operation input to a synthetic service,
including the approved requested fields. The Rhai mapping preserves the
identifiers and the completeness reported by that service. The pack pins
two JSON Schemas for the returned field objects. The source grant scope and
identifier schemes are fixture URNs or named synthetic scopes. No endpoint
or service credential is supplied by the pack. The embedding host uses an
operator-provided Adapter endpoint binding and keeps credentials in its
configured secret provider.

The engine proof checks the requested inputs against the pack routes.
The sealed transcript exercises normalized outcomes; a loopback source
checks that the configured credential and approved fields arrive at the
source and that repeated raw cache directives are honored. Run from the
Registry Stack worktree with its own external Cargo target directory:

```sh
cargo test --locked -p registry-adapter-engine --test projection_acquisition
```

The replay covers exact and batch identity, authoritative absence,
duplicate/missing batch keys, a company shareholder, complete/empty
collections, interruption, invalid collection membership and response
`no-store`. The host still needs an independently governed local grant,
audit and an authorized publication path before it can retain any result.
