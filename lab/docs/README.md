# Registry Lab documentation

Use the root [README](../README.md) for setup, topology, and verification.

## Maintained guides

- [Operations posture lab contract](ops-posture-lab-contract.md)
- [Public API workspace specification](public-api-workspace.md)
- [Bruno public API collection](../requests/registry-lab/README.md)

## Executable authoring examples

The supported project topology and integration examples live under
[`projects/`](../projects/). Run `just project-topologies` to prove combined
Relay plus Notary, Relay-only, Notary-only, and offline OpenSPP workspaces.

Product-specific source adaptation examples belong to Registry Stack project
starters and golden workspaces. The lab does not maintain a second adaptation
contract for Notary.
