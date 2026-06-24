# RegistryStack

This repository is the monorepo source of truth for RegistryStack product code.

## Layout

- `crates/`: Rust crates and runnable binaries for Platform, Manifest, Notary,
  Relay, Registryctl, and shared release tooling.
- `products/`: product-owned docs, examples, Docker inputs, specs, security
  material, scripts, performance harnesses, and fixtures that are not normal
  workspace crates.
- `docs/site/`: the public RegistryStack docs site.
- `lab/`: Registry Lab compose files, fixtures, demos, and source proof scripts.
- `release/`: stack release manifests, schemas, import audit records, and public
  release tooling.
- `external/`: notes for external inputs that intentionally stay outside this
  source tree.

## External Boundary

Crosswalk remains an external pinned input and is not imported into this
repository. Release builds use the pinned Git dependency declared in the root
workspace manifest and record the exact ref in `release/manifests/*.yaml`.

Registry Atlas and the eSignet relay authenticator remain Lab-only external
inputs unless a later product decision promotes them into RegistryStack.

## Verification

Useful first checks:

```bash
cargo metadata --locked --format-version 1
release/scripts/registry-release validate release/manifests/registry-stack-beta-6.yaml
release/scripts/registry-release audit release/manifests/import-map-2026-06-24.yaml
REGISTRY_LAB_RELEASE_SOURCE_MODE=monorepo lab/scripts/check-release-source-model.sh
```
