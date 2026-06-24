# External Inputs

RegistryStack-owned product code lives in this monorepo. The normal external
source input is Crosswalk:

```yaml
crosswalk:
  repo: PublicSchema/crosswalk
  ref: 1d44ec735fdc8a7c719264b339574371e8330337
  status: tested external input
```

Do not import Crosswalk under `crates/` or `external/`. Use the pinned workspace
Git dependency for release builds, and use local uncommitted Cargo patch
overrides only for development.
