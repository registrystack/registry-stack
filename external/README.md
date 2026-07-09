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

## Crosswalk Pin Rationale

Crosswalk provides CEL helpers, function modules, and PublicSchema mapping used
by the Notary source-adapter stack and by optional Relay and Notary CEL-backed
policy and mapping paths. It is kept as an external Git dependency because
Crosswalk is independently maintained upstream, while Registry Stack releases
need a repeatable, reviewed source input.

The pin is recorded in:

- the root `Cargo.toml` workspace dependency declarations;
- `Cargo.lock`;
- `release/manifests/registry-stack-*.yaml`.

The pin prevents unreviewed drift in PublicSchema mapping behavior, CEL helper
semantics, and Crosswalk's transitive dependency graph.

## Crosswalk Review Triggers

Review the Crosswalk pin before changing it, and at minimum when one of these
events occurs:

- Crosswalk publishes a release or tag that can replace the commit pin;
- Registry Stack enables, changes, or expands Crosswalk-backed runtime surfaces;
- Dependabot, `cargo deny`, CodeQL, OpenSSF Scorecard, or a maintainer review
  identifies a Crosswalk or Crosswalk-transitive supply-chain concern;
- upstream Crosswalk changes license, ownership, repository location, or release
  process;
- a stable Registry Stack release review refreshes external inputs.

Pin changes must be made through a coordinated pull request that updates the
workspace dependency declarations, `Cargo.lock`, release manifests, release
notes when applicable, and dependency vetting evidence.
