# Historical External Inputs

RegistryStack-owned product code lives in this monorepo. Crosswalk was a pinned
external source input for retired Relay V1 and Notary release shapes:

```yaml
crosswalk:
  repo: PublicSchema/crosswalk
  ref: 1d44ec735fdc8a7c719264b339574371e8330337
  status: retired historical input
```

Current `main` has no Crosswalk Cargo dependency or executable release check.
Historical release manifests retain the reviewed pin without modification.
Verify a pre-v0.19 release from its exact source tag and archived assets.

## Crosswalk Pin Rationale

Crosswalk provided CEL helpers, function modules, and PublicSchema mapping used
by the retired Notary source-adapter stack and Relay V1 policy and mapping
paths. It remained external because it was independently maintained upstream,
while those Registry Stack releases needed a repeatable, reviewed source input.

The pin remains recorded in historical `release/manifests/registry-stack-*.yaml`
files. It is absent from the current workspace manifest and lockfile.

The pin prevents unreviewed drift in PublicSchema mapping behavior, CEL helper
semantics, and Crosswalk's transitive dependency graph.

Crosswalk can return only through an explicit product and dependency review.
Such a change would add a new current dependency; it must not rewrite the
historical manifests that record earlier release inputs.
