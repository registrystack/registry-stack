# Changelog

## Unreleased

## registry-stack-beta-3-2026-06-21

- Added first-release readiness guidance for treating Registry Lab as the
  proof harness for RegistryStack components.
- Kept Registry Atlas outside the default first-release proof path unless it is
  explicitly opted in.
- Added the beta-3 CRVS Evidence Gateway pack baseline:
  `birth-registration-evidence/v1`, `birth-certificate-evidence/v1`,
  `marriage-certificate-evidence/v1`, and
  `combined-support-eligibility/v1`.
- Migrated DHIS2 and civil source-adapter demos to the built-in `http_json`
  sidecar engine, including OpenCRVS/civil fixture updates and smoke coverage.
- Advanced vendor pins for Platform, Manifest, Notary, Relay, and Crosswalk to
  the beta-3 candidate refs.
- Aligned static metadata Manifest and Relay refs with the beta-3 release
  manifest.
- Hosted/demo compose files still require live digest proof before public
  hosted go/no-go; the source release train does not treat those mutable runtime
  image tags as hosted proof.

## 0.1.0

- Initial public demo topology for Registry Relay, Registry Notary, Registry
  Manifest, Registry Platform, OpenFn sidecar scenarios, static metadata, and
  narrated client flows.
