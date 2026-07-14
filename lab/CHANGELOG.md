# Changelog

## Unreleased

- Aligned the public homepage, Claims Explorer, static metadata, performance
  harness, and hosted smoke with the active self-attested Notary-only topology.
  Registry-backed Notary examples now require a generated combined project and
  are no longer advertised as standalone lab services.

## registry-stack-beta-11-2026-07-10

- Added a pinned OpenID Foundation conformance-suite wrapper, OID4VCI issuer
  plan mapping, and an initial #205 Registry Notary metadata conformance run
  report.

## registry-stack-beta-10-2026-07-04

- Removed `fingerprint.commitment` from Lab Relay and Notary demo configs in
  favor of fingerprint references.
- Aligned Lab source-adapter, hosted validation, and demo secret-generation
  paths with the v0.8.4 Relay and Notary configuration model.
- Kept Registry Atlas and the eSignet Relay authenticator held as lab-only
  external inputs for the source release.

## registry-stack-beta-4-2026-06-22

- Advanced vendor pins for Platform, Manifest, Notary, and Relay to the beta-4
  release refs.
- Updated hosted/demo image fallbacks to the beta-4 Registry Relay, Registry
  Notary, and Notary source-adapter sidecar release digests.
- Refreshed the Lab governed-config helper to consume Registry Platform
  `v0.3.2`.

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
