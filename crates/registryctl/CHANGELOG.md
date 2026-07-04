# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.8.4] - 2026-07-04

### Added

- `registryctl init notary <dir> --source-kind fhir-sidecar` - scaffold a standalone Notary
  project pointing at an existing FHIR source-adapter sidecar, with a starter
  `patient-record-exists` claim and generated smoke request target.

### Changed

- Install script (`install.sh`) downloads the raw per-platform `registryctl` binary from
  the stack release, verifies it against the release `SHA256SUMS`, and falls back to a
  source-install hint on platforms without a published binary. The stack release publishes
  binaries for Linux x86_64, Linux arm64, and macOS arm64.
- BREAKING: Generated Relay and Notary projects no longer write
  `fingerprint.commitment` in YAML.
  Generated configs reference fingerprint env vars only; local raw keys and matching
  fingerprint values remain in `secrets/local.env`.
- The generated benefits sample now uses a richer three-sheet workbook
  (`Households`, `Persons`, `Applications`) and a broader Bruno collection covering
  discovery, row reads, relationship expansion, purpose-header failures, and aggregates.
- The generated Relay sample config now includes focused YAML comments that explain auth
  fingerprints, source tables, public entities, relationships, filters, and aggregates.
- `registryctl init relay <dir>` no longer generates a duplicate split `relay/metadata.yaml`
  manifest for the local sample; Relay derives standards metadata from `relay/config.yaml`
  unless a project explicitly opts into split metadata.

### Fixed

- The generated Relay sample no longer binds `person.id` to the API-key principal id,
  which made the Bruno "Read sample people" request return an empty result set.

## [0.1.0] - 2026-06-12

First tagged release of the `registryctl` CLI for Registry Commons.

### Added

- `registryctl init relay <dir>` - scaffold a local Relay-backed spreadsheet API project with a
  sample benefits workbook, Docker Compose file, project manifest, generated credentials, and a
  Bruno API collection.
- `registryctl init notary <dir>` - scaffold a standalone Notary project pointing at an existing
  Registry Data API source.
- `registryctl add notary --from local-relay` - add a Notary product to an existing Relay project.
- `registryctl start / stop / status / open / logs` - manage the local Compose project lifecycle
  and surface Relay and Notary API URLs.
- `registryctl smoke` - run built-in local smoke checks against the Relay API and write results to
  `output/smoke-results.json`.
- `registryctl notary smoke / open` - run smoke checks against the Notary API and open its docs.
- `registryctl openfn import` - import an OpenFn workflow URL or exported YAML into a Registry
  Notary OpenFn sidecar manifest, with topology validation, adaptor pin enforcement, per-item and
  native batch modes, and an optional Notary config snippet.
- `registryctl openfn convert` - convert a locally exported OpenFn project YAML into a sidecar
  manifest (lower-level variant of `import` without the OpenFn API fetch step).
- `registryctl bruno generate / open / run` - generate, open, and run the optional Bruno API
  collection for the local project.
- Digest-pinned container images for `registry-relay` and `registry-notary` to guarantee
  reproducible local environments.
- Credential generation using `ed25519-dalek` and `registry-platform-authcommon`; fingerprint
  commitments are verified at `start` and `smoke` time to catch accidental config drift.
- Install script (`install.sh`) for Linux x86_64, Linux aarch64, and macOS aarch64 without
  requiring a source checkout.

### Dependencies

- Pinned `registry-platform-authcommon` to the `v0.2.0` tag (was tracking `main`), ensuring a
  stable shared-library ABI for the release. (Closes issue #4, PR #15.)
