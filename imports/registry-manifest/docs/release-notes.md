# Release Notes

## 0.1.1

- Added CPSV-AP renderer, federated evaluation manifest schema, and API catalog discovery publication.

## 0.1.0

- Cut Registry Manifest into an independent Cargo workspace with `registry-manifest-core` and `registry-manifest-cli`.
- Added portable metadata validation, renderer tests, CLI tests, profile fixture validation, and static publication commands.
- Added repository bootstrap files: Apache-2.0 license, security policy, CODEOWNERS, Dependabot, and GitHub Actions CI.

Known non-goals for this cut:

- No Registry Relay HTTP route hosting, caller scoping, runtime binding validation, audit sinks, or authorization policy.
- No Evidence Server claim computation, disclosure policy, credential issuance, service runtime, or OpenAPI generation.
- No official OpenCRVS, OpenSPP, OpenIMIS, or SP DCI profile claims until profile examples are reviewed against official artifacts or maintainer feedback.
