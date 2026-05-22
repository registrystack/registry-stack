# Release Notes

## 0.1.0

- Cut Registry Metadata into an independent Cargo workspace with `registry-metadata-core` and `registry-metadata-cli`.
- Added portable metadata validation, renderer tests, CLI tests, profile fixture validation, and static publication commands.
- Added repository bootstrap files: Apache-2.0 license, security policy, CODEOWNERS, Dependabot, and GitHub Actions CI.

Known non-goals for this cut:

- No Registry Relay HTTP route hosting, caller scoping, runtime binding validation, audit sinks, or authorization policy.
- No Evidence Server claim computation, disclosure policy, credential issuance, service runtime, or OpenAPI generation.
- No official OpenCRVS, OpenSPP, OpenIMIS, or SP DCI profile claims until profile examples are reviewed against official artifacts or maintainer feedback.
