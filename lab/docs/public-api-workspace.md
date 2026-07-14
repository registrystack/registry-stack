# Public API Workspace Spec

Page type: implementation spec
Product: Registry Lab
Layer: public demo, API exploration, access-boundary testing
Audience: integrators, demo operators, and maintainers

## Definition Of Done

The public API workspace is done only when all criteria below are satisfied:

- A Bruno collection exists at `requests/registry-lab/` and opens successfully in
  Bruno without manual file edits.
- The collection includes a committed `Hosted Lab` environment whose public
  origins target `*.lab.registrystack.org`.
- The committed `Hosted Lab` environment includes every public demo caller token
  currently listed in `config/lab-homepage/public-demo-credentials.env`.
- No committed Bruno file contains infrastructure secrets, Relay consultation
  tokens, signing keys, private keys, database credentials, Redis credentials,
  Coolify tokens, eSignet admin credentials, or upstream system credentials.
- The token values in the `Hosted Lab` environment are generated or validated
  from `config/lab-homepage/public-demo-credentials.env`; manual drift between
  the homepage credentials and the Bruno environment is caught by a repository
  check.
- A `Local Compose` environment exists with localhost service URLs and token
  variable names matching the `.env` values produced by `just generate`.
- The first committed collection slice contains these folders:
  `00 - Start Here`, `10 - Relay Metadata`, `20 - Relay Access Boundaries`, and
  `30 - Notary Evaluation`.
- `00 - Start Here` contains requests for the lab homepage, static metadata
  root or catalog, hosted service health or discovery endpoints, and at least
  one Notary OpenAPI endpoint.
- `10 - Relay Metadata` contains successful metadata or dataset-list requests
  for civil, social protection, and health Relay services.
- `20 - Relay Access Boundaries` contains at least one successful authorized
  row or aggregate request and at least two deliberate denial probes proving
  that a public token cannot use a surface outside its intended scope.
- `30 - Notary Evaluation` contains source-free self-attested Notary discovery
  plus positive and negative evaluation examples for generated projects.
- Every request in the first slice has Bruno tests that assert the expected HTTP
  status and at least one response invariant specific to that request.
- The collection README explains that the committed hosted tokens are public
  demo credentials and names the credential source file.
- The collection README explains how to run the hosted slice and the local slice.
- A CI or local verification command validates Bruno file presence, environment
  token parity, and forbidden secret-name patterns.
- The hosted first-slice requests pass against the live hosted lab, or any live
  failure is recorded with the exact endpoint, expected status, actual status,
  and blocker.
- The local first-slice requests pass after `just generate`, `just build`,
  `just up`, and the required smoke preconditions, or any skipped local check is
  recorded with the exact missing dependency.
- The docs index links to this spec and the collection README.

## Scope

This workspace is a human-operated API workspace for exploring Registry Lab. It
does not replace smoke scripts, release checks, or hosted deployment validation.

The first implementation covers the public hosted lab and the local Compose
equivalent for the same surfaces. Relay-only, source-free Notary-only, and
combined project topologies remain distinct. Combined Notary evaluation uses
compiler-pinned Relay consultations rather than direct source connectors.

## Public Credential Boundary

The following values may be committed in the hosted Bruno environment because
they are intentionally public demo credentials:

- Relay metadata client tokens.
- Relay row reader tokens for seeded public demo data.
- Relay aggregate reader tokens for seeded public demo data.
- Relay evidence-only tokens intended for public evidence verification demos.
- Public Notary caller tokens listed in
  `config/lab-homepage/public-demo-credentials.env`.

The following values must never be committed to the API workspace:

- Relay consultation tokens used internally by Notary.
- Notary signing keys or issuer private keys.
- eSignet client private keys, admin credentials, or seed operator credentials.
- Zitadel admin or machine-user credentials not already published as public demo
  caller credentials.
- Upstream system usernames, passwords, or private integration tokens.
- Database, Redis, Coolify, SSH, webhook, or infrastructure credentials.

## Collection Shape

The collection should be committed under:

```text
requests/registry-lab/
```

The initial structure is:

```text
requests/registry-lab/
  bruno.json
  collection.bru
  README.md
  environments/
    Hosted Lab.bru
    Local Compose.bru
  00 - Start Here/
  10 - Relay Metadata/
  20 - Relay Access Boundaries/
  30 - Notary Evaluation/
```

The hosted environment should be immediately usable against
`lab.registrystack.org` without copying tokens from another page. The collection
README should still point to `lab.registrystack.org` and
`config/lab-homepage/public-demo-credentials.env` as the public credential
sources.

## Request Rules

Each request must be named for the behavior it proves, not only the endpoint it
calls. Prefer names such as `Civil metadata token cannot read rows` over
`GET records`.

Each request must include:

- The full intended URL through environment variables.
- The auth header or API key header used by the target service.
- Required domain headers such as `Data-Purpose` when the service requires them.
- Bruno tests for status code and at least one request-specific response value.
- A short description when the behavior is non-obvious, especially for deliberate
  denial probes.

Requests must not depend on hidden state created by another request unless the
folder README or request description says so. The first slice should avoid
multi-step stateful flows where possible.

## Verification

The implementation should add a small repository check that can be run locally
and in CI. The check must:

- Parse `config/lab-homepage/public-demo-credentials.env`.
- Parse the Bruno `Hosted Lab` environment.
- Fail if any public credential from the homepage env is missing or different in
  the Bruno hosted environment.
- Fail if a forbidden secret-name pattern appears in committed Bruno files.
- Fail if any required first-slice folder or request file is missing.

The hosted live run should be performed before marking the first slice complete.
The run evidence should list each request group, pass/fail counts, and any
blocked live dependency.

## Implementation Plan

### Wave 1: Spec And Skeleton

- Worker A creates `requests/registry-lab/` with Bruno collection metadata,
  `Hosted Lab`, `Local Compose`, README, and the four first-slice folders.
- Worker B creates the validation script for credential parity, forbidden
  secret-name patterns, and required collection structure.
- Worker C updates docs links and keeps the homepage credential source unchanged.

Definition of done:

- `requests/registry-lab/` opens in Bruno.
- `Hosted Lab` contains all values from
  `config/lab-homepage/public-demo-credentials.env`.
- The validation script passes.
- Docs link to the collection and this spec.

Code-review checkpoint:

- Review only skeleton, credential handling, and validation coverage.
- Do not proceed until reviewers confirm no forbidden credential category is
  present in committed Bruno files.

### Wave 2: First Hosted Requests

- Worker A implements `00 - Start Here` hosted requests.
- Worker B implements `10 - Relay Metadata` hosted requests.
- Worker C implements `20 - Relay Access Boundaries` hosted success and denial
  probes.
- Worker D implements `30 - Notary Evaluation` source-free Notary discovery,
  a positive evaluation, and a service-policy denial probe.

Definition of done:

- Every first-slice hosted request has status and response-invariant tests.
- Every first-slice hosted request passes against the live hosted lab, or a
  blocker record names the exact endpoint, expected result, actual result, and
  owner.
- The validation script still passes.

Code-review checkpoint:

- Review request names, auth headers, expected failures, and Bruno tests.
- Do not mark a request done unless its test asserts both status and a
  behavior-specific response invariant.

### Wave 3: Local Compose Parity

- Worker A maps `00 - Start Here` to localhost URLs.
- Worker B maps `10 - Relay Metadata` to localhost URLs.
- Worker C maps `20 - Relay Access Boundaries` to localhost URLs.
- Worker D maps `30 - Notary Evaluation` to localhost URLs.

Definition of done:

- The local environment uses local service URLs and generated `.env` variable
  names only.
- The first-slice local requests pass after `just generate`, `just build`,
  `just up`, and the required smoke preconditions.
- Any skipped local check names the missing command, service, or dependency.

Code-review checkpoint:

- Review hosted/local parity and confirm the local requests prove the same
  behavior as the hosted requests.
- Do not mark local parity done until the run evidence includes command output
  summaries for setup and request execution.

### Wave 4: Release Gate

- Worker A adds the validation command to the project verification path.
- Worker B documents the final run procedure in the collection README.
- Worker C self-reviews the diff for unrelated changes and dirty-worktree
  safety.

Definition of done:

- The validation command is runnable by maintainers.
- The final hosted and local run evidence is attached to the change or recorded
  in the PR.
- No unrelated dirty files are included.

Code-review checkpoint:

- Review the final diff, validation output, hosted run evidence, and local run
  evidence.
- Merge only when every definition-of-done item above is satisfied or listed as
  a true blocker with exact reason.
