# PR 748 salvage ledger

This ledger classifies every path changed by the backed-up pre-refactor PR.
It is a recovery and review record, not a list of files retained in the current
branch.

- Comparison base: `ef30a9eb3ec3e4f317a6f797757715338f9c54a5`
- Backup branch: `backup/pr-748-federation-v1-20260814`
- Backed-up head: `44e6616b6b80429a290762c42a7e163699a11854`
- Inventory command: `git diff --name-only ef30a9eb3ec3e4f317a6f797757715338f9c54a5..44e6616b6b80429a290762c42a7e163699a11854`
- Inventory size: 220 changed paths
- Coverage: 89 adapt, 72 preserve for
  later, 59 remove as wrong boundary, and zero retain

Every changed path below appears exactly once. For a path that also exists on
protected `main`, the decision applies only to the Federation PR delta, not to
the unrelated pre-existing file.

Files classified as adapt contribute only a selected concept to the new
Discovery implementation. The Federation implementation itself is absent.
Files classified as preserve for later remain recoverable only from the backup
branch and create no current production or public contract. Files classified as
remove as wrong boundary are deliberately excluded from Discovery.

| Decision | Meaning in this branch |
|---|---|
| Retain | Keep the exact Federation implementation unchanged. No changed path qualifies after the contract reset. |
| Adapt | Reimplement the useful part inside the smaller Discovery, Evidence, Relay, docs, CI, or test boundary. |
| Preserve for later | Keep the research recoverable in the backup and future-work ledger, with no dormant current code. |
| Remove as wrong boundary | Exclude trust, procedures, duplicate registration, native-client rewrites, or obsolete Federation documentation. |

## Retain

None. PR 748 is rebuilt from protected `main`; no Federation implementation
is carried over unchanged.

## Adapt

These deltas contain selected publication, exact-query, mapping,
immutable-index, client-selection, boundary-language, fixture, contract, CI, or
test ideas that are reimplemented proportionally in Registry Discovery.

```text
.github/scripts/ci_changes.py
.github/scripts/test_ci_changes.py
.github/workflows/ci.yml
AGENTS.md
Cargo.lock
Cargo.toml
README.md
crates/registry-evidencectl/Cargo.toml
crates/registry-evidencectl/src/federation.rs
crates/registry-evidencectl/src/lib.rs
crates/registry-evidencectl/tests/cli_surface.rs
crates/registry-federation-client-core/Cargo.toml
crates/registry-federation-client-core/src/directory.rs
crates/registry-federation-client-core/src/error.rs
crates/registry-federation-client-core/src/lib.rs
crates/registry-federation-client-core/src/model.rs
crates/registry-federation-client-core/src/selection.rs
crates/registry-federation-client/Cargo.toml
crates/registry-federation-client/README.md
crates/registry-federation-client/src/lib.rs
crates/registry-federation-client/tests/acceptance_fixtures.rs
crates/registry-federation-client/tests/directory_http.rs
crates/registry-federation-client/tests/native_composition.rs
crates/registry-federation/Cargo.toml
crates/registry-federation/README.md
crates/registry-federation/examples/federation-contracts.rs
crates/registry-federation/src/contracts.rs
crates/registry-federation/src/lib.rs
crates/registry-federation/src/main.rs
crates/registry-federation/src/model.rs
crates/registry-federation/src/problem.rs
crates/registry-federation/src/query.rs
crates/registry-federation/src/server.rs
crates/registry-federation/src/tooling.rs
crates/registry-federation/tests/v1_contract.rs
crates/registry-federationctl/Cargo.toml
crates/registry-federationctl/README.md
crates/registry-federationctl/src/main.rs
crates/registry-federationctl/tests/cli_ux.rs
crates/registry-relayctl/Cargo.toml
crates/registry-relayctl/src/federation.rs
crates/registry-relayctl/src/lib.rs
crates/registry-relayctl/src/shared.rs
crates/registry-relayctl/tests/cli_contract.rs
crates/registry-relayctl/tests/federation_export.rs
docs/site/astro.config.mjs
docs/site/scripts/federation-docs.test.mjs
docs/site/scripts/information-architecture.test.mjs
docs/site/src/content/docs/explanation/architecture.mdx
docs/site/src/content/docs/explanation/managed-federation.mdx
products/federation/README.md
products/federation/SPEC.md
products/federation/contracts/architecture-boundaries.yaml
products/federation/contracts/contract-inventory.yaml
products/federation/contracts/definition-of-done.yaml
products/federation/contracts/governance-authority.yaml
products/federation/contracts/lifecycle-review.yaml
products/federation/contracts/optional-profile-exclusions.yaml
products/federation/contracts/public-artifact-inventory.yaml
products/federation/contracts/security-invariant-matrix.yaml
products/federation/contracts/security-test-traceability.yaml
products/federation/examples/publication/README.md
products/federation/examples/publication/evidence.yaml
products/federation/examples/publication/relay.yaml
products/federation/fixtures/acceptance/evidence/adult-status.json
products/federation/fixtures/acceptance/evidence/legal-parent-relationship.json
products/federation/fixtures/acceptance/evidence/professional-licence.json
products/federation/fixtures/acceptance/evidence/residence-region.json
products/federation/fixtures/acceptance/fixture-index.json
products/federation/fixtures/acceptance/relay/business-register.json
products/federation/fixtures/acceptance/relay/civil-events.json
products/federation/fixtures/package-baseline/project/mappings/baseline.yaml
products/federation/fixtures/traceability/security-tests.json
products/federation/generated/contract-digests.json
products/federation/openapi/federation-v1.openapi.json
products/federation/schemas/api.schema.json
products/federation/schemas/common.schema.json
products/federation/schemas/evidence-mapping.schema.json
products/federation/schemas/federation-project.schema.json
products/federation/schemas/runtime-config.schema.json
products/federation/schemas/service-public.schema.json
products/federation/schemas/service-publication.schema.json
products/federation/scripts/check-contracts.sh
products/federation/scripts/check-source-neutrality.sh
products/federation/scripts/generate-contracts.sh
products/federation/scripts/generate_contract_digests.py
products/federation/scripts/test_contract_artifacts.py
products/federation/scripts/validate_contract_artifacts.py
products/federation/scripts/validate_optional_profile_exclusions.py
```

## Preserve for later

These deltas contain Federation-shaped non-Rust bindings, sealed-package lifecycle work,
provider-routing research, installer or release work, distribution evidence, or
release-workflow integration that does not fit the current Discovery journey.
The dedicated Discovery Node.js and Python bindings were implemented against
the smaller Discovery client API rather than reviving these Federation
surfaces. The listed deltas remain only on the backup branch and the still
deferred capabilities are summarized in `products/discovery/FUTURE-WORK.md`.

```text
.github/workflows/nightly-security.yml
.github/workflows/release-canary.yml
.github/workflows/release-candidate.yml
.github/workflows/release-repeatability.yml
.github/workflows/release.yml
crates/registry-federation-client-node/.gitignore
crates/registry-federation-client-node/Cargo.toml
crates/registry-federation-client-node/LICENSE
crates/registry-federation-client-node/README.md
crates/registry-federation-client-node/__test__/surface.test.js
crates/registry-federation-client-node/build.rs
crates/registry-federation-client-node/index.d.ts
crates/registry-federation-client-node/index.js
crates/registry-federation-client-node/package-lock.json
crates/registry-federation-client-node/package.json
crates/registry-federation-client-node/src/lib.rs
crates/registry-federation-client-py/Cargo.toml
crates/registry-federation-client-py/LICENSE
crates/registry-federation-client-py/README.md
crates/registry-federation-client-py/build.rs
crates/registry-federation-client-py/pyproject.toml
crates/registry-federation-client-py/python/registry_federation_client/__init__.py
crates/registry-federation-client-py/python/registry_federation_client/__init__.pyi
crates/registry-federation-client-py/python/registry_federation_client/py.typed
crates/registry-federation-client-py/python/registry_federation_client/types.py
crates/registry-federation-client-py/src/lib.rs
crates/registry-federation-client-py/tests/python/bootstrap.py
crates/registry-federation-client-py/tests/python/fixtures/test-ca.pem
crates/registry-federation-client-py/tests/python/test_federation_client.py
crates/registry-federation-client-py/tests/python/test_offline.py
crates/registry-federation-client-py/tests/python/test_package_layout.py
crates/registry-federation-client-py/tests/python/test_product_namespaces.py
crates/registry-federation-client-py/tests/python/test_typed_surface.py
crates/registry-federation/install.sh
crates/registry-federation/src/compiler.rs
crates/registry-federation/src/package.rs
crates/registry-federation/src/startup.rs
crates/registry-federation/tests/install_script.rs
products/federation/contracts/package-inventory.yaml
products/federation/fixtures/package-baseline/expected.package.json
products/federation/fixtures/package-baseline/project/federation-project.yaml
products/federation/schemas/provider-routing-vocabulary.schema.json
products/federation/schemas/sealed-package.schema.json
products/federation/scripts/check-package-baseline.sh
release/OPERATIONS.md
release/REPEATABLE-BUILDS.md
release/VERIFY.md
release/docker/Dockerfile.federation
release/scripts/build-release-binaries.sh
release/scripts/build-release-image.sh
release/scripts/check-debian13-images.py
release/scripts/check-gates-inventory.py
release/scripts/cleanup-release-candidates.py
release/scripts/client_registry.py
release/scripts/registry-release
release/scripts/release_candidate.py
release/scripts/smoke-evidence-client-package.js
release/scripts/smoke-federation-client-package.py
release/scripts/smoke-relay-client-package.js
release/scripts/smoke-release-image-oci-labels.sh
release/scripts/test_check_debian13_images.py
release/scripts/test_check_release_image_oci_labels.py
release/scripts/test_cleanup_release_candidates.py
release/scripts/test_client_registry.py
release/scripts/test_registry_release.py
release/scripts/test_registry_release_plans.py
release/scripts/test_release_candidate.py
release/scripts/test_release_repeatability_workflow.py
release/scripts/test_release_workflow_structure.py
release/scripts/test_verify_public_release.py
release/scripts/verify_public_release.py
release/security/federation-advisory-baseline.json
```

## Remove as wrong boundary

These deltas implement Discovery-owned trust, an Evidence procedure, duplicate
service registration, native Evidence or Relay client composition, or obsolete
Federation CLI documentation. None belongs in the Discovery product or current
provider SDK surface.

```text
crates/registry-evidence-client-node/Cargo.toml
crates/registry-evidence-client-node/README.md
crates/registry-evidence-client-node/__test__/federation.test-d.ts
crates/registry-evidence-client-node/__test__/federation.test.js
crates/registry-evidence-client-node/client.d.ts
crates/registry-evidence-client-node/client.js
crates/registry-evidence-client-node/federation.d.ts
crates/registry-evidence-client-node/federation.js
crates/registry-evidence-client-node/index.d.ts
crates/registry-evidence-client-node/index.js
crates/registry-evidence-client-node/package-lock.json
crates/registry-evidence-client-node/package.json
crates/registry-evidence-client-node/src/convert.rs
crates/registry-evidence-client-node/src/lib.rs
crates/registry-evidence-client-py/README.md
crates/registry-evidence-client-py/pyproject.toml
crates/registry-evidence-client-py/python/registry_evidence_client/__init__.pyi
crates/registry-evidence-client-py/python/registry_evidence_client/federation.py
crates/registry-evidence-client-py/python/registry_evidence_client/federation.pyi
crates/registry-evidence-client-py/src/lib.rs
crates/registry-evidence-client/Cargo.toml
crates/registry-evidence-client/README.md
crates/registry-evidence-client/src/federation.rs
crates/registry-evidence-client/src/lib.rs
crates/registry-federation-client-core/src/trust.rs
crates/registry-federation-client/tests/procedure_runtime.rs
crates/registry-relay-client-node/Cargo.toml
crates/registry-relay-client-node/README.md
crates/registry-relay-client-node/__test__/federation.test-d.ts
crates/registry-relay-client-node/__test__/federation.test.js
crates/registry-relay-client-node/client.d.ts
crates/registry-relay-client-node/client.js
crates/registry-relay-client-node/federation.d.ts
crates/registry-relay-client-node/federation.js
crates/registry-relay-client-node/index.d.ts
crates/registry-relay-client-node/index.js
crates/registry-relay-client-node/package-lock.json
crates/registry-relay-client-node/package.json
crates/registry-relay-client-node/src/lib.rs
crates/registry-relay-client-py/README.md
crates/registry-relay-client-py/pyproject.toml
crates/registry-relay-client-py/python/registry_relay_client/federation.py
crates/registry-relay-client-py/python/registry_relay_client/federation.pyi
crates/registry-relay-client/Cargo.toml
crates/registry-relay-client/README.md
crates/registry-relay-client/src/federation.rs
crates/registry-relay-client/src/lib.rs
docs/site/src/content/docs/reference/cli/evidencectl.mdx
docs/site/src/content/docs/reference/cli/evidencectl/federation.mdx
docs/site/src/content/docs/reference/cli/evidencectl/federation/export.mdx
docs/site/src/content/docs/reference/cli/relayctl.mdx
docs/site/src/content/docs/reference/cli/relayctl/federation.mdx
docs/site/src/content/docs/reference/cli/relayctl/federation/export.mdx
docs/site/src/content/docs/spec/rs-pr-relayctl.mdx
docs/site/src/data/generated/cli-reference.json
products/federation/fixtures/package-baseline/project/services/baseline.yaml
products/federation/schemas/evidence-procedure.schema.json
products/federation/schemas/service-registration.schema.json
products/federation/schemas/service-trust.schema.json
```
