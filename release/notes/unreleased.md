# Registry Stack unreleased changes

This note supplements the product changelogs for the current standalone-product
refactor. Use matching tools and runtimes. BReg's Record, Dataset, Action and
Proposal model and Evidence's normalized project model replace their previous
contracts directly; the fresh-project boundary is documented in
[release operations](../OPERATIONS.md#rehearse-the-upgrade-from-the-previous-release).

## Evidence fixture controls

BREAKING: the `EvidenceFixture` alpha format keeps its current envelope and
replaces snake_case control keys with camelCase. Both fixture forms now reject
unknown control keys through the shared YAML reader, and the generated schema
uses the same typed controls. The old names receive `config.removed-key` with
their replacement, rather than being accepted as aliases.

Apply these renames only at the listed control locations:

| Location | Old keys | Replacement keys, in the same order |
| --- | --- | --- |
| Root | `synthetic_only`, `coequal_acceptance_definition`, `provider_contract`, `privacy_expectation` | `syntheticOnly`, `coequalAcceptanceDefinition`, `providerContract`, `privacyExpectation` |
| `common` and each `cases` item | `observed_at`, `legal_local_date`, `verified_token_claims` | `observedAt`, `legalLocalDate`, `verifiedTokenClaims` |
| Each `cases` item | `expected_lookup`, `expected_public_problem`, `expected_subject_roles`, `derivation_runs`, `signed_success`, `source_failure`, `companion_bundle`, `injected_derivation`, `expected_value`, `expected_values` | `expectedLookup`, `expectedPublicProblem`, `expectedSubjectRoles`, `derivationRuns`, `signedSuccess`, `sourceFailure`, `companionBundle`, `injectedDerivation`, `expectedValue`, `expectedValues` |
| `privacyExpectation` | `evidence_contains`, `evidence_excludes`, `diagnostics_exclude`, `member_inputs`, `minimization_claim`, `subject_bindings` | `evidenceContains`, `evidenceExcludes`, `diagnosticsExclude`, `memberInputs`, `minimizationClaim`, `subjectBindings` |

Preserve all nested source, response, selector, claim, fact, provider and
expected-value data. Those keys belong to their source and output contracts.
Production Rhai names such as `observed_at` and `legal_local_date` keep their
existing ABI spelling. The reference and coequal forms retain their existing
semantics; changing a key does not convert between them. See the maintained
[fixture contract](../../products/evidence/reference/request-adapter/deployment-projects/FIXTURES.md).

Run `evidencectl test PROJECT --target TARGET --deny-warnings` after editing,
resolve any named unknown key or duplicate case ID, and rebuild the package
with `evidencectl package PROJECT --target TARGET --output OUTPUT`. A changed
fixture changes the captured package bytes and their digests. Earlier split
Evidence projects still require a fresh normalized project as described in
release operations; these fixture edits do not create an in-place state upgrade.

`evidencectl check --file CLIENT.yaml` now checks the local access-client format
through the same typed reader and pure value checks used by registration. Public
client documents use the shared 1 MiB configuration limit. Registration retains
its private-key, file ownership and path checks.
