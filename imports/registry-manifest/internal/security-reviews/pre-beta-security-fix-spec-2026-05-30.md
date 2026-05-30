# Registry Manifest Pre-Beta Security Fix Spec

- **Date:** 2026-05-30
- **Source audit:** `internal/security-reviews/beta-security-audit-2026-05-30.md`
- **Release target:** first beta release of `registry-manifest` 0.1.2
- **Primary goal:** no schema-valid malicious manifest can write outside the publish tree, repoint protected semantic prefixes, crash or stall the parser, or inject attacker-controlled structural RDF node identities into trusted renderer output.

## Release Blockers

The following items must be fixed before tagging beta:

1. H1: `profiles[].id` arbitrary-path file write during `publish`.
2. H2: manifest `vocabularies` can override protected well-known prefixes.
3. H3 and M1: YAML alias amplification and pre-validation parse CPU/memory DoS.
4. H4 and M4: unvalidated dataset `public_services[].id` and codelist concept `@id` paths.

The fast-follow section at the end lists additional hardening that is useful for the same release but is not part of the conditional-go blocker set.

## Design Constraints

- Keep `registry-manifest-core` portable. Do not add web, auth, Notary, database, runtime server, or CLI-only dependencies to core.
- Preserve the manifest format where existing shipped examples are already valid, except for disallowing YAML anchors and aliases.
- Prefer validation failures over silent rewriting for malicious or ambiguous input.
- Use `validate_manifest` as the authoritative schema/value guard for core semantics.
- Keep CLI filesystem containment checks as defense in depth, even when core validation should make dangerous path segments impossible.
- Add focused regression tests for every blocker.

## P0. Safe Publish Paths And Profile Claims

### Problem

`ProfileClaim.id` is copied into `CompiledMetadata` without validation and `publish` writes `out/profiles/{id}.json`. A relative traversal such as `../../../../tmp/poc` or an absolute id such as `/tmp/poc` writes outside `--out` when the target parent exists.

### Requirements

- Validate every `manifest.profiles[]` entry in `validate_manifest`.
- Apply `validate_id` to `profiles[].id`.
- Validate `profiles[].version` is non-empty.
- Enforce `profiles[].id` uniqueness within `manifest.profiles`.
- Keep `catalog.application_profiles[]` validation unchanged.
- Add CLI publish containment checks for generated artifact paths:
  - Reject absolute generated filenames and any generated path component equal to `..`.
  - Ensure the final write target remains under the intended root before calling `fs::write`.
  - Apply the same helper to JSON artifact writes used by `publish`.
- Do not rely on string prefix checks alone for containment. Canonicalize the existing output root after `create_dir_all`, lexically normalize the target against that root, and compare path components.
- Do not canonicalize the final write target directly, because it normally does not exist yet. Intermediate symlink races are acceptable for this defense-in-depth layer, but the helper must not depend on the target file already existing.
- Do not break the documented `--site-root` behavior. Writes under `--site-root/.well-known` should be contained within `--site-root`; bundle writes should be contained within `--out`.

### Acceptance Tests

- Core validation rejects:
  - `profiles: [{ id: "../x", version: "1" }]`
  - `profiles: [{ id: "/tmp/x", version: "1" }]`
  - duplicate `profiles[].id`
  - blank `profiles[].version`
- `publish` fails without writing outside `--out` when given a manifest with malicious `profiles[].id`.
- Add a CLI regression test that creates a temporary outside directory, attempts both relative traversal and absolute profile ids, and asserts no outside file is created.

## P0. Protected Vocabularies And IRI Well-Formedness

### Problem

`vocabularies` is manifest-controlled and is consulted before built-in prefixes in `expand_uri`. A manifest can redefine `cccev`, `dcat`, `odrl`, and other protected terms so structural `@id`, `@type`, `sh:path`, and `sh:targetClass` positions point at attacker namespaces.

### Requirements

- Define one canonical table of built-in prefixes and namespace IRIs.
- Use that table consistently for:
  - validation of `vocabularies`
  - `expand_uri`
  - `expand_policy_uri`
  - JSON-LD context construction, where practical
- Treat built-in prefixes as protected. A manifest must not be able to change their meaning.
- Reject any `vocabularies` key that matches a protected built-in prefix unless the value is byte-identical to the built-in value. This exact carve-out is required for shipped fixtures, which currently redeclare `eli: http://data.europa.eu/eli/ontology#`.
- Make `expand_uri` consult built-ins before manifest vocabularies as defense in depth, so a missed validation call still cannot repoint a protected prefix.
- Require custom vocabulary keys to use a conservative prefix grammar:
  - lower-case ASCII letters, digits, `_`, or `-`
  - starts with a lower-case ASCII letter
  - no colon, slash, dot, whitespace, or unicode confusables
- Require custom vocabulary values to be absolute `http://` or `https://` IRIs.
- Add a post-expansion IRI sanity check used by `validate_uri`, `validate_optional_uri`, and policy URI validation:
  - reject empty expanded IRIs
  - reject ASCII whitespace
  - reject C0 controls
  - reject `<`, `>`, `"`, `{`, `}`, `|`, `^`, and backtick
- Continue to accept existing shipped examples.
- Rebuilding `@context` from the resolved namespace table is allowed as defense in depth, but it is not a substitute for protected-prefix enforcement.

### Acceptance Tests

- Validation rejects:
  - `vocabularies: { cccev: "https://attacker.example/ns#" }`
  - `vocabularies: { dcat: "https://attacker.example/ns#" }`
  - custom prefixes with dots, slashes, uppercase, whitespace, or unicode
  - custom vocabulary values that are relative, `urn:`, `did:`, blank, or malformed
  - CURIE suffixes containing whitespace, controls, `<`, `>`, `"`, `{`, `}`, `|`, `^`, or backtick
- Validation accepts:
  - a custom safe prefix such as `example_vocab: "https://example.org/ns#"`
  - protected prefixes only when byte-identical to their built-in value
- Rendering a manifest with `rdf_type: cccev:Requirement` must still produce the canonical `http://data.europa.eu/m8g/Requirement`.

## P0. YAML Input Resource Limits

### Problem

`load_manifest` and profile fixture loaders call `serde_yaml_ng::from_str` with no byte cap or alias rejection. A 220 KB alias-amplification input has been measured at 412 MB peak RSS before validation. Separately, nested-flow YAML can burn seconds to minutes of CPU before validation rejects it.

### Requirements

- Add a single CLI input-loading helper for YAML files.
- Use it for:
  - `load_manifest`
  - profile descriptor loading
  - profile fixture loading
  - any untyped `serde_yaml_ng::Value` parse used by `validate-profiles`
- Check file size with `fs::metadata().len()` before reading into memory.
- Enforce a default maximum YAML input size of **64 KiB** for manifests, profile descriptors, and fixtures.
- The limit may be a private constant in the CLI. Do not add an environment-variable bypass for beta.
- Reject YAML aliases and anchors before typed deserialization.
- Use an event-based prepass that detects real YAML `Alias` and anchored scalar/sequence/mapping events without materializing aliases.
- `serde_yaml_ng` does not expose the needed libyaml events through its public API, so add a small direct parser/event-scanning dependency for this prepass. Prefer `unsafe-libyaml` if its public API is practical, since it is already in the dependency tree transitively; otherwise choose a maintained YAML event parser with a narrow use in the CLI.
- Do not implement a hand-rolled lexical scanner as the load-bearing alias/anchor defense. A scanner that cannot fully distinguish YAML syntax from `&` or `*` inside URLs, quoted strings, block scalars, and comments is too fragile for this finding.
- If an event-based prepass cannot be implemented in time, do not treat a lexical scanner as an acceptable substitute. The only fallback is a documented release-risk exception: reduce the size cap to **32 KiB**, explicitly defer alias rejection, and record that H3 is mitigated by size only rather than fully closed.
- Return deterministic CLI errors:
  - size limit: `metadata.manifest.too_large` or equivalent profile-specific code
  - alias/anchor: `metadata.manifest.aliases_unsupported` or equivalent profile-specific code
- Add post-deserialization count limits in `validate_manifest` for large collections. Initial limits:
  - `profiles`: 64
  - `catalog.conforms_to`: 64
  - `catalog.application_profiles`: 32
  - top-level `requirements`, `evidence_types`, `authorities`, `public_services`, `data_services`, `forms`, `datasets`, `codelists`: 256 each
  - per-dataset `entities`: 256
  - per-entity `fields` and `relationships`: 512 each
  - per-codelist `concepts`: 1024
  - per-list URI fields such as `concepts`, `applicable_legislation`, `conforms_to`: 128
- Keep limits centralized as named constants so future profile needs can raise them deliberately.

### Acceptance Tests

- CLI validation rejects a manifest larger than 64 KiB before `serde_yaml_ng::from_str`.
- CLI validation rejects a manifest containing:
  - anchored scalar plus aliases
  - anchored sequence
  - anchored mapping
  - flow-style aliases
- CLI validation accepts existing shipped manifests and profile descriptors.
- CLI validation accepts plain `&` and `*` characters inside URLs, quoted strings, block scalars, and comments.
- The measured H3 shape must fail quickly and must not allocate hundreds of MB. The test should use a small scaled-down fixture suitable for CI.
- A nested-flow input just over the size limit must fail on size before parse.
- Core validation rejects collection counts above the configured limits with path-specific errors.

## P0. Structural RDF Identity Validation

### Problem

Dataset-embedded `public_services[].id` and `codelists[].concepts[]` flow into structural RDF positions without the validation applied to similar fields.

### Requirements

#### Dataset Public Services

- For beta, accept a present `datasets[].public_services[].id` only if it is either:
  - a local id accepted by `validate_id`; or
  - a well-formed absolute `http://` or `https://` IRI that passes the post-expansion IRI sanity check.
- Do not require dataset public service IRIs to share `catalog.base_url` origin. The shipped CPSV-AP fixture deliberately models a child-support catalog that references a health-authority service at `https://health.example.gov/...`; this is legitimate cross-authority CPSV-AP modeling.
- Do not accept `urn:`, `did:`, relative IRIs, compact IRIs, `javascript:`, path traversal strings, whitespace/control-delimited strings, or malformed IRI tokens for this field.
- Keep generated fallback ids for missing ids and emit them in the same current shape.
- Enforce uniqueness of present dataset public service ids within a dataset.
- Track the residual modeling issue separately: an externally-referenced public service should not automatically imply `cv:hasCompetentAuthority` equals the catalog publisher. That is a semantic renderer refinement, not a beta blocker for syntactic safety.

#### Codelist Concepts

- Validate every `codelists[].concepts[]`.
- Require `concept.code` to be non-empty after trimming and reject C0 control characters.
- Preserve real-world codelist code shapes such as uppercase ISO/currency codes and dotted classification codes.
- When `concept.iri` is absent, percent-encode `concept.code` before interpolating it into the fallback `@id` (`{scheme_iri}/{encoded_code}`). Encode at least slash, whitespace, controls, and RFC 3987 delimiter characters; preserving unreserved ASCII is fine.
- Enforce `concept.code` uniqueness within a codelist.
- Validate `concept.iri`, when present, with the same URI validation and post-expansion IRI sanity check used elsewhere.
- Preserve existing codelist examples.

### Acceptance Tests

- Validation rejects dataset public service ids containing:
  - relative IRIs, compact IRIs, `urn:`, `did:`, `javascript:`, path traversal strings, whitespace-delimited garbage, controls, and IRI delimiters
  - duplicates within the same dataset
- Validation accepts the shipped CPSV-AP dataset public service id `https://health.example.gov/services/health-coverage-registry`.
- Validation rejects codelist concepts with:
  - blank code
  - C0 controls in code
  - duplicate code
  - malformed or attacker-controlled compact IRI suffix in `iri`
- Validation accepts codelist codes such as `US`, `USD`, `ACTIVE`, and `01.02`; fallback `@id` rendering percent-encodes any unsafe bytes.
- Rendering valid codelists still emits `skos:Concept` nodes with expected canonical ids.
- Rendering valid dataset public services still passes existing CPSV-AP tests.

## Same-Release Hardening

These items should be implemented in the same release if time permits. They are not beta blockers unless product risk tolerance changes.

1. M2: require `federation.jwks_uri` and `federation.federation_api` to share the `issuer` origin, or add an explicit opt-in field for cross-origin key/API endpoints.
2. L2: validate form JSON Schema property names. Add a conservative grammar for `FormFieldManifest.name` and enforce uniqueness across top-level fields plus non-repeatable section fields that land in the same `properties` map. Do not apply `validate_id` because existing camelCase wire names must remain valid.
3. L3: validate `evaluation_profiles[].ruleset` with `validate_id` or a documented ruleset-id grammar.
4. L5: constrain `validate-profiles` fixture paths to stay under the profile descriptor directory. Reject absolute paths and `..`.
5. L4 and I1: document raw manifest publication clearly and consider a `--no-copy-manifest` flag or warning for public deployments.
6. L6: validate or type-check ODRL `right_operand.value` against its asserted datatype where feasible, or document it as an opaque literal assertion.
7. I2: validate form field `language` as BCP-47 or a documented conservative subset before emitting it in form schemas.
8. I3: validate `LocalizedText` language tags and values before any renderer emits localized maps.

## Implementation Order

1. Add validation helpers and tests in `registry-manifest-core`.
2. Fix `profiles[]`, vocabularies, expanded IRI sanity, dataset public service ids, and codelist concepts in core validation.
3. Add CLI YAML loading helper with size and alias/anchor rejection.
4. Add CLI publish containment helper and convert publish writes to use it.
5. Add focused regression tests for each blocker.
6. Run the verification ladder.

## Verification Ladder

Run these before considering the spec complete:

```sh
cargo fmt --all -- --check
cargo test -p registry-manifest-core
cargo test -p registry-manifest-cli
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p registry-manifest-cli -- validate-profiles profiles
cargo build --workspace --all-targets
```

If a command is skipped, record the exact reason in the release notes or PR description.

## Done Criteria

- All P0 acceptance tests exist and pass.
- All shipped manifests, fixtures, and profile descriptors validate without anchors or aliases.
- `publish` cannot write generated artifacts outside `--out` or `--site-root`.
- Protected built-in vocabulary prefixes cannot be repointed by a manifest.
- The H3 alias-amplification shape fails before typed deserialization and without large allocation.
- Structural RDF identity fields added in H4 and M4 are validated before rendering.
- The final diff contains no unrelated formatting or generated-output churn.

## Concrete Definition Of Done

This work is done only when all of the following are true:

- Every P0 behavior in this spec is implemented in code, with no placeholder branches, TODOs, or intentionally skipped validation paths.
- Every P0 acceptance test listed in this spec has a corresponding automated test in `registry-manifest-core` or `registry-manifest-cli`.
- The tests include malicious fixtures for:
  - relative and absolute `profiles[].id` path escape attempts;
  - protected vocabulary prefix override attempts;
  - malformed expanded IRI/CURIE suffix attempts;
  - YAML anchor and alias inputs;
  - oversized YAML input;
  - invalid dataset public service ids;
  - invalid and duplicate codelist concepts.
- The tests include positive fixtures proving:
  - all shipped manifests and profile descriptors still validate;
  - shipped `eli` vocabulary redeclarations are accepted only because they are byte-identical to the built-in value;
  - the shipped cross-origin CPSV-AP dataset public service IRI remains valid;
  - codelist codes `US`, `USD`, `ACTIVE`, and `01.02` are accepted and fallback concept `@id` values are percent-encoded when needed.
- `publish` is covered by tests that assert no file is created outside `--out` or `--site-root` for path traversal and absolute-path profile ids.
- YAML size and anchor/alias checks run before typed `serde_yaml_ng::from_str` deserialization in all CLI manifest, profile descriptor, fixture, and untyped `Value` parse paths.
- `expand_uri` cannot repoint a protected prefix even if validation is bypassed.
- The H3 regression test fails quickly in CI and does not depend on allocating large memory.
- The following commands pass from the repository root:

```sh
cargo fmt --all -- --check
cargo test -p registry-manifest-core
cargo test -p registry-manifest-cli
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p registry-manifest-cli -- validate-profiles profiles
cargo build --workspace --all-targets
```

- A final review confirms the diff touches only intended source, test, fixture, and documentation files, and that unrelated dirty worktree files were not reverted, reformatted, or mixed into the change.

## Wave Implementation Plan

Use parallel workers only for independent read/write surfaces. The parent agent owns integration, conflict resolution, final verification, and review gates.

### Wave 1 — Core Validation And Renderer Safety

- Worker A: implement shared vocabulary table, protected-prefix validation, built-in-first expansion, and expanded IRI sanity checks in `registry-manifest-core`.
- Worker B: implement `profiles[]`, dataset public service id, and codelist concept validation, including percent-encoded fallback codelist concept `@id` rendering.
- Worker C: add focused core tests for all Wave 1 negative and positive cases.

Definition of done:

- `cargo test -p registry-manifest-core` passes.
- Core tests prove all Wave 1 P0 acceptance cases listed above.
- All shipped manifests still validate through core validation.

Code-review checkpoint:

- Review validation helpers for a single source of truth and no duplicated protected-prefix tables.
- Review rendered JSON-LD/SHACL outputs for safe structural IRIs.
- Do not start Wave 2 integration until every Wave 1 test is passing.

### Wave 2 — CLI Input And Filesystem Containment

- Worker D: implement the shared CLI YAML loader with byte cap and event-based anchor/alias rejection.
- Worker E: implement publish containment helpers for `--out` and `--site-root` writes.
- Worker F: add CLI tests for oversized YAML, anchor/alias rejection, traversal/absolute path write attempts, and shipped profile validation.

Definition of done:

- `cargo test -p registry-manifest-cli` passes.
- CLI tests prove YAML guards execute before typed deserialization.
- CLI tests prove malicious publish inputs create no outside files.
- `cargo run -p registry-manifest-cli -- validate-profiles profiles` passes.

Code-review checkpoint:

- Review that no hand-rolled YAML lexical scanner is the load-bearing alias/anchor defense.
- Review containment logic against non-existent targets and absolute path joins.
- Do not mark H1, H3, or M1 closed until the CLI tests demonstrate the actual failure modes.

### Wave 3 — Integration, Hardening Sweep, And Release Gate

- Parent agent integrates Wave 1 and Wave 2 changes, resolves conflicts, and runs the full verification ladder.
- Reviewer worker performs a final diff review focused on security regressions, missed acceptance tests, and unrelated churn.
- Optional worker implements same-release hardening items only after all P0 checks are green.

Definition of done:

- Full verification ladder passes exactly as listed in the Concrete Definition Of Done.
- Reviewer returns no blocking findings.
- Any skipped optional hardening item is explicitly listed as not part of the P0 beta gate.

Code-review checkpoint:

- Confirm each audit blocker has a named test and a passing command proving closure.
- Confirm no feature is marked done because it is partially implemented or manually tested only.
- Confirm release notes or PR description list commands run, results, residual risks, and any intentionally deferred hardening.
