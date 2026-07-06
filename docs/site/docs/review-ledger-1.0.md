# Docs 1.0 review ledger

Working record of the docs/1.0-overhaul effort. One row per page. A page is
done only when its verdict is recorded and the claims behind it were verified
against code on this branch.

Verdicts: `verified` (page kept, claims anchored, at most style fixes) |
`rewritten` (substantive content changes) | `merged` (content folded into
another page; rationale required) | `deleted` (rationale required).

Status: `pending` | `surveyed` | `batched` (fix batch landed, gates green) | `done` (fresh-eyes passed).

TODO[evidence] budget: final count must be <= 2 (the pre-existing baseline),
each remaining marker justified here.

## Hand-authored pages

| Page | Status | Verdict | Notes |
|---|---|---|---|
| index.mdx | batched | rewritten | P3: clean homepage |
| changelog.mdx | batched | rewritten | P1: status current over unreviewed 2026-07-04 entry; long-line debt |
| accessibility.mdx | batched | rewritten | P2: baseline TODO[evidence] #1 (contrast audit); source_repos gap |
| start/quickstart.mdx | batched | rewritten | P2: hosted-lab URLs verified vs lab/ code; Solmara transition exposure |
| start/credential-tour.mdx | batched | rewritten | P2: hosts verified; fixture identities + negative control to verify |
| start/when-to-use.mdx | batched | verified | P3: clean |
| tutorials/configure-dhis2-claim-checks.mdx | batched | rewritten | P1: fully lab/-dependent, no Solmara equivalent; fate decision needed |
| tutorials/deploy-standalone-with-own-data.mdx | batched | rewritten | P2: claims solid; missing troubleshooting section, heavy style debt |
| tutorials/first-run-with-registry-lab.mdx | batched | rewritten | P1: only CI-executed tutorial; Solmara rewrite + drift-check port |
| tutorials/getting-started-fhir-evidence.mdx | batched | rewritten | P1: fully lab/-dependent, no Solmara equivalent; fate decision needed |
| tutorials/publish-spreadsheet-secured-registry-api.mdx | batched | rewritten | P3: best-anchored page; fix source_repos slug |
| tutorials/run-notary-standalone-for-api.mdx | batched | rewritten | P2: CLI claims verified; overlap with deploy-standalone noted |
| tutorials/verify-claim-registry-api.mdx | batched | rewritten | P2: problem-document JSON bodies need verification |
| tutorials/verify-opencrvs-claims.mdx | batched | rewritten | P1: doc_type should be how-to (IA names this case); no cleanup/troubleshooting |
| explanation/architecture.mdx | batched | rewritten | P3: spot-checks clean; 2 bold-led items |
| explanation/consultation-flow.mdx | batched | rewritten | P1: scope surface undercounted (identity_release; ops_read, metrics_read) |
| explanation/data-minimization-and-purpose-limitation.mdx | batched | rewritten | Tier-C heavy. P2: restates known-limitations hub; line-wrap debt |
| explanation/disclosure-modes-and-computed-answers.mdx | batched | rewritten | P2: restates hub; exists-rule semantics to verify; CCCEV leak claim confirmed |
| explanation/dpi-safeguards-alignment.mdx | batched | rewritten | P2: external framework figures unverified |
| explanation/evidence-issuance.mdx | batched | verified | P3: cleanest page |
| explanation/integration-patterns.mdx | batched | verified | P3: clean |
| explanation/known-limitations.mdx | batched | verified | hub itself clean (5/5 spot-checks); line-wrap debt |
| explanation/publishing-pipeline.mdx | batched | rewritten | P2: dead fixture path (registry-manifest/profiles/...); stray draft:true key |
| explanation/records-stay-home.mdx | batched | rewritten | Tier-C heavy. P2: restates hub; cache_dir claim + mermaid policy to check |
| explanation/threat-model.mdx | batched | rewritten | Tier-C heavy. P2: strongest page; 2 follow-ups (dup-claim-id, forward refs) |
| explanation/trusted-context-constraints.mdx | batched | verified | Tier-C heavy. P2: contract-id strings unchecked yet status current |
| map/boundaries-and-map.mdx | batched | rewritten | P2: doc_type mismatch (reference vs narrative); v0.8.1 pin outlier; 400-char lines |
| operate/upgrade-and-rollback.mdx | batched | rewritten | P1: deployment/not_ready claim wrong for Notary; last_reviewed integrity |
| reference/api-stability.mdx | batched | verified | P3: draft for GH#203; reference-vs-narrative tension; route claims unverified |
| reference/apis/index.mdx | batched | verified | P3: clean; archive_remote on personal account noted |
| reference/apis/registry-notary.mdx | batched | verified | P3: spot-checks all confirmed |
| reference/apis/registry-relay.mdx | batched | verified | P3: openapi_requires_auth confirmed; admin scopes unverified |
| reference/contracts.mdx | batched | verified | P3: all pins current v0.8.4 |
| reference/deprecation-policy.mdx | batched | verified | P3: precedent claims unverified |
| reference/environment-variables.mdx | batched | rewritten | P1: DATA_GATE_POSTGRES_ROOT_CERT_PATH undocumented (also code-naming flag) |
| reference/errors.mdx | batched | rewritten | P2: 45-row hand table violates data-file rule; v0.8.1 pin stale; content correct |
| reference/glossary.mdx | batched | rewritten | P3: standards_referenced missing 3 body terms |
| reference/itb-semic-evidence.mdx | batched | verified | P3: evidence on personal-account URLs, provenance flag |
| reference/registryctl.mdx | batched | rewritten | P1: `restart` missing from CLI reference; 38-row hand table; v0.8.1 pin |
| reference/standards.mdx | batched | rewritten | P2: frontmatter missing 5 of 22 yaml entries |
| security/hardening-checklist.mdx | batched | verified | Tier-C. P3: well-anchored; 5 medium-confidence items to close |
| security/index.mdx | batched | verified | Tier-C. P3: most rigorously anchored page |
| security/openssf-evidence.mdx | batched | rewritten | Tier-C. P1: cargo-deny row false/stale (landed 2026-07-02); v0.8.4 tense stale |
| security/report-a-vulnerability.mdx | batched | verified | Tier-C. P3: verbatim-consistent with SECURITY.md |
| security/self-assessment.mdx | batched | rewritten | Tier-C. P3: one wording imprecision |
| security/support-window.mdx | batched | rewritten | Tier-C. P2: leans on unratified api-stability draft as settled |
| spec/index.mdx | batched | verified | P3: register shell, clean |
| spec/rs-arc-g.mdx | batched | rewritten | P2: REQ-ARC-G-009 replay claim stronger than enforcement; softening in batch |
| spec/rs-dm-claim.mdx | batched | verified | P3: GH#232/GH#170 gap statements verified in code |
| spec/rs-dm-manifest.mdx | batched | verified | P3: sampled statements verified |
| spec/rs-doc.mdx | batched | verified | P3: conventions verified against all 9 pages |
| spec/rs-pr-notary.mdx | batched | verified | P3: 4 evidence citations resolve |
| spec/rs-pr-relay.mdx | batched | rewritten | P2: REQ-PR-RELAY-020 header list incomplete (inert unguarded parse path); caveat in batch |
| spec/rs-sec-g.mdx | batched | verified | audit verified accurate; PENDING Tier-C sign-off (Jeremi) |
| spec/rs-terms.mdx | batched | verified | P3: 5 new standards ids cross-checked in batch |
| decisions/rename-2026-05-23.mdx | batched | rewritten | baseline TODO[evidence] resolved: Phase-4 rename verified in code (Cargo.toml:87, openapi.rs, validate.rs, 14 snapshots) |

## Synced product pages (edit the sources, not products/**)

40 pages enumerated from src/data/repo-docs.yaml (13 relay, 22 notary,
5 manifest). All src paths exist; no page excluded from a current docset.
Coordinator fixed three doc_type errors in repo-docs.yaml
(opencrvs-onboarding, sidecar-trust-and-secrets: how-to to explanation;
oid4vci-wallet-interop: reference to how-to).

| Source file | Dest | Status | Verdict | Notes |
|---|---|---|---|---|
| crates/registry-relay/docs/README.md | registry-relay/index | batched | verified | P3; links to 2 unsynced files degrade to GitHub |
| crates/registry-relay/docs/client-integration.md | .../client-integration | batched | verified | P3 |
| crates/registry-relay/docs/configuration.md | .../configuration | batched | verified | P3: healthiest relay page |
| crates/registry-relay/docs/api.md | .../api | batched | rewritten | P3 + attribute-release API section added in batch |
| crates/registry-relay/docs/metadata.md | .../metadata | batched | verified | P3: 19 routes match exactly |
| crates/registry-relay/docs/ops.md | .../ops | batched | rewritten | P3 drift; heavy Title Case debt |
| crates/registry-relay/docs/provenance.md | .../provenance | batched | verified | P2: wire shapes verified in batch |
| crates/registry-relay/docs/openfn-relay-adaptor-guide.md | .../openfn-relay-adaptor-guide | batched | verified | P3: claims live outside this tree |
| crates/registry-relay/docs/standards-adapter-operator-guide.md | .../standards-adapter-operator-guide | batched | verified | P3: feature names verified |
| crates/registry-relay/docs/xlsx-readiness-contract.md | .../xlsx-readiness-contract | batched | rewritten | P2: narrative-in-reference + banned word |
| crates/registry-relay/STANDARDS_ASSUMPTIONS.md | .../standards-assumptions | batched | verified | P3 |
| crates/registry-relay/docs/relay-scenario-catalog.md | .../relay-scenario-catalog | batched | verified | P3: matrix sampled clean |
| crates/registry-relay/docs/release-notes.md | .../release-notes | batched | rewritten | P1: frozen at 0.1.0; rewrite from CHANGELOG in batch |
| products/notary/docs/README.md | registry-notary/index | batched | verified | P3; unsynced security-assurance.md link (owner decision) |
| products/notary/docs/architecture-overview.md | .../architecture-overview | batched | verified | P3: all spot-checks match |
| products/notary/docs/client-sdk-guide.md | .../client-sdk-guide | batched | rewritten | P2: idempotency rejection noted in batch; split is maintainer call |
| products/notary/docs/identity-and-record-matching.md | .../identity-and-record-matching | batched | verified | P2: minimum_assurance wired-vs-inert traced in batch |
| products/notary/docs/source-claim-modeling-guide.md | .../source-claim-modeling-guide | batched | verified | P2: bulk_mode unverified |
| products/notary/docs/operator-config-reference.md | .../operator-config-reference | batched | rewritten | P1: 12+ matching fields + 2 assisted-access gates added in batch (Tier-C-adjacent) |
| products/notary/docs/credential-lifecycle-status.md | .../credential-lifecycle-status | batched | rewritten | P2: status bits verified; promissory should fixed in batch |
| products/notary/docs/signing-key-provider.md | .../signing-key-provider | batched | verified | P3: Tier-C claims all verified |
| products/notary/docs/sd-jwt-vc-conformance-profile.md | .../sd-jwt-vc-conformance-profile | batched | verified | P3 |
| products/notary/docs/notary-capability-matrix.md | .../notary-capability-matrix | batched | verified | P3: banned word fixed in batch |
| products/notary/docs/notary-scenario-patterns.md | .../notary-scenario-patterns | batched | verified | P3: 27 Title Case headings fixed in batch |
| products/notary/docs/fhir-source-adapter-guide.md | .../fhir-source-adapter-guide | batched | verified | P2: one e2e test name to settle |
| products/notary/docs/script-rhai-source-adapter-guide.md | .../script-rhai-source-adapter-guide | batched | verified | P3 |
| products/notary/docs/opencrvs-onboarding.md | .../opencrvs-onboarding | batched | rewritten | P1: uncorroborated profile name checked in batch; doc_type fixed |
| products/notary/docs/opencrvs-dci-standalone-tutorial.md | .../opencrvs-dci-standalone-tutorial | batched | verified | P3: most rigorously verified in its batch |
| products/notary/docs/federated-evaluation-operator-guide.md | .../federated-evaluation-operator-guide | batched | verified | P3 |
| products/notary/docs/self-attestation-operator-guide.md | .../self-attestation-operator-guide | batched | verified | P3: prose blockquote fixed in batch |
| products/notary/docs/sidecar-trust-and-secrets.md | .../sidecar-trust-and-secrets | batched | verified | P2: fail-closed chain traced in batch (Tier-C); doc_type fixed |
| products/notary/docs/deployment-hardening-runbook.md | .../deployment-hardening-runbook | batched | verified | P2: audit field names verified in batch |
| products/notary/docs/api-reference.md | .../api-reference | batched | rewritten | P3: 29/29 routes match; per-item code prefixes fixed in batch |
| products/notary/docs/oid4vci-wallet-interop.md | .../oid4vci-wallet-interop | batched | verified | P2: banned words fixed; protocol details flagged; doc_type fixed |
| products/notary/docs/release-notes.md | .../release-notes | batched | verified | P3: maintained, matches 0.8.4 |
| products/manifest/docs/overview.md | registry-manifest/index | batched | rewritten | P1: wrong version + wrong binary name; fixed in batch |
| products/manifest/docs/validate-and-render.md | .../validate-and-render | batched | rewritten | P1: wrong binary name + fabricated cardinality format; fixed in batch |
| products/manifest/docs/profile-fixtures.md | .../profile-fixtures | batched | rewritten | P1: wrong binary name; fixed in batch |
| products/manifest/docs/reference.md | .../reference | batched | rewritten | P2: 6 contract omissions + ecosystem-bindings section added in batch |
| products/manifest/docs/itb-semic-validation.md | .../itb-semic-validation | batched | verified | P3: fully accurate vs script |

## Deletions and merges

No page was deleted or merged. Considered and declined:

| Page | Action | Rationale |
|---|---|---|
| tutorials/run-notary-standalone-for-api.mdx | keep (merge candidate with deploy-standalone) | Overlapping "Notary against a Relay-shaped source" scope, but one is registryctl-generated and one hand-rolled; merging would break the IA's first-run journey. Maintainer conversation flagged in final report. |
| tutorials/configure-dhis2-claim-checks.mdx + getting-started-fhir-evidence.mdx | keep (deletion candidates at lab/ removal) | Fully lab/-dependent with no Solmara equivalent; accurate against current main. Their fate belongs to the lab-deletion PR (#257), not this overhaul. |
| map/boundaries-and-map.mdx | keep, doc_type reference -> explanation | Narrative boundary prose plus a generated table; IA places it under Concepts, and two independent reviews judged the content explanation-shaped. File stays at map/ (directory follows URL). |

## TODO[evidence] register (final count must be <= 2)

| Page | Marker | Justification |
|---|---|---|

## Reader verification runs (verifying-tutorials-as-reader)

| Page | Verdict | Key findings |
|---|---|---|
| start/quickstart.mdx | pass-with-findings (clean run) | Both findings fixed on the page: expected-output block missing observed_at; curl-only token path moved inline |
| start/credential-tour.mdx | fail at eSignet sign-in | LIVE INFRA: hosted lab denies documented demo identity (relay_auth_subject_denied); fallback PIN fails client+server validation. Internal finding: registry-internal/docs/hosted-lab-esignet-signin-denial-2026-07-07.md. Page instructions match lab fixtures; honest troubleshooting row added. |
| tutorials/publish-spreadsheet-secured-registry-api.mdx | fail at "Start the local stack" | Product bug GH#278 (stale image digest pins in registryctl v0.8.4); troubleshooting rows added; page text otherwise accurate |
| tutorials/deploy-standalone-with-own-data.mdx | pass-with-findings | All fixed on the page: example config missing required aggregate_scope; false Notary default-config claim; amd64 platform note; doctor warning expectation; teardown section added |
| tutorials/getting-started-fhir-evidence.mdx | fail at just setup, then verified end-to-end post-deviation | Product bug GH#279 (justfile escaping); doc fixes applied: uv prerequisite, two-images fix, readiness wait, zsh env sourcing, troubleshooting rows |
| tutorials/verify-claim-registry-api.mdx | pass-with-findings (post-GH#278 deviation) | Fixed on page: smoke PASS line text, request_id variability note, GH#278 re-bake warning + literal pin syntax, compose project-name collision row. All JSON bodies and disclosure scenarios matched exactly. |
| tutorials/run-notary-standalone-for-api.mdx | pass-with-findings (post-GH#278 deviation) | Central promise concretely verified (predicate-only disclosure, no source-row fields). Fixed on page: literal pin syntax in the GH#278 row, cleanup reassurance. |
| tutorials/verify-opencrvs-claims.mdx | fail at start (GH#278), partial by design | Fixed on page: source URL now an explicit placeholder + base-URL prerequisite named; source.unavailable vs auth-error troubleshooting split; GH#278 row with pin syntax; jq field names (passed/actual_status); two broken onboarding links; platform-override wording matches actual registryctl behavior. |
| tutorials/configure-dhis2-claim-checks.mdx | environment-blocked | Ports 4311-4331 held by the running Solmara stack; stopping it was declined (volume/audit-chain risk). No execution coverage anywhere: residual gap, run after the Solmara stack can be paused or on another machine. Claims statically verified against lab/ compose+configs. |
| tutorials/first-run-with-registry-lab.mdx | environment-blocked (reader mode) | Same port conflict. Executable truth covered by CI: check-tutorial.sh executes this page end to end in the root lab job; reader-persona findings remain uncollected. |

## Issues filed from divergence findings

| Issue | Page(s) | Finding |
|---|---|---|
| [GH#278](https://github.com/registrystack/registry-stack/issues/278) | publish-spreadsheet, verify-claim, run-notary-standalone | registryctl v0.8.4 pins pre-0.8.4 service image digests; generated Relay project cannot start |
| [GH#279](https://github.com/registrystack/registry-stack/issues/279) | first-run, getting-started-fhir, configure-dhis2 | lab `just setup` broken on fresh clones ($$ escaping); Notary warm-up 500s; zsh env sourcing; undeclared uv prerequisite |
