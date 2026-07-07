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
| tutorials/first-run-with-registry-lab.mdx | done | rewritten (replaced) | Replaced 2026-07-07 by tutorials/first-run-with-solmara-lab.mdx after registrystack/solmara-lab went public; redirect in astro.config.mjs; check-tutorial.sh contract ported (3 steps / 4 verify / 16 services, solmara-lab pinned at 1af06c8) |
| tutorials/first-run-with-solmara-lab.mdx | done | rewritten (new) | Reader run passed verbatim twice (findings folded back); single-page fresh-eyes review passed post-fix; status current |
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

Final count: 1 (baseline was 2; the rename-decision marker was resolved by
verifying all three Phase-4 rename facts in code).

| Page | Marker | Justification |
|---|---|---|
| accessibility.mdx | WCAG contrast values calculated, not audited (axe-core run pending) | Honest gap: no automated contrast check has run against the built site; the claim is already demoted to "calculated values" in prose. Closing it requires running an audit tool, out of docs scope. |

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
| tutorials/first-run-with-solmara-lab.mdx | pass-with-findings (harness-isolation entries only; every step passed verbatim, twice) | Fixed on page: curl prerequisite, compose project-name collision row, lead restructure, lab-replacement overclaim dropped, /docs-vs-openapi causal tightening. Product issues filed: solmara-lab#1 (stale Bruno example), #2 (project-name collision, down -v destroys colliding volumes), #3 (stale committed checksums). Owner's stack stopped/restarted around the run, health-checked (16 up, portal/home/relay 200). CI note: check:tutorial execute mode is not wired into any workflow (only dry-run); follow-up decision. |

## Deliberate deviations

- verify-opencrvs-claims.mdx links the OpenCRVS onboarding model with an absolute
  docs.registrystack.org URL instead of a relative path. The target page is
  excluded from archived docsets (exclude_docsets), so a relative link fails the
  archive link check; the absolute URL points every docset at the canonical
  current page. Same rationale family as keeping publishing-pipeline.mdx draft.

## Fresh-eyes review outcome

Three independent reviewers (trust path, reader path, contract path) ran
reviewing-docs-pages on the full branch diff. Contract path: zero P1. Trust
path: 3 P1s (cargo-deny path-filter overclaim introduced by the security batch;
"since v0.8.0" continuity; wrong admin scope string on two pages, pre-existing).
Reader path: 3 P1s (kbd vs MD033, already fixed; false distroless claim for
Notary; impossible DCI-env troubleshooting row). All six fixed on the branch and
re-verified; P2/P3 findings fixed or recorded above.

## Issues filed from divergence findings

| Issue | Page(s) | Finding |
|---|---|---|
| [GH#278](https://github.com/registrystack/registry-stack/issues/278) | publish-spreadsheet, verify-claim, run-notary-standalone | registryctl v0.8.4 pins pre-0.8.4 service image digests; generated Relay project cannot start |
| [GH#279](https://github.com/registrystack/registry-stack/issues/279) | first-run, getting-started-fhir, configure-dhis2 | lab `just setup` broken on fresh clones ($$ escaping); Notary warm-up 500s; zsh env sourcing; undeclared uv prerequisite |

## Editorial and visual review passes (2026-07-07, post-PR-open)

Two independent full-coverage review passes ran after PR #284 opened, at the maintainer's request.

**Implementer-tone pass** (audience fit, tone, economy; facts out of scope as already verified):
all 57 hand-authored site pages + 47 product doc sources + STANDARDS_ASSUMPTIONS.md read end to
end. Verdict: implementer-first overall; residue was the project's own quality process leaking
into prose (published reviewer annotations, decision-record citations, roadmap vocabulary,
self-narrated honesty, unglossed insider terms). 16 P1 + ~170 P2/P3 findings; all applied across
six fix batches except: (1) verify-opencrvs absolute onboarding URLs kept (recorded deliberate
deviation for the archive link check); (2) self-assessment "publicly inferable" sentence kept
unchanged because the prescribed rewrite would have dropped the security-reviewer-approval
carve-out (policy change, routed to Tier-C); (3) the github.com/jeremi OpenFn adaptor pointer
flagged for maintainer decision, not changed. New factual finds routed out: relay
security-assurance.md cited security/waivers.yml, corrected during PR follow-up
to point at exposure-manifest route waivers and the advisory baseline;
products/manifest/docs/repository-split.md deleted (internal split history).

**Diagram pass**: 13 of 20 site SVGs were orphans; 4 audited and re-wired (standards-claim-levels,
notary-three-parties [stale WITNESS name fixed], relay-two-rooms [feature-gate labels fixed]),
1 REJECTED with evidence (notary-disclosure-lens drew a fourth disclosure mode the docs deny),
9 retired. In-use fixes: evidence-transports pre-rename routes, claim-model connector/rule kinds
(+ page alt), country-evidence-mesh unanchored AI panel removed. New diagrams: solmara-lab-topology
(first-run tutorial), registry-relay-or-notary (when-to-use), registry-trust-boundaries
(threat-model, Tier-C deltas recorded), mermaid adapter chains on the FHIR and DHIS2 tutorials.
check-svg-a11y.mjs expected list realigned (13 in-use files). Dark-mode contrast issue filed as
registry-stack#291. Spec-page mermaid deliberately left as mermaid (drift-resistant).

## Codex PR-review follow-up (2026-07-07)

All four Codex P2 comments on PR #284 verified and confirmed valid. Root cause of two:
the pinned solmara-lab ref 1af06c8 declared top-level `name: solmara-lab` (shared Compose
project regardless of clone directory) and its `just down` ran `down -v`; solmara-lab
3698ea8 (fixes #1-#3) removes both hazards (per-checkout hashed project name; `down`
non-destructive; `reset` owns `down -v`). Fixes applied: SOLMARA_LAB_REF bumped to 3698ea8;
check-tutorial.sh clone mode now exports a unique COMPOSE_PROJECT_NAME, runs `just setup`,
and cleans up with `just reset` (caller-supplied checkouts get non-destructive `just down`);
tutorial Verify curl now requires exactly the four expected claim_ids satisfied (was
vacuously true on empty results); troubleshooting collision row and Cleanup section
rewritten for the new semantics (my original row misattributed the collision to directory
basenames). Execute mode re-run at the new pin from a fresh clone: PASS end to end
(log dist-check/tutorial-20260707T080930Z.log), reader stack stopped/restarted gracefully
around the run, no leftover containers/volumes.
