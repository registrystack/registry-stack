# 1.0 Release Readiness

This document tracks the evidence that Registry Relay and Registry Notary are
ready for a stable release. "Stable" means both semver API stability
commitments and a production security posture suitable for government
deployments that self-host the stack.

An item is complete when its evidence link exists and has been reviewed, not
when the underlying work merges. Evidence is a link: a doc in this repository,
a CI run, a published report, or a closed issue.

If work on any item surfaces a suspected vulnerability, report it through
[`SECURITY.md`](../SECURITY.md). Never post suspected-vulnerability details on
a public issue or PR.

## 1. First-run experience

What a domain expert does in their first hour. Broken quickstarts end
evaluations early.

- [ ] Quickstart and both tutorials verified end to end on the current
      release by a fresh reader using only published docs and release assets.
- [ ] Release binaries self-report the release version.

## 2. Threat models

Maintainer work; not delegated. One threat model per product covering assets,
trust boundaries, and the guarantees each product claims against a hostile
client, plus where those guarantees could leak (logs, error messages, audit
records, caches, timing).

- [ ] Relay threat model written and reviewed.
- [ ] Notary threat model written and reviewed.
- [ ] Attack checklist derived from the threat models (drives section 4).

## 3. Standards conformance

Every standard the docs claim must carry evidence: a conformance suite run,
published test vectors passing, or interop with an implementation we did not
write.

- [x] Inventory of standards and specification claims across docs and specs.
      Evidence: [`standards-claims-inventory.md`](notes/standards-claims-inventory.md).
- [ ] Per-claim evidence recorded (conformance run, test vectors, or interop).
- [ ] OpenID conformance suite running repeatably against a supported
      deployment topology (#205). Must not depend on the monorepo `lab/`,
      which is being replaced by a standalone lab repository (#224). Initial
      harness and metadata-run evidence:
      [`openid-conformance-suite.md`](../lab/docs/openid-conformance-suite.md),
      [`openid-conformance-initial-report.md`](../lab/docs/openid-conformance-initial-report.md).
- [ ] Credentialing, OID4VCI, and status-list interop proof (#57).

## 4. Adversarial verification

Tests written alongside generated code confirm the implementation; this
section is about challenging it.

- [ ] Maintainer adversarial review of the load-bearing crates:
      `registry-platform-pdp`, `registry-platform-sdjwt`,
      `registry-platform-crypto`, `registry-platform-authcommon`, Relay scope
      enforcement, Notary disclosure policy evaluation. `registry-platform-sts`
      is parked outside the workspace until a consumer is promoted (#298).
- [ ] Negative-path test coverage mapped against the attack checklist;
      gaps closed with tests that assert denial and correct audit records.
      Mapping evidence: [`negative-path-coverage-map.md`](notes/negative-path-coverage-map.md).
- [ ] cargo-fuzz targets for manifest and artifact parsers (#26).
- [ ] cargo-fuzz targets for token, credential, and sidecar parse boundaries.
- [ ] Data-minimization leak review across logs, error paths, audit records,
      and caches (maintainer work; #176 is the known open case).

## 5. Independent security audit

Deferred until the self-review above is complete, so audit time is spent on
what we could not find ourselves.

- [ ] Audit scope defined (crypto and auth surfaces at minimum).
- [ ] Audit firm engaged; report received and findings resolved or accepted.

## 6. Supply chain and provenance

Release assets are already cosign-signed with SLSA provenance
([`VERIFY.md`](VERIFY.md)) and repeatable-build evidence exists
([`REPEATABLE-BUILDS.md`](REPEATABLE-BUILDS.md)); open tracking issues:
GH#122, GH#123, GH#127, GH#128, GH#129.

- [x] SBOM published per release. Evidence:
      [release workflow](../.github/workflows/release.yml) publishes
      digest-bound SPDX SBOMs for release binaries, image-input binaries
      including the Notary PKCS#11 variant, and images on the next tag release.
- [x] Unsafe-code inventory generated and reviewed. Evidence:
      [`unsafe-code-inventory.md`](notes/unsafe-code-inventory.md).
- [x] Dependency vetting policy documented. Evidence:
      [`dependency-vetting-policy.md`](notes/dependency-vetting-policy.md).
- [x] Crosswalk pinned-dependency rationale and review trigger documented in
      `external/`. Evidence: [`external/README.md`](../external/README.md).

## 7. Operations and lifecycle

What 1.0 promises the institutions that run this.

- [ ] API stability and semver policy published.
- [ ] Deprecation policy published.
- [ ] Security support window published.
- [ ] Upgrade and rollback documented and partially exercised. Evidence:
      [exercised run v0.8.3 -> v0.8.4 -> v0.8.3](exercises/upgrade-v0.8.3-to-v0.8.4.md)
      (#203; exercises the draft operate/upgrade-and-rollback page with
      source-built release-tag images; release-artifact verification,
      credential issuance, metrics, Redis replay/nonce survival, and
      anti-rollback monotonic rejection remain outside this run). Backup and
      restore guidance for generated and single-node deployments is documented
      in [`backup-and-restore.mdx`](../docs/site/src/content/docs/operate/backup-and-restore.mdx)
      (#226). The
      [v0.8.4 -> v0.9.0 -> v0.8.4 procedure](exercises/upgrade-v0.8.4-to-v0.9.0.md)
      records the beta-11 migration and rollback gate; it does not claim a
      successful run until finalized-source and published-asset evidence are
      added.
- [ ] Single-node Compose deployment behind an institution-owned reverse proxy,
      IAM, and front rate limiter documented. Evidence:
      [`single-node-compose-behind-proxy.mdx`](../docs/site/src/content/docs/operate/single-node-compose-behind-proxy.mdx)
      (#13). Kubernetes and high-availability profiles remain outside the 1.0
      deployment profile.
- [ ] Security-relevant configuration defaults inventoried and reviewed for
      secure-by-default (#172 and #171 are known open questions). Inventory
      evidence: [`security-config-defaults.md`](notes/security-config-defaults.md);
      review decisions remain open.
- [ ] DoS posture decided: rate-limit backstops (#78, #51) triaged as
      1.0-blocking or explicitly deferred with rationale.
- [ ] Vulnerability disclosure flow behind `SECURITY.md` tested end to end.

## 8. Data protection posture

Notary's pitch is minimization; it will be held to it.

- [ ] Behavioral guarantee claims extracted from the docs site and verified
      against implementation. Extraction evidence:
      [`behavioral-guarantee-claims.md`](notes/behavioral-guarantee-claims.md);
      implementation verification remains open.
- [ ] Audit log and error path review confirms minimized data never appears
      (overlaps section 4 leak review).
- [x] Retention behavior documented. Evidence:
      [retention-and-persistent-state.mdx](../docs/site/src/content/docs/operate/retention-and-persistent-state.mdx).
- [ ] DPI safeguards mapping current; GDPR alignment notes published.
