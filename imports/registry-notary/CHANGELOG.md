# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING: removed OpenFn sidecar naming from the current source-adapter
  path.** Claim provenance, config connector values, batch-mode values,
  examples, Dockerfile naming, metrics, security inventories, and operator docs
  now use `source_adapter_sidecar` naming instead of the retired OpenFn sidecar
  name. Operators must update Notary YAML from `connector: openfn_sidecar` to
  `connector: source_adapter_sidecar`, update sidecar batch connections from
  `bulk_mode: openfn_sidecar_batch` to
  `bulk_mode: source_adapter_sidecar_batch`, rebuild any dashboards or alerts that use the
  old `registry_notary_openfn_sidecar_*` Prometheus metric names, re-render and
  re-sign governed runtime targets with the
  `registry.notary.source_adapter_sidecar.runtime.v1` schema id, and update
  deployment environment variables such as
  `REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_CONFIG`.
- **BREAKING: removed the ignored source-adapter sidecar `--jobs-root` CLI
  flag.** Built-in adapter manifests are self-contained; wrappers that still
  pass `--jobs-root` must drop it.

## [0.6.2] - 2026-06-22

### Fixed

- **Federated evaluation policy context compatibility**: federation evaluation
  profiles now pass legal basis, consent, jurisdiction, and assurance context to
  source matching without presenting that context as a per-transaction
  authorization scope. This fixes beta-4 lab delegated federation evaluations
  that depend on governed source-policy gates.

## [0.6.1] - 2026-06-22

### Fixed

- **Static credential policy context compatibility**: static credentials can
  again carry configured legal basis, consent, jurisdiction, and assurance
  context for source matching PDP gates without being treated as exact
  per-transaction authorization scopes. OIDC/RAR authorization details remain
  fail-closed unless they include transaction scope fields.

## [0.5.0] - 2026-06-21

### Added

- **Dependent source lookups for civil-registration evidence packs**: claim
  evaluation can precompute source lookup dependencies needed by the OpenCRVS
  certificate evidence path.
- **OpenCRVS Notary onboarding documentation**: operator-facing guidance now
  covers the standalone OpenCRVS DCI claim path used by the beta-3 tutorials.
- **Built-in DHIS2 health-programme and civil source-adapter examples**: the
  source-adapter sidecar gains `http_json` manifests
  (`examples/dhis2-health-sidecar.yaml`, `examples/civil-http-json-sidecar.yaml`)
  that reproduce the retired OpenFn DHIS2 health and civil jobs through the
  built-in engine plus CEL collection macros, a live DHIS2 health canary
  (`scripts/smoke-http-json-dhis2-health-sidecar.sh`), and a parity gate note
  (`docs/dhis2-health-parity.md`).

### Changed

- **Crosswalk input alignment**: advanced the Crosswalk input to the `0.2.0`
  release ref used by the beta-3 train.
- **Platform input alignment**: advanced the Registry Platform input to the
  `0.3.1` release ref used by the beta-3 train.

### Removed

- **BREAKING: retired the `engine: openfn` source-adapter execution engine.**
  The source-adapter sidecar no longer runs the pinned OpenFn Node worker pool.
  All sources now run through the built-in `http_json`, `http_flow`, and `fhir`
  engines. Removed the manifest `openfn`, `worker`, `jobs_root`, and per-source
  `workflow` fields (and their governed-target schema fields), the OpenFn
  worker-pool lifecycle and version-pin/expression-hash checks, the
  `config print-expression-hashes` CLI subcommand (and the `--jobs-root` flag is
  now accepted for compatibility but ignored), the Node worker assets and
  OpenFn smoke scripts, and the `OpenFn DHIS2 Canary` workflow. The sidecar
  image (`Dockerfile.openfn-sidecar`) is now a pure-Rust distroless image; its
  filename and built image name/tag conventions, the `openfn_sidecar` Notary
  source-connector name, and the `registry_notary_openfn_sidecar_*` metric
  prefix are intentionally kept stable this round (a cosmetic rename is a
  deferred follow-up). The OpenFn-as-caller integration
  (`demo/openfn-notary-caller/`, `docs/openfn-notary-caller-guide.md`, and the
  `@registry/notary-openfn` caller adaptor) is unchanged and still supported.

  GOVERNED-CONFIG IMPACT: dropping the `openfn`/`worker`/`jobs_root` fields
  changes the governed runtime target's field set, so its `config_hash` changes
  even though the target schema id is unchanged. Deploying this version requires
  a coordinated governed-config apply: re-render and re-sign the runtime target,
  and update the `expected_sidecar.config_hash` that Notary pins for each
  source connection, before rollout.

### Security

- **Hardened security checks**: tightened token replay handling, forwarded-host
  trust, and approval-reference checks.
- **Gated sidecar metrics**: gated source-adapter sidecar metrics behind optional
  bearer-token auth.
- **Egress-hardening guidance**: tightened OpenFn egress-hardening guidance while
  the integration remains available as a caller-side path.

## [0.4.0] - 2026-06-13

### Added

- **Deployment profile gates and audit assurance posture** (#205–#209, PR #218):
  profile-aware startup and readiness gates with expiring waivers, plus deployment
  and audit-assurance posture blocks. A `doctor` command reports gate status (PR #219).
- **SD-JWT VC compatibility conformance harness** (#10, PR #218): fixture-driven
  verifier conformance suite with stable verification error codes.
- **Explicit credential verifier** (#77, PRs #215, #216): standalone SD-JWT VC
  verifier with stable error codes; accepts credentials issued without
  selective-disclosure arrays.
- **Parser fuzz regression coverage and authentication hardening** (#132, #173,
  #175, #177, PR #213).
- **Durable break-glass approvals** (#221, PR #223): emergency approvals backed by
  a durable multi-approver store; the default tier emits a `configuration.emergency`
  posture block carrying no reason or identity material.
- **Zero-trust source adapter sidecar** (PR #227): out-of-process source adapter with
  hardened egress, including SSRF and cloud-metadata (IMDS, including IPv6
  `fd00:ec2::254`) blocking and a bounded per-source LRU cache (PR #232).
- **`http_flow` sidecar engine** (PR #228): declarative HTTP flow engine with `when`
  guards, nullable flow bindings, default 404 not-found behavior, and explicit
  `on_status` actions.
- **Transaction-token enforcement** (PR #233): per-evaluation transaction-token
  authorization-details parsing and enforcement across core and server paths;
  rejects scope broadening against targetless self-attestation bodies before source
  reads, enforces `jti` replay protection and subject-binding, and fails closed on
  `cnf` tokens pending sender-proof validation. Supports Assisted Access proving a
  user-authorized claim without exposing raw eSignet tokens.

### Changed

- **Relationships scoped by purpose** (#92, PR #214): relationship resolution now
  honors the declared purpose.

### Fixed

- **Release tag ancestry check** (PRs #234, #235, #238): compare release tags against
  the protected `main` SHA before publishing.
- **Doctor gate alignment** (PRs #234, #235, #238): align `doctor` deployment gates
  with runtime behavior and make readiness gates non-waivable.
- **Source provenance and workflow integrations** (PRs #234, #235, #238): carry source
  runtime provenance through derived claims; honor OpenFn native workflow batches;
  apply published config with antirollback accept; resolve bundled approval
  integration.

### Security

- **SD-JWT holder-proof challenge binding** (PRs #234, #235, #238): bind SD-JWT holder
  proofs to the verifier key-binding challenge.
- **Workflow credential hardening** (PRs #234, #235, #238): isolate container OIDC from
  pull-request workflows, enforce workflow security hardening, drop persisted
  credentials in the fuzz workflow, and modernize gitleaks allowlists.

## [0.3.0] - 2026-06-12

### Added

- **Image signing and supply-chain hardening** (#121/#95, PR #183): release images are
  signed via Cosign; published image aliases and signatures verified in CI;
  stable and snapshot image channels defined (#124).
- **Binary release workflow** (#123): automated binary build and release pipeline.
- **OID4VCI pre-authorized-code flow** (PRs #98–#101, #107–#111): pre-auth config,
  token-signing and rate-limit primitives; pre-auth endpoints and self-issuance trust
  anchor; issuer metadata and OpenAPI docs; eSignet userinfo subject-binding resolution;
  RS256 eSignet RP client-assertion key support; wallet display metadata; optional
  preauth `tx_code`; eSignet `userinfo` without `exp` accepted.
- **SD-JWT VC Type Metadata** (PRs #93–#94): served at `/.well-known/vct` and
  VCT URL paths; CCCEV evidence type metadata exposed.
- **source-adapter sidecar** (PRs #102, #150–#152, #159): batch matching; governed assurance
  with antirollback; idempotent antirollback restarts; scalable batch controls;
  Notary sidecar adaptor and perf smoke.
- **Registry Notary client SDK** (#73): client SDK with documented API.
- **Governed configuration apply and signing rotation** (#129, PRs #141–#144):
  admin surface aligned; remote TUF apply config capabilities; credential rotation support.
- **Atomic runtime governed-config snapshot** (#133, PR #186): governed apply now
  publishes the runtime snapshot atomically from the locked base.
- **Notary Trust Ops posture endpoint** (#125): posture endpoint with shared tier filter.
- **Perf threshold gate** (#160, PR #184): CI now enforces notary perf thresholds;
  aiohttp perf harness upgraded to 3.14.1 (PR #191, clears Dependabot moderates).
- **OpenAPI contract gate** (#163, PR #185): committed OpenAPI artifact checked in;
  CI rejects divergence between generated and committed spec; breaking-change diff
  against base ref available via `OPENAPI_CONTRACT_BASE_REF`.
- **Remote TUF config source operator allowlist, fail-closed** (#172, PR #193):
  remote TUF sources are constrained to an explicit operator allowlist; requests
  for unlisted sources are rejected.
- **Claim provenance and `on_behalf_of` contracts frozen for beta** (#182).
- **OpenSPP and OpenCRVS credential support** (#83, #87): stabilized client contract;
  attribute credential queries.
- **Evidence request subject model** (#85).
- **Hosted lab product image support** (#89).
- **PKCS#11 signing production-ready** (#113): CEL production runtime hardened (#115);
  CEL worker boundary packaged (#116); published as single CEL PKCS#11 image (#120).
- **Security assurance gates** (#96, #104): Grype advisory ratchet gates scoped by
  image subject; reviewed advisory baselines.
- **Signing key providers** (#61).

### Changed

- **Admin listener split topology** (#143): Notary admin listener separated from
  public surface.
- **Renamed cel-mapping to crosswalk** (#168): all internal references updated.
- **Userinfo subject binding** (#147): `userinfo` subject-binding claims requested
  in preauth redirects.
- **OpenAPI auth surface aligned** (#146): auth declarations consistent across routes.
- **Admin route security declarations** (#174, PR #190): explicit per-route security
  declared on all admin routes in the frozen OpenAPI contract.
- **VCT wildcard catch-all semantics** (#166): machine-visible in spec and check.
- **Bare VCT routes frozen as deliberate exceptions** (#167): protocol rationale
  documented.
- **Dependency: aiohttp bumped to 3.14.1** (PR #191): clears Dependabot moderate
  advisories in the perf harness lockfile.
- Documentation overhaul (#158): persona-routed information architecture; admin API
  client matrix corrected; release-readiness diagrams added.

### Fixed

- **file_watch signing provider SHA-256 content identity** (#130, PR #192):
  same-mtime key-file replacement now detected via content hash; provider no longer
  misses key rotations when mtime is unchanged.
- **Rejected governed applies recorded in posture** (#136, PR #194): rejected
  apply outcomes are now persisted to the posture store.
- **Notary consistency surfaces** (#153): request IDs injected at early boundary;
  sidecar accept loop hardened; API key header canonicalized; discovery API key
  header canonicalized; problem details returned for readiness failures; HTTP
  duration histogram emitted; request IDs minted server-side; metrics read scope
  enforced and labels aligned; notary OIDC config canonicalized.
- **Nonce throttling and credential validity edge cases** (#157): OID4VCI nonce
  issuance throttled on public surface; overflowing credential validity rejected;
  spoofable forwarding headers ignored for public throttles.
- **OpenAPI nullable syntax** (#157): OpenAPI 3.1 `nullable` syntax corrected in
  claim result schemas.
- **CEL startup preflight** (#119): date helpers allowed in startup preflight.
- **Governed posture config polish** (#138): `previous_config` hash normalization
  (#137); JWKS discovery made public (#165); governed auth changes validated (#149).
- **Beta security blockers** (#78): auth handling hardened (#72); metrics endpoint
  hardened (#79).
- **zlib1g CVE-2023-45853** (#122): reclassified as false positive in Grype advisory
  baseline.
- **eSignet id_token without `typ` header** (#105): accepted in pre-auth callback.
- **CI lockfile and drift** (various): crosswalk lock refreshed; CI test tooling
  aligned; lockfile graph restored.

### Security

- **Admin route security declarations** (#174, PR #190): all admin API routes in the
  frozen OpenAPI contract now carry explicit security declarations, preventing
  unauthenticated access through missing auth annotations.
- **Remote TUF allowlist, fail-closed** (#172): operator allowlist gates remote TUF
  config sources; missing allowlist entry is a hard rejection, not a fallback.
- **Reject overflowing credential validity** (#157): prevents crafted validity windows
  from bypassing expiry enforcement.
- **Ignore spoofable forwarding headers for public throttles** (#157): `X-Forwarded-For`
  and similar headers no longer influence rate-limit key derivation on the public
  surface.
- **Wildcard allowlist segment boundaries enforced** (#149): CEL frame limit aligned.
- **Cross-origin redirect stripping** (#149): SDK auth stripped on cross-origin
  redirects; body headers dropped on converted redirects.
- **Governed auth change validation** (#149): mixed governed auth changes rejected.

## [0.2.1]

See [release tag v0.2.1](https://github.com/jeremi/registry-notary/releases/tag/v0.2.1).

## [0.2.0]

See [release tag v0.2.0](https://github.com/jeremi/registry-notary/releases/tag/v0.2.0).
