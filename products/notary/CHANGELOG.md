# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- BREAKING: Replace deployment-waiver `reason` with a required validated
  `reference` and an optional validated `summary`. Strict configuration parsing
  rejects the retired field. Restricted posture and boot warnings expose only
  the new metadata, default posture continues to omit waiver metadata, and
  hard startup/readiness gates remain non-waivable.

## [0.12.2] - 2026-07-20

- No new Notary product features or public API contract changes. This release
  fixes forward from the incomplete v0.12.1 publication with a canonical
  reproducible release-build path for binaries and runtime images.
- Isolated the single-use eSignet authorization-code exchange on short-lived
  DNS-pinned transport. Redirects and proxies remain denied, timeouts remain
  bounded, and the non-idempotent exchange is not transparently retried. No
  public route or authentication contract changed.

## [0.12.1] - 2026-07-20

### Security

- Bound time-bounded reviews of the three non-fixable Debian 13 `libc6`
  findings to the ordered runtime root filesystem layer digest. Fixable,
  expired, mismatched, and unreviewed findings fail the image advisory gate.

## [0.12.0] - 2026-07-19

### Added

- Added a complete source-tested registry-backed OID4VCI journey for EdDSA and
  ES256 issuer profiles with EdDSA `did:jwk` holder proof, exact generated
  metadata assertions, client verification, replay and provenance checks, and
  unsupported-profile denial.
- Added registryctl authoring for the issuer signing algorithm and transaction
  code mode. EdDSA and a required transaction code are secure defaults. An
  explicit no-PIN profile retains the 300-second compiler ceiling.
- Added the bounded batch evaluation v1 contract. Batch evaluation has an
  immutable 100-member platform ceiling with lower-only global and per-claim
  configuration, client and OpenAPI bounds, and pre-side-effect HTTP 413
  rejection using `batch.too_large`.
- Added the committed Draft 2020-12 Registry Notary runtime configuration
  schema at `schemas/registry-notary.config.schema.json`. `registry-notary
  schema`, `just config-schema-generate`, and the schema drift check all use
  the production `StandaloneRegistryNotaryConfig` deserialization graph.
  The operator reference now has a bidirectional key-path contract check.

### Changed

- BREAKING: the Registry Notary 1.0 wallet facade now supports only
  issuer-initiated pre-authorized code backed by a stored registry transaction.
  `GET /oid4vci/credential-offer` and `POST /oid4vci/nonce` are removed, and
  issuer metadata no longer advertises `nonce_endpoint`. Credential responses
  no longer expose `c_nonce` or `c_nonce_expires_in`.
  The Rust, Node.js, and Python client helpers for those removed routes are
  removed as well.
  Start at `GET /oid4vci/offer/start`, complete the identity-provider callback,
  redeem the rendered offer at `POST /oid4vci/token`, and use that token
  response's transaction-bound proof nonce. The identity provider's
  authorization code is internal to Notary and is not a wallet grant.
- Status-bearing credentials now require fail-closed client verification from
  the configured exact HTTPS status origin. The reserved top-level `status`
  claim cannot be selectively disclosable.
- OID4VCI remains limited to EdDSA or ES256 issuer signing and EdDSA `did:jwk`
  holder proof. No EUDI, HAIP, PAR, DPoP, wallet-attestation, ES256-holder, or
  external conformance claim is made without frozen candidate evidence.
- Maintained Notary runtime images now use Debian 13 distroless. Release checks
  enforce the expected base and vulnerability policy before publication.

## [0.11.0] - 2026-07-18

### Added

- Added `registry-notary audit quarantine` as an offline recovery path for an
  inconsistent file-backed audit chain. The command takes the existing
  single-writer lock, retains the corrupt chain under a timestamped suffix,
  and starts a keyed `audit.chain.break` segment linked to the last verified
  local record.
- Registry-backed Relay consultations can now bind bounded scalar inputs from
  `request.target.attributes.<stable-name>`. Notary preserves string, boolean,
  and integer types through single and batch evaluation and Relay requests.
  Target attributes remain caller-supplied context and cannot satisfy an
  authenticated target-identifier requirement for delegated subject access.

### Changed

- BREAKING: direct and OID4VCI credential issuance now accept only newly
  evaluated, non-delegated registry-backed claims with one exact compiler pin
  for every claim in each selected root's dependency closure and one normalized
  record per unique Relay execution. A deterministic SHA-256 binding now
  cross-checks every pin against its execution and claim provenance before
  signer access. Restricted Relay identifiers are retained only for evaluations
  whose selected roots share a validated credential profile. Source-free,
  delegated, and registry-backed evaluation-only claims cannot be
  configured for credential issuance. Existing stored evaluations remain
  readable and renderable but must be re-evaluated before issuance. No database
  migration or correctness-state schema change is required.
- BREAKING: configuration `${VAR}` expansion now rejects environment variables
  that are unset or empty. `${VAR:-fallback}` uses its fallback for either
  state, `${VAR:-}` explicitly expands to empty, and `${VAR:?message}` reports
  its message for either state. Whitespace-only values remain non-empty.
- Notary now verifies its retained audit chain during runtime activation.
  Confirmed chain forks and verification failures latch `/ready` at `503` with
  the bounded code `audit.chain.inconsistent` until offline recovery and a
  process restart. `/healthz` remains `200`; transient I/O, JSON, secret, and
  other operational failures do not permanently poison readiness. Governed
  signed-bundle acceptance remains write-before-persist and write-before-serve.
  Embedders must now await `standalone_router`; all router construction paths
  reject runtimes that have not attempted retained-chain verification.
- Omitted claim `formats` now defaults to the canonical
  `application/vnd.registry-notary.claim-result+json` evaluation response
  format. An explicitly empty `formats: []` is rejected at configuration load
  with the claim id and remediation. Explicit lists must include the canonical
  format and may otherwise contain only `application/ld+json; profile="cccev"`.
  SD-JWT VC is a credential-profile issuance format, not a claim evaluation
  renderer. Subject-access `allowed_formats` now follows the same evaluation
  boundary and no longer needs to repeat the credential profile's output
  format.
- Requests that present more than one primary credential channel now fail
  before candidate parsing or validation with `auth.multiple_credentials`.
  The public response and restricted audit record remain candidate-neutral and
  do not reveal which credential, if any, was valid.
- The registryctl local Notary tutorial now exercises a live registry-backed
  claim through an exact compiler-pinned Relay consultation. It is an
  evaluation-only tutorial and does not claim credential issuance, wallet
  interoperability, or OID4VCI interoperability.

## [0.10.0] - 2026-07-17

### Added

- Release distributions now publish `registry-notary-cel-worker` as a
  standalone Linux amd64 binary. CEL-enabled standalone installations keep it
  beside `registry-notary` under its canonical executable name; the Notary
  image carries the same isolated worker.

### Changed

- BREAKING: all deployable Notary correctness state now uses one typed,
  Notary-owned PostgreSQL state contract with separate private and API schemas,
  configured by the top-level `state` block.
  Removed Redis and per-domain storage configuration is rejected without
  aliases. Explicit single-process local development may use `in_memory`.
- BREAKING: authentication no longer uses a mode selector, and a present
  `auth.mode` is rejected. API keys may coexist with
  OIDC for distinct service and citizen or wallet callers, while each request
  must present exactly one credential type. Static bearer tokens and OIDC
  remain mutually exclusive because both use `Authorization: Bearer`.
- Project authoring now emits only PostgreSQL settings that identify a secret
  consumer or reflect an authored deployment choice. Connection-pool and
  timeout policy follow the Notary runtime defaults instead of becoming
  implementer-owned generated configuration.
- The embedded server activation API is now
  `NotaryRuntimeSnapshot::activate()`. The synchronous `standalone_router`
  helper is limited to explicit local in-memory state; PostgreSQL callers use
  the compile, activate, then build-router sequence. Router builders now name
  their exposure explicitly: `notary_public_router_from_runtime`,
  `notary_shared_router_from_runtime`, or `notary_routers_from_runtime` for
  separate public and admin listeners.
- Signed pre-authorized codes now bind the exact offer's transaction-code
  requirement. Restart or configuration changes cannot remove or add the PIN
  requirement for a live offer.
- Pre-authorized-code replay identity now uses the verified Notary issuer and
  stable Notary replay hashes. Redeemed no-PIN codes remain spent across
  sensitive-state key rotation, unrelated service configuration changes,
  process or database restart, and logical restore.
- PostgreSQL now derives effective credential status from database time, so
  skewed replicas agree on expiry. Revocation remains terminal, and credential
  expiry supersedes valid or suspended status.
- Added `registry-notary state install` and `registry-notary state doctor`,
  startup and readiness schema attestation, PostgreSQL 16 through 18 support,
  and active-active transaction semantics for replay, nonce, evaluation,
  idempotency, credential status, quotas, and preauthorization.
- Documented clean pre-1.0 cutover, backup and restore, stale-restore
  quarantine, forward upgrades, sensitive-state key handling, and the
  local-to-production implementer journey.
- BREAKING: Registry-backed claims now use only authenticated,
  compiler-pinned Registry Relay consultations. Notary no longer accepts
  direct source connections, DCI/FHIR connectors, source adapter sidecars,
  source credentials, or transitional evidence modes.
- Notary validates the complete Relay consultation semantics and
  `contract_hash` before serving and at readiness. A mismatch fails before
  Relay can access the registry source.
- Relay outcomes and typed outputs remain separate from Notary claims,
  disclosure, and credential issuance. One consultation can supply several
  direct and CEL claims without exposing raw Relay errors.
- Relay-only, self-attested Notary-only, and combined deployments are modeled
  independently. Combined deployments use the project's single Relay
  connection.
- BREAKING: a combined deployment may connect Notary to its paired Relay
  through an explicitly enabled HTTP IP-loopback origin in any deployment
  profile. The obsolete `notary.relay.insecure_url` posture finding is removed;
  remote HTTP Relay origins remain invalid, so no cleartext hop crosses the
  shared network namespace.
- Project authoring keeps the Relay's public catalog origin separate from the
  Notary-to-Relay connection URL. Only the paired internal connection may use
  an explicitly enabled literal IP-loopback HTTP origin; public or remote
  Relay origins still require HTTPS.
- BREAKING: registry-backed claim rules are now named
  `consultation_output { consultation, output }` and
  `consultation_matched { consultation }`. The unreleased `extract`/`exists`
  and `source`/`field` forms are rejected without aliases.
- BREAKING: public claim provenance is now
  `registry-notary-claim-provenance/v2` with one
  `relay_consultation_count`; the misleading `source_count` and unused
  `source_versions` fields are removed. Audit records use the same Relay
  consultation terminology.
- BREAKING: federation configuration uses `evaluation_scopes` and
  `max_claim_result_age_seconds`, and signed federation responses use
  `claim_result_issued_at` plus `federation.stale_claim_result`. Federation
  profiles remain source-free in this version.

### Removed

- Removed production Notary Redis code, dependencies, configuration, and
  current operator documentation. The standalone Solmara Lab consumes the new
  PostgreSQL state contract in its owning repository.
- Removed the Notary source-adapter sidecar image, routes, security inventory,
  direct DCI/FHIR/OpenSPP demo configurations, OpenFn caller demo, and the
  direct-source performance harness.

## [0.9.0] - 2026-07-10

### Added

- New deployment gate `notary.signer_custody.unapproved`: keys used by
  credential issuance, access-token issuance, or federation signing require
  explicit `deployment.evidence.signer_custody_approved: true` under
  `production` and `evidence_grade`. Provider kind, including `pkcs11`, is not
  treated as proof because PKCS#11 modules may be hardware- or software-backed.
  The gate is unbound for `local` and `hosted_lab`, reports `readiness_fail`
  under `production`, and blocks startup under `evidence_grade`. `/ready` now
  exposes typed custody-specific provider and surface counts without publishing
  the deployment profile, complete finding list, or secret-bearing provider
  fields.
- `registry-notary doctor` now warns (`notary.source_binding.no_matching_policy`)
  when a claim source binding declares no matching policy (no `policy_id`, no
  context constraints), naming each affected binding. A matching new
  deployment gate surfaces the same condition as a `finding_warn` under
  `production` and a `finding_error` under `evidence_grade`; `hosted_lab` and
  `local` stay quiet. Claim resolution behavior is unchanged: such bindings
  already fell back to unrestricted, identifier-only resolution per spec
  RS-DM-CLAIM; this only adds visibility so operators can accept that
  knowingly or declare a matching policy.
- New deployment gate `notary.audit.retention_local_only`: fires when the
  audit sink is `file` or `jsonl` and `deployment.evidence.audit_offhost_shipping`
  is not declared, because a local file sink caps retention and an attacker
  with host access can destroy the evidence. `stdout` and `syslog` sinks are
  exempt. Bound `finding_warn` under `production` and `startup_fail` under
  `evidence_grade`; unbound under `local` and `hosted_lab`. Operators can
  clear the finding by declaring `deployment.evidence.audit_offhost_shipping:
  true` once audit events are shipped off-host. `startup_fail` is a hard gate
  and hard gates cannot be waived: a config carrying a `deployment.waivers`
  entry for this finding under `evidence_grade` now fails to load
  (`HardGateNotWaivable`). Migration: remove the waiver, then either ship
  audit events off-host and declare
  `deployment.evidence.audit_offhost_shipping: true`, or switch to a
  `stdout`/`syslog` sink to clear the local-retention gate. An
  `evidence_grade` deployment must also configure
  `deployment.evidence.audit_ack_cursor_path` for every sink type.
- `registry-notary doctor`'s JSON report
  (`registry.config.diagnostic_report.v1`) now carries an `audit_shipping`
  object (`sink_type`, `shipping_target_configured`, `shipping_target`) when
  the config parses, mirroring the posture `audit` shipping fields. The
  existing "audit file/jsonl sink is local-chain-only" warning now fires only
  when off-host shipping has not been declared.
- Added `evidence.machine_quota`, a per-principal quota for machine
  `evaluate` and `batch_evaluate` traffic. The budget is counted in subjects
  (a single evaluate costs 1, a batch costs `items.len()`) over a fixed
  one-minute window per `principal_id`, so request rate and batch fan-out
  share one limit instead of being controlled independently. Exhaustion
  returns `429` with the stable code `evaluation.quota_exceeded` and a
  `Retry-After` header. Disabled by default (`enabled: false`); enabling it
  does not affect the existing self-attestation rate limiters or the
  per-request `max_subjects` cap.
- `deployment.evidence.audit_ack_cursor_path` and
  `deployment.evidence.audit_ack_max_age_secs` config fields: point Notary at
  the local state file an off-host audit shipper writes on each successful
  hand-off (`registry.audit.ack_cursor.v1`), and set how old the cursor's
  `acked_at` timestamp may get before it reads as stale (defaults to 900s).
  Config load rejects `audit_ack_max_age_secs` set without
  `audit_ack_cursor_path` (`AuditAckMaxAgeWithoutCursor`), and rejects
  `audit_ack_cursor_path` set on a local file audit sink that has not
  declared `audit_offhost_shipping` (`AuditAckCursorWithoutShippingDeclared`);
  a `stdout`/`syslog` sink may carry a cursor without that declaration.
- Two new deployment gates read the ack cursor's observed health:
  `notary.audit.shipping_unverified` (a shipping target is configured but no
  ack cursor is configured; `finding_warn` under `production`,
  `startup_fail` under `evidence_grade`, unbound under `hosted_lab`) and
  `notary.audit.shipping_stale` (a cursor is configured but its observed
  health is not `ok`, including a watermark that differs from the live keyed
  chain tail; `finding_error` under `production`, `readiness_fail`
  (non-waivable) under `evidence_grade`, unbound under `hosted_lab`).
- Notary readiness and posture re-evaluate audit shipping gates on each request,
  so a fresh ack cursor that becomes stale after startup now makes an
  `evidence_grade` instance not ready without requiring a restart.
- Runtime cursor reads use one blocking worker with a 500 ms deadline. A slow
  or stalled cursor filesystem fails readiness without blocking async request
  workers or accumulating additional blocked cursor readers. The cursor must
  be a regular file of at most 16 KiB and must be replaced atomically by the
  shipper.
- `registry-notary doctor`'s `audit_shipping` object and the admin
  `GET /admin/v1/posture` `posture.audit` block both gain `shipping_health`
  (`ok`, `stale`, `missing`, `invalid`, `unverified`, or `null`) and
  `shipping_observed_at` (an RFC3339 timestamp, or `null`), the observed
  freshness of off-host audit shipping read from the ack cursor. Both are
  `null` whenever `shipping_target_configured` is `false`. Runtime `ok`
  requires a fresh cursor bound to the current keyed chain tail; offline doctor
  output remains `unverified`. Tail equality establishes a zero local backlog
  for the trusted shipper's claim, not cryptographic proof of remote receipt.
  The committed OpenAPI example for `GET /admin/v1/posture`
  is regenerated to include both fields.
- A signed-bundle boot writes `config.bundle_accepted` before the service begins
  serving. Evidence-grade readiness remains `503` until the independent shipper
  acknowledges that new tail. Offline `registry-notary doctor` cannot perform
  live tail binding, so a fresh cursor remains `unverified` and the offline
  evidence-grade check reports the hard shipping gate.

### Changed

- **BREAKING: `deployment.profile` is required.** Set it explicitly to one of
  `local`, `hosted_lab`, `production`, or `evidence_grade`. Notary does not
  infer a profile and refuses startup when it is absent.
- **BREAKING: the TUF-era live config-apply HTTP surface is removed.**
  `/admin/v1/config/verify`, `/admin/v1/config/dry-run`, and
  `/admin/v1/config/apply` are no longer served, and the CLI
  `config apply-bundle` command is removed. First run
  `registryctl bundle verify` for stateless signature and binding verification,
  then place the signed Registry Config Bundle v1 on the Notary node. For a
  genuinely absent, version-specific antirollback state path, start Notary with
  `--initialize-state`; that boot verifies the bundle and initializes state.
  Notary's read-only `config verify-bundle` command remains, but it requires
  accepted state to exist, so use it only for later candidate validation and
  restarts. Replace retired TUF-era fields inside `config_trust` with current
  Config Bundle v1 trust fields because strict parsing rejects the old schema.
  There is no current hot-apply path. Back up the durable
  `config_trust.antirollback_state_path` state before upgrading and keep
  release-specific restore sets. A rollback must restore the state belonging
  to that release; never delete or reinitialize antirollback state to force an
  older bundle to load.
- **BREAKING: source-adapter sidecar configuration rejects unknown keys.**
  Remove misspelled, retired, or wrapper-only fields before upgrading instead
  of relying on them to be ignored.
- Production and evidence-grade operators must review custody for credential,
  access-token, and federation signing roles. Set
  `deployment.evidence.signer_custody_approved: true` only when retained review
  evidence supports the approval; it is an attestation, not a gate bypass.
- **BREAKING: claim configuration is now validated at load time (#170).**
  Startup rejects a duplicate claim `id` (REQ-DM-CLAIM-001), a
  `disclosure.default` outside the claim's allowed disclosure set
  (REQ-DM-CLAIM-008), and an `extract`/`exists` rule whose `source` does not
  name a declared source binding (REQ-DM-CLAIM-006), with an error naming the
  offending claim and field. Configurations that previously loaded with one
  of these inconsistencies fail to load until corrected; behavior for
  consistent configurations is unchanged.
- `extract` and `exists` rule results are now checked against the claim's
  declared `value.type` at evaluation time (REQ-DM-CLAIM-009), the same
  enforcement CEL rules already had. A source value that does not conform
  fails that claim's evaluation instead of flowing into disclosure and
  credential issuance; claims with `value.type: unknown` (or no declared
  type) are exempt.
- The `file` audit sink now takes a process-lifetime advisory single-writer
  lock on `<path>.lock`, and each append verifies the on-disk tail before
  writing. A second Notary process pointed at the same audit file fails at
  startup instead of silently interleaving writes and forking the hash
  chain, and a write that would extend a diverged chain fails closed.

### Fixed

- Federation denials after request-signature verification now retain the
  redacted peer, source-scope, profile, purpose, request-JTI, claim, and
  subject-reference audit context already available at the denial point.
  Federation response-signing failures retain the same context. Raw peer ids,
  request JTIs, and subject identifiers do not enter audit records.

## [0.8.4] - 2026-07-04

### Fixed

- Corrected the `GET /admin/v1/posture` OpenAPI example to include the
  `deployment` and `audit` sections that the live default-tier posture
  document already returns.

### Changed

- **BREAKING: credential profiles now default to holder binding.** When
  `holder_binding` is omitted, Registry Notary defaults to `mode: did` with
  `allowed_did_methods: [did:jwk]`, so direct SD-JWT VC issuance requires a
  holder DID before it can mint a credential. Deployments that intentionally
  issue unbound, bearer-style credentials must set `holder_binding.mode: none`
  explicitly; `registry-notary doctor` now warns on those profiles.
- Renamed the binary package from `registry-notary-bin` to `registry-notary`
  so the Cargo package, executable, release artifact, and visible version output
  use the same user-facing command name.
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
