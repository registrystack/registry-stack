# Upgrade and rollback: v0.10.0 -> v0.11.0 -> v0.10.0

Status: published-asset verification completed on 2026-07-18. The complete
stateful upgrade, audit-recovery, and rollback procedure has not been executed,
so release acceptance and manifest closeout remain held. The immutable
published assets passed the integrity and developer-journey checks recorded
below; those checks do not replace the remaining deployment exercise.

## Purpose

Prove that an operator can apply the beta-13 issuance, authentication,
configuration, and audit-recovery changes without crossing product trust
boundaries, and can restore the complete v0.10.0 deployment if rollback is
required.

This procedure does not claim a stable upgrade contract. Rollback restores
version-matched software, configuration, databases, audit evidence,
anti-rollback state, and key-lifecycle records. It never starts a v0.10.0
binary against state changed by v0.11.0 traffic unless a product-specific
attestation proves the state contract and recovery point are safe.

## Fixed inputs

- Baseline source and images: annotated tag `v0.10.0` and its immutable image
  digests.
- Candidate source: the finalized beta-13 manifest source ref.
- Candidate images: source-built before tagging, then the immutable digests
  published by the `v0.11.0` tag workflow for the post-tag pass.
- Crosswalk: `1d44ec735fdc8a7c719264b339574371e8330337`.
- Topology: one Relay, one paired Notary, separate product-owned PostgreSQL
  databases, and one generated project using the matching registryctl image
  lock.

Record exact refs, image ids or digests, database versions, registryctl and
image-lock versions, orchestration version, host architecture, and timestamps.
Do not use `latest` or another mutable reference.

## Back up before upgrade

1. Remove issuance and evaluation callers from traffic and stop every v0.10.0
   Relay and Notary writer.
2. Back up each complete PostgreSQL database, product configuration, signed
   bundles, source and project files, secret references, audit files and
   shipping cursors, anti-rollback state, signer references, Relay keyring
   lifecycle inputs, and Notary sensitive-state key version.
3. Record hashes, ownership, permissions, schema fingerprints, and the last
   acknowledged audit watermark without printing secrets or subject data.
4. Keep the v0.10.0 restore set immutable and separate from v0.11.0 state.
5. Record baseline liveness, readiness, one allowed and denied Relay request,
   one evaluation, one direct issuance when enabled, and one duplicate replay
   rejection.

## Prepare v0.11.0 configuration

1. Install registryctl v0.11.0 with the exact
   `registryctl-v0.11.0-image-lock.json`. Regenerate the project and run its
   offline fixture tests, authoring check, and build. Confirm the five public
   starters remain HTTP, DHIS2 Tracker, OpenCRVS DCI, FHIR R4, and exact
   snapshot.
2. Remove every source-free, self-attested, delegated, or evaluation-only
   claim from credential profiles. Credential issuance must select only
   non-delegated registry-backed claims whose complete dependency closure is
   compiler-pinned to exact Relay consultations.
3. Review each Relay Script diagnostic. Unknown host calls and unsupported
   arities are authoring failures, not runtime fallbacks. Confirm diagnostics
   contain locations and valid signatures but no authored argument values.
4. Update empty environment-variable handling. An unset or empty `${VAR}` now
   fails; use `${VAR:-fallback}` or an intentionally empty `${VAR:-}` only
   where the consuming field permits it.
5. Update callers to send exactly one primary credential channel. Remove any
   logic that simultaneously sends `Authorization` and `x-api-key` or expects
   fallback from one to the other.
6. Validate Relay configuration against the committed Draft 2020-12 schema and
   both products' runtime `doctor` commands. Schema validation proves structure
   only; the runtime checks must separately attest referenced resources,
   authorities, roles, and deployment gates.

No database migration is required solely for the issuance narrowing. If either
product reports a different schema fingerprint or requires a state install for
another included change, stop and follow that product's exact release runbook.
Do not infer a migration from this procedure or alter tables manually.

## Candidate upgrade proof

1. Start one v0.11.0 Relay and one v0.11.0 Notary without caller traffic.
   Require both to report `0.11.0`, pass liveness, verify retained audit state,
   and attest readiness.
2. Prove one authorized purpose-bound Relay request succeeds and one denied
   request remains denied.
3. Present `Authorization` and `x-api-key` together to each applicable public
   API. Require `auth.multiple_credentials` before candidate validation, then
   confirm restricted audit evidence does not reveal which candidate was
   valid.
4. Evaluate one registry-backed claim and retain its exact compiler pin,
   normalized Relay execution provenance, selected roots, and result without
   recording subject data.
5. Attempt direct issuance from a retained v0.10.0 evaluation. It must fail
   before signer access. When OID4VCI is enabled, repeat the same negative
   proof through the credential endpoint.
6. Re-evaluate the same claim under v0.11.0. Confirm every selected credential
   root's dependency closure is registry-backed, non-delegated, compiler-pinned,
   and bound to one normalized record per unique Relay execution. Direct
   issuance may then proceed. Repeat the OID4VCI path when enabled.
7. Evaluate and render one permitted source-free or delegated evaluation, then
   prove issuance remains rejected. Evaluation and rendering capability must
   not become credential capability.
8. Restart both products and repeat retained evaluation, replay rejection,
   issuance provenance, audit-chain, and readiness checks.

The local `registryctl add notary` tutorial may be used as an evaluation
canary. It does not replace the issuance negatives above and does not count as
wallet, credential-presentation, or OID4VCI interoperability proof.

## Audit inconsistency recovery proof

Use a disposable copy of the candidate audit state, never the primary release
evidence set.

1. Stop the product, introduce a controlled retained-chain inconsistency in the
   disposable copy, and restart without traffic.
2. Confirm `/healthz` remains live while `/ready` latches unavailable with
   `audit.chain.inconsistent`. Confirm the response exposes no audit contents.
3. Stop the process. Run the product's offline audit quarantine command with
   the deployed configuration. It must acquire the single-writer lock, retain
   the corrupt files, and open a hash-linked break segment.
4. Restart and require retained-chain verification and readiness. Preserve the
   quarantined segment and recovery record as evidence.
5. Separately induce a transient I/O or secret-resolution failure and confirm
   it is not misclassified as a confirmed chain inconsistency.

## Rollback proof

1. Stop every v0.11.0 writer. Preserve the v0.11.0 databases, generated
   closure, audit evidence, and issued public verification material.
2. Confirm no v0.11.0 issuance or other acknowledged state exists after the
   v0.10.0 recovery point. If it does, keep the affected database offline and
   fix forward unless a reviewed product recovery procedure proves rollback
   safe.
3. Restore the complete v0.10.0 databases, configuration, exact binaries or
   image digests, image lock, anti-rollback state, audit state, signer
   references, and key-lifecycle material from the immutable backup.
4. Start one v0.10.0 instance of each product without traffic. Require the
   recorded baseline schema fingerprints, retained-chain verification,
   liveness, and readiness.
5. Repeat the baseline allowed and denied Relay requests, evaluation, direct
   issuance when enabled, and duplicate replay rejection.
6. Verify backup hashes and prove that sources, audit evidence, the v0.10.0
   databases, and the retained v0.11.0 state were not silently rewritten.

Rollback succeeds only when the restored topology matches the baseline and no
v0.11.0 acknowledged state is discarded. Keep any v0.11.0 public signing keys
published for the lifetime of credentials issued during the candidate run.

## Acceptance record

Record pass or fail for every step, exact refs and digests, redacted schema and
readiness facts, diagnostic codes, and the recovery-point decision. Do not
record raw credentials, tokens, subject identifiers, database URLs, source
records, or audit contents.

The source preparation alone does not claim successful execution, full
OID4VCI interoperability, a hosted promotion, an audit completion, an external
pilot, or stable 1.0 readiness.

## Published-asset verification record

The `v0.11.0` tag-triggered release workflow completed successfully as run
`29629077997`. The annotated tag peels to
`3e587a4f3483b180037b6994fcc4cc0e1d670a16`, whose release manifest source ref
is `9b851a606c9cfe298c16e515fbbb5f32c28d98cd`.

The independent consumer-side verification used a fresh download directory
and proved:

- the non-draft prerelease contains exactly 106 assets: 35 payloads, 35 keyless
  signatures, 35 signing certificates, and one SLSA provenance file;
- `SHA256SUMS` validates all eight versioned binaries and the Registryctl image
  lock;
- every one of the 35 payload signatures has the expected tag-workflow
  identity, and every payload is a subject of the authenticated SLSA
  provenance;
- the image lock, release capsule, file and image SBOMs, image-input checksums,
  image digest files, and vulnerability-report hashes agree;
- the public `registry-notary:v0.11.0` and `registry-relay:v0.11.0` tags resolve
  to the exact locked digests, are anonymously pullable, and run as non-root;
- the two service binaries report `0.11.0`; the embedded CEL and Rhai workers
  are internal framed-protocol executables and are not standalone versioned
  CLIs; and
- the published macOS Registryctl binary initialized the HTTP starter, emitted
  the VS Code and Zed editor manifest, passed all 21 generated offline
  fixtures, passed `check --environment local`, and completed
  `build --environment local`.

The signed Grype reports remain `review-required`. Their summaries are 7
Critical and 17 High matches for the Notary Debian runtime layer, and 1
Critical and 2 High matches for the Relay distroless Debian runtime layer.
The match sets are identical to the published `v0.10.0` reports, the recorded
feed offers no fixed package versions for the Critical and High matches, and
the affected images run non-root.
This is transparent prerelease evidence, not a stable-release clearance or a
claim that the findings are unreachable. Runtime-base migration remains a 1.0
work item.

The following release-gate work remains unexecuted and is not claimed:

- a retained v0.10.0 deployment backup and baseline;
- the registry-backed direct-issuance and OID4VCI positive and negative proofs;
- the disposable audit-inconsistency quarantine and recovery proof;
- restoration of the complete v0.10.0 databases, configuration, audit state,
  anti-rollback state, and key-lifecycle material; and
- hosted publication, the Solmara exact-digest adopter repin, or its smoke run.

Accordingly, `release/manifests/registry-stack-beta-13.yaml` remains
`release-candidate`. The GitHub prerelease is published and integrity-verified,
but the complete acceptance gate above must pass, or its residual risk must be
explicitly accepted for this beta, before the manifest is changed to
`released`.
