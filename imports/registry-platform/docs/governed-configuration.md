# Governed Configuration

`registry-platform-config` and the governed-configuration helpers in
`registry-platform-ops` provide shared primitives for Registry services that
accept signed runtime configuration. They are public integration contracts for
Registry Relay, Registry Notary, and similar runtimes. They are not a hosted
control plane, authoring service, or complete deployment workflow.

The consumer service still owns parsing the product config, compiling it into a
runtime snapshot, exposing admin endpoints, authenticating operators, and
emitting product-specific audit events. The platform crates own the verification
and state contracts that should be consistent across services.

## Verification Flow

A governed apply should follow this order:

1. Verify the TUF repository with `TufConfigVerifier`.
2. Parse `ConfigTargetMetadata` from the verified target custom metadata and
   bind it to the local `VerificationContext`.
3. Authorize the target against `RegistryAcceptedTrustRoots`.
4. Compile the candidate product configuration and confirm the requested
   `apply_policy` is safe for the current runtime boundary.
5. Build an `AntiRollbackProposal` and accept it with `FileAntiRollbackStore`
   immediately before applying runtime side effects.
6. Apply the candidate or report the rejection with the shared result
   vocabulary.

`verify_config_target` and `verify_remote_config_target` return
`VerifiedConfigTarget`, which contains the raw verified TUF target plus
Registry metadata projected from that verified target.

## TUF Verification

Use `LocalTufRepositoryInput` when metadata and targets are already on disk.
Use `RemoteTufRepositoryInput` when fetching metadata and targets from URLs.
Both modes require an explicit `datastore_dir`; this datastore is the TUF client
state used to reject stale timestamp and snapshot metadata across applies.

Remote verification uses the shared outbound fetch policy. Strict mode should be
the production default. `allow_dev_insecure_fetch_urls` exists only for local
development and test repositories that cannot satisfy the strict URL policy.

The verifier records:

- `root_sha256`, the hash of the final verified TUF root.
- TUF role versions for root, targets, snapshot, and timestamp.
- `target_bytes` and the verified target custom metadata.
- `signer_kids`, derived only from cryptographically valid signatures over the
  verified TUF targets role.

Do not trust `signer_kids` supplied inside target custom metadata as an
authorization source. `verify_config_target` overwrites metadata signer kids
with the verified TUF targets-role signer set before returning.

## Target Metadata

`ConfigTargetMetadata` is the Registry-specific metadata carried in TUF target
custom metadata. It is strict JSON and rejects unknown fields. Required fields
include:

- `product`, `instance_id`, and `environment`, which must match the local
  `VerificationContext`.
- `stream_id`, `bundle_id`, and monotonic `sequence`.
- `config_hash`, as a `sha256:` URI over the target payload bytes.
- `previous_config_hash`, when chaining from a prior accepted config.
- `change_classes`, the named change categories this bundle performs.
- `apply_policy`, such as a hot-apply or restart-required policy understood by
  the consuming product.

Change class names are product-defined vocabulary. Keep them stable enough for
trust roots and audit/report consumers to reason about them.

## Trust Roots, Roles, And Change Classes

`RegistryTrustRoot` binds a Registry trust policy to a specific verified TUF
root hash. `RegistryAcceptedTrustRoots` lets a service accept more than one
root during a bounded rotation window.

A trust root contains:

- `root_id`, for audit and operator reference.
- `production`, which enables extra validation for high-risk roles.
- `tuf_root_sha256`, matching `VerifiedConfigTarget.tuf.root_sha256`.
- Optional validity timestamps.
- `signers`, keyed by signer kid with an enabled flag.
- `roles`, each with a signer threshold and allowed change classes.
- `high_risk_change_classes`, used to forbid single-signer production roles.

Authorization is per change class. For every class listed by the target
metadata, at least one role must allow that class and have enough distinct
verified signer kids present. Disabled signers are rejected if they appear in
the verified signer set. In production, a role that covers a high-risk change
class must require at least two signers.

Signer kids are lowercase hex TUF keyids. To avoid mismatches, copy them from a
verified TUF target result or from the TUF root metadata tooling used to publish
the repository.

## Anti-Rollback State

`FileAntiRollbackStore` is the shared local state store for accepted governed
configuration. Its key is `product`, `instance_id`, `environment`, and
`stream_id`; a state file cannot be reused for a different runtime identity.

On accept, the store enforces:

- Strictly increasing bundle `sequence`.
- Non-decreasing TUF root version when a root version is known.
- `previous_config_hash` matching the last accepted config hash.

The store serializes writes through a sidecar lock file and writes state by
temporary file plus rename. Keep the anti-rollback file on durable local storage
that survives service restarts. Do not place it in a temporary directory for
production deployments.

## Break-Glass And Local Approval

Break-glass approval is an emergency path. A valid `BreakGlassApproval` can
waive only the `previous_config_hash` chain check. It does not waive monotonic
sequence, TUF root-version checks, TUF verification, trust-root authorization,
product config validation, or runtime readiness checks. Break-glass proposals
must include an approval, and runtimes must source the `BreakGlassRateLimit`
from trusted local verifier configuration before calling `FileAntiRollbackStore`.
Accepted approvals are recorded in the anti-rollback state.

`AntiRollbackProposal.break_glass_rate_limit` remains only as a compatibility
field for older callers that have not yet moved policy into the verifier-owned
store configuration. Production runtimes should configure
`FileAntiRollbackStore::with_break_glass_rate_limit(...)` and leave the proposal
field empty. A locally configured store rejects proposal policy that does not
match its verifier-owned policy, and the compatibility field should be removed
in the next breaking API revision once downstream products no longer construct
break-glass proposals with request-controlled rate limits.

Local operator approval is a separate controlled path for changes that require
site-local acknowledgement. `FileLocalApprovalStore` loads a
`LocalOperatorApproval` by approval reference, change class, config hash, and
previous config hash. The anti-rollback store records accepted local approvals
and enforces the rate limit loaded with the local approval record. Local approval does not waive
`previous_config_hash`; it must match the proposal.

Both approval types require non-empty operator, reason, reference, and
rate-limit identity fields, and both expire by Unix timestamp.

## Apply Results And Posture Vocabulary

Use `ApplyReportResult` for apply reports and audit-facing outcomes:

- `verified`
- `applied`
- `rejected_signature`
- `rejected_threshold`
- `rejected_freshness`
- `rejected_rollback`
- `rejected_restart_required`
- `rejected_readiness`
- `rejected_break_glass`
- `rejected_local_approval`
- `internal_error`

`ApplyReportResult::as_posture_result()` maps detailed report outcomes to the
coarser posture vocabulary:

- `applied` becomes `accepted`.
- Signature, threshold, freshness, rollback, restart-required, readiness,
  break-glass, and local-approval rejections become `rejected`.
- `internal_error` becomes `failed`.
- `verified` becomes `not_applied`.

Services should use the detailed result in apply responses and audit records,
then expose the posture result through `ConfigProvenance.last_apply_result`.

## Local And Simple Deployment Path

A small deployment does not need a remote control plane. The simplest governed
path is:

1. Publish a local TUF repository directory containing metadata and target
   config files.
2. Configure the service with `LocalTufRepositoryInput` paths for bootstrap
   root, metadata, targets, durable TUF datastore, and target name.
3. Store accepted Registry trust roots in the product's local operator config.
4. Store anti-rollback state in a durable local path unique to the product,
   instance, environment, and stream.
5. Optionally store local approvals in a local JSON file consumed by
   `FileLocalApprovalStore`.

For this local mode, posture should report `ConfigSource::SignedBundleFile`
when applying a signed bundle from disk, or `ConfigSource::LocalFile` when the
service is running from an unsigned static config file. Use
`ConfigSource::SignedBundleEndpoint` only when the service verifies and applies
a signed bundle fetched from an endpoint.

This path is appropriate for single-node or manually promoted environments as
long as the TUF datastore and anti-rollback state are durable and backed up with
the runtime. Multi-node deployments need product-level coordination so every
node observes compatible trust roots, TUF client state, anti-rollback state, and
runtime snapshots.
