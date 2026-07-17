# Governed Configuration

`registry-platform-config` provides the shared Registry Config Bundle v1
contracts for services that boot from signed runtime configuration. Registry
Relay, Registry Notary, and similar runtimes use these primitives to verify a
local bundle directory before startup. They are not a hosted control plane,
remote update service, admin API, or complete deployment workflow.

The consumer service still owns parsing the product config, compiling it into a
runtime snapshot, validating readiness, and emitting product-specific audit
events. The platform crate owns the local bundle verification and state
contracts that should be consistent across services.

## Environment expansion

Shared configuration loaders expand `${VAR}` expressions before YAML parsing.
`${VAR}` requires `VAR` to be set to a non-empty value. `${VAR:-fallback}`
uses `fallback` when `VAR` is unset or empty, including `${VAR:-}` for an
explicit empty result. `${VAR:?message}` fails with `message` when `VAR` is
unset or empty. Whitespace-only values are non-empty. Diagnostics name the
variable or use the supplied message; they never include the variable value.

## Bundle layout

A Registry Config Bundle v1 is a local directory. The verifier reads:

- `manifest.json`, the strict bundle manifest.
- `manifest.sig.json`, signatures over the canonical manifest.
- `config/...`, the product configuration files named by the manifest.

The manifest binds the bundle to a product, environment, stream, optional
instance, monotonic sequence, bundle id, creation time, whole-config hash, and
the closed set of files allowed in the bundle. The verifier rejects unlisted
files, missing files, symlinks, paths outside the bundle, and file hashes that do
not match the manifest.

## Verification flow

A bundle-aware runtime should follow this order at startup:

1. Verify the local bundle directory against the configured trust anchor.
2. Bind the manifest to the local product, environment, stream, and instance.
3. Confirm at least one enabled trust-anchor signer produced a valid manifest
   signature.
4. Confirm the file closure and `config_hash`.
5. Compile and validate the product configuration.
6. Accept or initialize anti-rollback state immediately before the service
   starts with the verified configuration.
7. Report the acceptance or rejection with the shared result vocabulary.

`verify_config_bundle` returns `VerifiedConfigBundle`, which contains the
manifest, verified signer kids, primary config path, and config bytes.

## Manifest metadata

`ConfigBundleManifest` is strict JSON and rejects unknown fields. Required
fields include:

- `product` and `environment`, which must match the local trust anchor.
- `instance_id`, when the bundle is bound to a specific runtime instance.
- `stream_id`, `bundle_id`, and monotonic `sequence`.
- `config_hash`, as a `sha256:` URI over the target payload bytes.
- `previous_config_hash`, when chaining from a prior accepted config.
- `files`, the exact file paths and hashes allowed under the bundle directory.
- `created_at`, the bundle creation timestamp.

Config Bundle v1 does not carry change classes or hot-apply policy. Applying a
bundle means placing the verified bundle directory where the service reads it
and restarting the service.

## Trust anchors

`ConfigTrustAnchor` is a local JSON file. It binds the accepted signing keys to
a specific product, environment, stream, and instance.

A trust anchor contains:

- `product`, `environment`, `stream_id`, and `instance_id`.
- `signers`, each with a key id, public JWK, and enabled flag.

The verifier derives signer kids from the trust-anchor JWKs and accepts only
valid signatures from enabled signers. Rotate trust anchors through your
deployment process and restart the runtime with the updated trust anchor.

## Anti-Rollback State

`FileAntiRollbackStore` is the shared local state store for accepted governed
configuration. Its key is `product`, `environment`, and `stream_id`; `instance_id`
is a boot-time binding check only. A state file cannot be reused for a different
product, environment, or stream.

On accept, the store enforces:

- Strictly increasing bundle `sequence`.

`previous_config_hash` is advisory. Runtimes record whether it matched the last
accepted config hash, but a mismatch is not a rejection because nodes may
legitimately skip sequences while offline.

The store serializes writes through a sidecar lock file and writes state by
temporary file plus rename. Keep the anti-rollback file on durable local storage
that survives service restarts. Do not place it in a temporary directory for
production deployments.

## Emergency local override

`ConfigBreakGlassOverride` is a local boot fallback file, not an HTTP admin
break-glass mechanism. It is optional and intended for emergency startup when an
operator needs to recover locally.

`accept_rollback` can pin the exact signed bundle hash to accept during boot.
`accept_unsigned` can pin an absolute local config file path and hash for
emergency startup. In `accept_unsigned` mode, signature, binding, and sequence
checks are skipped, but file permissions, hash pinning, and product config
validation still run. The override file is consumed locally and must expire.

## Acceptance results and posture vocabulary

Use `ApplyReportResult` for verification reports and audit-facing outcomes:

- `verified`
- `rejected_signature`
- `rejected_binding`
- `rejected_validation`
- `rejected_rollback`
- `internal_error`

`ApplyReportResult::as_posture_result()` maps detailed report outcomes to the
coarser posture vocabulary:

- Signature, binding, validation, and rollback rejections become `rejected`.
- `internal_error` becomes `failed`.
- `verified` becomes `not_applied`.

Services should use the detailed result in audit records, then expose the
posture result through `ConfigProvenance.last_apply_result`.

## Local And Simple Deployment Path

A small deployment does not need a remote control plane. The simplest governed
path is:

1. Build a local bundle directory containing `manifest.json`,
   `manifest.sig.json`, and `config/...`.
2. Configure the service with the local `bundle_path`, `trust_anchor_path`, and
   durable `antirollback_state_path`.
3. Run the node CLI `config verify-bundle` before promotion when you want an
   offline check.
4. Place the bundle directory on the node and restart the service.

For this local mode, posture should report `ConfigSource::SignedBundleFile`.
Use `ConfigSource::LocalFile` only when the service is running from an unsigned
static config file.

This path is appropriate for single-node or manually promoted environments as
long as the anti-rollback state is durable and backed up with the runtime.
Multi-node deployments need product-level coordination so every node observes
compatible trust anchors, anti-rollback state, and runtime snapshots.
