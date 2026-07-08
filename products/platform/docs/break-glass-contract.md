# Break-Glass Override Contract

This note defines the Registry Config Bundle v1 emergency override contract.
Break-glass is a local boot fallback, not an HTTP admin operation and not a
workflow engine. Registry Relay, Registry Notary, and registryctl use the shared
platform primitives so emergency recovery has the same fail-closed behavior
across products.

## Scope

In scope:

- The local override file shape and permissions.
- The difference between `accept_rollback` and `accept_unsigned`.
- Atomic consumption and restart pin behavior.
- Anti-rollback and posture effects.
- Audit and stderr behavior for emergency acceptance and rejection.

Out of scope:

- A central approval service or cross-node coordination store.
- Any admin config apply, verify, or dry-run route.
- Remote config repositories or hot-apply policy.

## Override File

The override file uses schema `registry.platform.config_break_glass.v1`.

```json
{
  "schema": "registry.platform.config_break_glass.v1",
  "mode": "accept_unsigned",
  "config_hash": "sha256:...",
  "config_path": "/var/lib/registry/config/emergency.yaml",
  "reason": "operator supplied local reason",
  "operator": "operator id",
  "created_at": "2026-07-07T10:00:00Z",
  "expires_at": "2026-07-07T12:00:00Z"
}
```

`mode` is one of:

- `accept_rollback`: authorizes boot from the exact signed bundle config hash
  named by `config_hash`. `config_path` is forbidden.
- `accept_unsigned`: authorizes boot from the absolute local file named by
  `config_path`, pinned by `config_hash`.

`expires_at` must be after `created_at`, must be in the future, and must not
extend the emergency window beyond the platform cap.

## Permissions

The override file is a root-controlled local artifact:

- It must be owned by uid 0 on Unix systems.
- It must not be group-writable or world-writable.
- It must not be a symlink.
- In `accept_unsigned` mode, `config_path` must be absolute and must resolve to
  a regular file whose bytes hash to `config_hash`.

The directory may be service-writable so the runtime can consume the file, but
the file itself must be root-owned. A compromised service account must not be
able to mint its own override.

## Boot Behavior

The runtime first attempts normal signed bundle verification. If verification or
anti-rollback fails, it may consider the configured override file.

`accept_rollback` keeps signature, binding, file-closure, hash, and product
validation checks. It waives only the monotonic sequence rejection for the exact
signed bundle config hash in the override.

`accept_unsigned` skips signature, binding, and sequence checks. It still
requires:

- Valid override-file permissions.
- Exact hash pinning of the unsigned local config file.
- Full product config parsing and validation.

`accept_unsigned` never advances the high-water mark. Exiting the emergency
requires a later signed bundle with a sequence higher than the last normally
accepted signed bundle.

## Consumption And Restart Pin

Consumption is an atomic same-directory rename of the override file. If the
rename fails, boot aborts.

After a valid override is consumed, the anti-rollback state records a restart
pin for the exact pinned config hash. This prevents a crash loop from re-bricking
the node before an operator can finish recovery. The pin grants nothing else:

- A different hash is still rejected.
- An expired or mismatched override is still rejected.
- The next normal signed bundle acceptance clears the pin.

## State Key

Anti-rollback state is keyed by `product`, `environment`, and `stream_id`.
`instance_id` is a boot-time binding check only; it is not part of the persisted
anti-rollback key. This prevents a node from opening a rollback window by moving
between fleet-wide and instance-pinned bundles in the same stream.

`previous_config_hash` is advisory. Runtimes record whether it matched the last
accepted hash, but they do not reject solely because it does not match. Enforcing
it would reject legitimate offline sequence skips.

## Audit And Posture

Normal signed bundle acceptance emits `config.bundle_accepted` before persisting
anti-rollback state. A crash between the audit event and the state write may
re-emit the event on the next boot; consumers should treat `bundle_id` plus
`sequence` as the idempotency key.

Rejection events are best-effort because a node that rejects a bundle cannot
depend on audit configuration from that bundle. Rejections are always mirrored to
stderr with a nonzero exit.

Posture reports unsigned emergency boot as `source: LocalFile` with
`override.active: true`. Signed rollback override posture keeps the signed bundle
identity and marks the override pin.
