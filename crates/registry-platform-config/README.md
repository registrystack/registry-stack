# registry-platform-config

Shared contracts for governed runtime configuration delivery.

This crate owns the Registry-specific layer that sits around the TUF client:
target metadata parsing, product/instance/environment binding, per-change-class
authorization, trust-root validation, and verifier input checks that prevent
ephemeral rollback state. Product crates still parse and compile their own
configuration after this layer accepts a target.

`verify_config_target` treats the verified TUF targets-role signatures as the
authoritative signer set and projects those kids onto the returned target
metadata. Local products should authorize against `RegistryAcceptedTrustRoots`
when more than one local root is configured for a bounded rotation overlap.

Operator and integration guidance for the governed configuration primitives is
in [`docs/governed-configuration.md`](../../docs/governed-configuration.md).
