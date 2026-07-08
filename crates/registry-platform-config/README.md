# registry-platform-config

Shared contracts for Registry Config Bundle v1 delivery.

This crate owns the Registry-specific local bundle verifier: manifest parsing,
product/instance/environment binding, manifest signature verification, trust
anchor validation, file-closure checks, and emergency local override parsing.
Product crates still parse and compile their own configuration after this layer
accepts a bundle.

`verify_config_bundle` verifies a local directory containing `manifest.json`,
`manifest.sig.json`, and `config/...` against a local trust anchor. It returns
the manifest, verified signer kids, primary config path, and config bytes.

Operator and integration guidance for the governed configuration primitives is
in
[`products/platform/docs/governed-configuration.md`](../../products/platform/docs/governed-configuration.md).
