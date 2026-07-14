# Signed DCI Registry Stack project

This starter demonstrates the product-neutral `script` capability with
host-owned signed DCI verification and synthetic OpenCRVS-shaped fixtures.

```bash
registryctl test --project-dir . --integration birth-record --fixture birth-record-match --trace
registryctl test --project-dir . --integration birth-record --fixture birth-record-match --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

Project-owned Rhai handles traversal and normalization. Relay owns signature,
correlation, selector, sender, receiver, and cardinality verification.
