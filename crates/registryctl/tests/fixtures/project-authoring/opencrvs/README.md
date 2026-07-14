# Signed DCI Registry Stack project

This starter demonstrates the product-neutral `script` capability with
host-owned signed DCI verification and synthetic OpenCRVS-shaped fixtures.

```bash
registryctl test --project-dir . --integration birth-record --fixture birth-record-match --trace
registryctl test --project-dir . --integration birth-record --fixture birth-record-match --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
registryctl authoring xw --format reference
registryctl authoring schema --kind integration > integration.schema.json
```

`check` is human-readable by default. Use `--format json` only for machine
consumers. The generated schema can be selected from an editor modeline.

Project-owned Rhai handles traversal and normalization. Relay owns signature,
correlation, selector, sender, receiver, and cardinality verification.
