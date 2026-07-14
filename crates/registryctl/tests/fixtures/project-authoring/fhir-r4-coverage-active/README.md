# FHIR R4 Registry Stack project

This starter demonstrates the product-neutral `script` capability with bounded
FHIR R4 search-set handling and same-authority continuation fixtures.

```bash
registryctl test --project-dir . --integration coverage --fixture coverage-active --trace
registryctl test --project-dir . --integration coverage --fixture coverage-active --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
registryctl authoring xw --format reference
registryctl authoring schema --kind integration > integration.schema.json
```

`check` is human-readable by default. Use `--format json` only for machine
consumers. The generated schema can be selected from an editor modeline.

The fixtures are synthetic and offline. Keep source authority, authentication,
private-network admission, and TLS bindings in `environments/`.
