# Script source-adapter Registry Stack project

This starter demonstrates the product-neutral `script` capability with a
synthetic DHIS2 Tracker wire shape. Product and version metadata do not select
the Rhai runtime.

```bash
registryctl test --project-dir . --integration health-record --fixture complete-health-match --trace
registryctl test --project-dir . --integration health-record --fixture complete-health-match --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

Edit the reviewed `adapter.rhai`, integration contract, and synthetic fixtures
together. Keep source credentials in the environment binding.
