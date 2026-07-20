# Custom HTTP Registry Stack project

This starter demonstrates one bounded product-neutral HTTP integration.

From this workspace directory:

```bash
registryctl authoring editor --project-dir .
registryctl test --project-dir . --integration person-record --fixture active-person --trace
registryctl test --project-dir . --integration person-record --fixture active-person --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

`authoring editor`, `test`, `check`, and `build` are human-readable by default. Use `--format json`
with those report commands only for machine consumers. Editor setup uses the five schemas copied
from this `registryctl` build for VS Code and Zed.

Edit `integrations/person-record/integration.yaml` and its synthetic fixtures.
Keep real destinations and credentials only in `environments/` secret bindings.
