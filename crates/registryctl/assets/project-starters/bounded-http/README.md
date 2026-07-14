# Custom HTTP Registry Stack project

This starter demonstrates one bounded product-neutral HTTP integration.

From this workspace directory:

```bash
registryctl test --project-dir . --integration person-record --fixture active-person --trace
registryctl test --project-dir . --integration person-record --fixture active-person --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
registryctl authoring schema --kind integration > integration.schema.json
```

`check` is human-readable by default. Use `--format json` only for machine
consumers. The generated schema can be selected from an editor modeline.

Edit `integrations/person-record/integration.yaml` and its synthetic fixtures.
Keep real destinations and credentials only in `environments/` secret bindings.
