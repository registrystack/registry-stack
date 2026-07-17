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
registryctl authoring xw --format reference
registryctl authoring schema --kind integration > integration.schema.json
```

`check` is human-readable by default. Use `--format json` only for machine
consumers. The generated schema can be selected from an editor modeline.

Edit the reviewed `adapter.rhai`, integration contract, and synthetic fixtures
together. Keep source credentials in the environment binding.

The `include_inactive` boolean is a bounded, typed target attribute supplied by
the evaluation caller and forwarded through Notary and Relay. It is request
context only. It is not an authenticated identity or a substitute for the
`dhis2_tracked_entity` identifier used to select the record.
