# Exact snapshot Registry Stack project

This starter demonstrates an exact consultation over one Relay-local
materialized entity without requiring a records API.

```bash
registryctl test --project-dir . --integration person-snapshot --fixture snapshot-match --trace
registryctl test --project-dir . --integration person-snapshot --fixture snapshot-match --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

Add a records service only when the project intentionally publishes the entity
through Relay's governed records API.
