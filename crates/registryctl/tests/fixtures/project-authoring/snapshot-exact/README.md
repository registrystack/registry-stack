# Exact snapshot Registry Stack project

This starter demonstrates an exact consultation over one Relay-local
materialized entity without requiring a records API.

```bash
registryctl -C . tooling editor
registryctl test --project-dir . --integration person-snapshot --fixture snapshot-match --trace
registryctl test --project-dir . --integration person-snapshot --fixture snapshot-match --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

`authoring editor`, `test`, `check`, and `build` are human-readable by default. Use `--format json`
with those report commands only for machine consumers. Editor setup uses the five schemas copied
from this `registryctl` build for VS Code and Zed.

Add a records service only when the project intentionally publishes the entity
through Relay's governed records API.

Relay normalizes the source fields as `registration_status` and
`residency_confirmed` and exposes them through the bounded consultation API.
The consultation consumer, not this project, determines how those outputs are used.
The decision owner remains accountable for eligibility, qualification,
prioritization, approval, payment, workflow, and action rules. A no-match keeps
both output values unknown rather than silently converting missing source data
to a negative fact.
