# Signed DCI Registry Stack project

This starter demonstrates the product-neutral `script` capability with
host-owned signed DCI verification and synthetic OpenCRVS-shaped fixtures.

```bash
registryctl authoring editor --project-dir .
registryctl test --project-dir . --integration birth-record --fixture birth-record-match --trace
registryctl test --project-dir . --integration birth-record --fixture birth-record-match --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
registryctl authoring xw --format reference
```

`authoring editor`, `test`, `check`, and `build` are human-readable by default. Use `--format json`
with those report commands only for machine consumers. Editor setup uses the five schemas copied
from this `registryctl` build for VS Code and Zed.

Project-owned Rhai handles traversal and normalization. Relay owns signature,
correlation, selector, sender, receiver, and cardinality verification.

The match response is explicitly synthetic. Its fictional parent records
contain a source-only reference so the adapter demonstrates data minimization:
it constructs each released parent object field by field and releases only
`type`, `name`, and `identifier`. The closed `parents` output permits at most
two objects and caps both the array and each item by canonical serialized
bytes. The adapter never spreads or returns a whole source parent record.
`parents` is one top-level credential claim and is disclosed or withheld as a
whole unit; this project does not declare nested selective disclosure.
