# Relay V2 tooling integration

`registry-relayctl` owns command-line parsing and presentation only. Its single
semantic dependency seam is `src/shared.rs`, which calls
`registry_relay_v2::tooling` directly. The CLI never starts `relay`, parses
runtime output, opens SQLite itself, or classifies a contract change.

The shared facade must provide:

- `init_project(&InitOptions)` for a complete authoring workspace whose
  compiler-derived semantics, classifications, processing metadata, and
  lifecycle-policy suggestions are marked unreviewed;
- `inspect_schema(&InspectOptions)` through the Relay wrapper over
  `registry-platform-sqlite`, returning structural metadata only;
- `check_project(&CheckOptions)`, including a production profile that refuses
  every unreviewed suggestion and an opt-in explanation of the exact compiled
  operation, access, disclosure, processing, transform, query, and wire-format
  boundaries;
- `generate_project`, `test_project`, `diff_projects`, and `package_project`
  using the exact compiler, fixture, diff, and packager implementations shared
  with the runtime;
- a serializable `ToolingReport` with typed status, `is_success()`, stable
  value-free diagnostics, project-relative paths, and command-specific
  `ToolingDetails`;
- a `ToolingError::safe_message()` that contains neither source values nor
  absolute paths.

`ToolingDetails::SchemaInspection` may contain object and column names,
declared SQLite types, nullability, key membership, object kind, and the schema
fingerprint. It must never contain row values, defaults evaluated from rows, or
SQL query results. `ToolingDetails::Diff` is the compiler's authoritative
change report. The CLI neither adds nor removes change classes.

`relayctl check PROJECT --explain` remains read-only and compiles through that
same facade once. A successful check includes the canonical typed operation
explanation. A refused check includes the existing diagnostics and no partial
explanation. `relayctl generate` writes the same canonical explanation to
`generated/reports/operation-explanation.json` by default, or to the same
relative report path beneath `--output`. The CLI only renders it for people or
serializes the shared report for automation.

Workspace integration adds `registry-relay-v2` and `registry-relayctl` as root
members and workspace dependencies. That root edit and the corresponding lock
update are intentionally outside this crate's ownership.
