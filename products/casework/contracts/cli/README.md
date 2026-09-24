# `caseworkctl` JSON wire contract

Every parsed public command response produced by `caseworkctl --format json`
carries this top-level envelope:

```json
{
  "apiVersion": "registry.registrystack.org/caseworkctl/v1alpha1",
  "kind": "CheckReport",
  "ok": true,
  "command": "check"
}
```

`apiVersion` versions the complete CLI surface. `kind` selects one of the
self-contained draft 2020-12 schemas in this directory. The schemas cover
successful reports and the diagnostic refusal a parsed command can emit.
Argument parsing failures use `UsageReport`.

Clap's `--help` and `--version` displays are command-line metadata, not command
responses. Clap emits them as plain text before command dispatch, even when
`--format json` is also present, so they are intentionally outside this JSON
wire contract.

| Command | `kind` | Schema |
|---|---|---|
| `attempt settle` | `AttemptSettlementReport` | `AttemptSettlementReport.schema.json` |
| `attempt mark-uncertain` | `AttemptUncertainMarkingReport` | `AttemptUncertainMarkingReport.schema.json` |
| `check` | `CheckReport` | `CheckReport.schema.json` |
| `db migrate` | `DatabaseMigrationReport` | `DatabaseMigrationReport.schema.json` |
| `doctor` | `DoctorReport` | `DoctorReport.schema.json` |
| `explain` | `ExplainReport` | `ExplainReport.schema.json` |
| `init` | `InitReport` | `InitReport.schema.json` |
| `lifecycle` | `LifecycleReport` | `LifecycleReport.schema.json` |
| `package` and `package --dry-run` | `PackageReport` | `PackageReport.schema.json` |
| `retention erase` | `RetentionEraseReport` | `RetentionEraseReport.schema.json` |
| `simulate` | `SimulationReport` | `SimulationReport.schema.json` |
| `source add` | `SourceAddReport` | `SourceAddReport.schema.json` |
| `test` | `TestReport` | `TestReport.schema.json` |
| `dev`, `dev start`, and `dev stop` | `DevReport` | `DevReport.schema.json` |
| `dev events` | `DevEventsReport` | `DevEventsReport.schema.json` |
| `dev grant` | `DevGrantReport` | `DevGrantReport.schema.json` |
| `dev identity` | `DevIdentityReport` | `DevIdentityReport.schema.json` |
| `dev token` | `DevTokenReport` | `DevTokenReport.schema.json` |
| invalid command arguments | `UsageReport` | `UsageReport.schema.json` |

The dev-only reports are included. They are local operator surfaces, but shell
tools still parse them and need the same explicit drift signal as adopter
commands. Internal supervisor and service-guard entry points are excluded
because they are process-control implementation details and do not support
`--format json`.

## Pinned and opaque fields

A field is **pinned** when its schema names it, types it, and its containing
object has `additionalProperties: false`. These fields are constructed
explicitly by `registry-caseworkctl`; changing their name, type, presence, or
closed value set changes this wire contract. Every report's top-level fields,
the common diagnostic shape, doctor readiness keys, lifecycle descriptions,
simulation subject, test fixture summary, and dev directory summary are
pinned.

A field is **opaque** when the schema constrains it only as an object, array,
or unconstrained JSON value. These nodes pass through a type owned by the
Casework engine, a source adapter, or another product. Their interior is not a
promise made by this CLI contract:

- `AttemptSettlementReport.report`, `AttemptUncertainMarkingReport.report`,
  and `RetentionEraseReport.report`
- `CheckReport.effective`
- `DoctorReport.secretFileChecks` and `DoctorReport.sourceChecks`
- the policy arrays in `ExplainReport`
- `PackageReport.files`
- `SimulationReport.routing` and `SimulationReport.clock`
- `SourceAddReport.connection`, `bregAuthoringChanges`,
  `bregAuthoringPatch`, and `candidateRuntimeBinding`
- `DevReport.sources` and `DevReport.clients`

Consumers of an opaque node must validate the fields they read. A stable
`caseworkctl` `apiVersion` does not say that an opaque engine-owned structure
has not changed.

## Compatibility and gate

The version changes when a pinned field is removed or renamed, its type or
closed vocabulary changes, or a field is added to a pinned object. Additions
are breaking because pinned objects reject unknown properties. Changes inside
an explicitly opaque node do not require a CLI version change.

`crates/registry-caseworkctl/src/cli_contract_tests.rs` exercises all 18 kinds
through the real command dispatcher and validates each response against its
schema. Commands whose successful path requires a live database, issuer,
source, or retained dev session use a deliberate real refusal fixture, so the
gate remains database-free while still proving their envelope and diagnostic
path. The same gate runs the generator in freshness mode.

Regenerate after an intentional contract edit:

```sh
python3 products/casework/scripts/generate_cli_schemas.py
python3 products/casework/scripts/generate_cli_schemas.py --check
```
