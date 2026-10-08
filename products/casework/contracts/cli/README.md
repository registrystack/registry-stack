# `caseworkctl` JSON wire contract

Every parsed public command response produced by `caseworkctl --format json`
carries this top-level envelope:

```json
{
  "ok": true,
  "command": "check",
  "status": "complete",
  "apiVersion": "registry.registrystack.org/caseworkctl/v1alpha3",
  "kind": "CheckReport"
}
```

The report opens with `ok`, `command`, and `status`, in that order, as the
sibling `evidencectl` and `schedulingctl` reports do. `ok` is true exactly when
the process exits 0. `command` names the command path. `status` names what
happened: the command's own status where its schema declares one, `passed` for
a successful `test`, `complete` for any other success, `refused` for a plan
that names its refusals, and otherwise the exit class of the failure:
`domain-refusal` (exit 1), `usage-error` (exit 2), or `operational-failure`
(exit 3). A report that is not ok carries a non-empty `diagnostics` array, and
each diagnostic names a `suggestedAction`.

`apiVersion` versions the complete CLI surface. `kind` selects one of the
draft 2020-12 schemas in this directory. Each is published in the
identifier catalog under the `kind` in kebab case: `CheckReport.schema.json`
is
`https://id.registrystack.org/schemas/casework/check-report/check-report.v1alpha3.schema.json`. The schemas cover successful reports and the diagnostic
refusal a parsed command can emit. Argument parsing failures use
`UsageReport`.

`ExplainReport` and `CheckReport` carry part of the authored project and refer
to the project schema's definitions of it,
`../project/project.v1alpha1.schema.json`, rather than copying them. A
validator for those two loads
`products/casework/generated/project/project.schema.json` beside the report
schema.

Clap's `--help` and `--version` displays are command-line metadata, not command
responses. Clap emits them as plain text before command dispatch, even when
`--format json` is also present, so they are intentionally outside this JSON
wire contract.

| Command | `kind` | Schema |
|---|---|---|
| `attempt settle` | `AttemptSettlementReport` | `AttemptSettlementReport.schema.json` |
| `attempt mark-uncertain` | `AttemptUncertainMarkingReport` | `AttemptUncertainMarkingReport.schema.json` |
| `apply` | `ApplyReport` | `ApplyReport.schema.json` |
| `check` | `CheckReport` | `CheckReport.schema.json` |
| `doctor` | `DoctorReport` | `DoctorReport.schema.json` |
| `explain` | `ExplainReport` | `ExplainReport.schema.json` |
| `init` | `InitReport` | `InitReport.schema.json` |
| `lifecycle` | `LifecycleReport` | `LifecycleReport.schema.json` |
| `package` and `package --dry-run` | `PackageReport` | `PackageReport.schema.json` |
| `plan` | `PlanReport` | `PlanReport.schema.json` |
| `retention erase` | `RetentionEraseReport` | `RetentionEraseReport.schema.json` |
| `simulate` | `SimulationReport` | `SimulationReport.schema.json` |
| `source add` | `SourceAddReport` | `SourceAddReport.schema.json` |
| `status` | `StatusReport` | `StatusReport.schema.json` |
| `test` | `TestReport` | `TestReport.schema.json` |
| `dev`, `dev start`, and `dev stop` | `DevReport` | `DevReport.schema.json` |
| `dev events` | `DevEventsReport` | `DevEventsReport.schema.json` |
| `dev grant` | `DevGrantReport` | `DevGrantReport.schema.json` |
| `dev identity` | `DevIdentityReport` | `DevIdentityReport.schema.json` |
| `dev token` | `DevTokenReport` | `DevTokenReport.schema.json` |
| invalid command arguments, and the removed `db migrate` | `UsageReport` | `UsageReport.schema.json` |

The dev-only reports are included. They are local operator surfaces, but shell
tools still parse them and need the same explicit drift signal as adopter
commands. Internal supervisor and service-guard entry points are excluded
because they are process-control implementation details and do not support
`--format json`.

## Pinned and opaque fields

A field is **pinned** when its schema names it, types it, and its containing
object is closed. Changing a pinned field's name, type, presence, or closed
value set changes this wire contract. Every field is pinned except the opaque
ones listed below. A field typed by a project schema definition is pinned to
that definition and changes when the project schema does.

A field is **opaque** when the schema constrains it only as an object, array,
or unconstrained JSON value. These nodes pass through a type owned by the
Casework engine, a source adapter, or another product. Their interior is not a
promise made by this CLI contract:

- the `target` of each request in `CheckReport.effective.sources`
- `SimulationReport.clock`
- `SourceAddReport.bregAuthoringChanges`, `bregAuthoringPatch`, and
  `candidateRuntimeBinding`
- `DevReport.sources` and `DevReport.clients`

Consumers of an opaque node must validate the fields they read. A stable
`caseworkctl` `apiVersion` does not say that an opaque engine-owned structure
has not changed.

## Compatibility and gate

The version changes when a pinned field is removed or renamed, its type or
closed vocabulary changes, or a field is added to a pinned object. Additions
are breaking because pinned objects reject unknown properties. Changes inside
an explicitly opaque node do not require a CLI version change.

`crates/registry-caseworkctl/src/cli_contract_tests.rs` exercises all 21 kinds
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
