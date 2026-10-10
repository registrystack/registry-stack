# `caseworkctl` JSON wire contract

Every parsed public command response produced by `caseworkctl --format json`
carries this top-level envelope:

```json
{
  "ok": true,
  "command": "check",
  "status": "complete",
  "apiVersion": "id.registrystack.org/formats/casework/check-report/v1alpha3",
  "kind": "CaseworkCheckReport"
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

Each report is its own format. `apiVersion` names it,
`id.registrystack.org/formats/casework/<report>/v1alpha3`, where `<report>`
is the report's name in kebab case, and `kind` is the same name behind the
product's: `CaseworkCheckReport` is the format `casework/check-report`. The
reports carry one version and move together: a breaking change to any pinned
field bumps the version of them all. `kind` selects one of the draft 2020-12
schemas in this directory, each in a file named for the report without the
product prefix and published in the identifier catalog under the report's
name in kebab case: `CheckReport.schema.json` is
`https://id.registrystack.org/schemas/casework/check-report/check-report.v1alpha3.schema.json`. The schemas cover successful reports and the diagnostic
refusal a parsed command can emit. Argument parsing failures use
`CaseworkUsageReport`.

`CaseworkExplainReport` and `CaseworkCheckReport` carry part of the authored project and refer
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
| `attempt settle` | `CaseworkAttemptSettlementReport` | `AttemptSettlementReport.schema.json` |
| `attempt mark-uncertain` | `CaseworkAttemptUncertainMarkingReport` | `AttemptUncertainMarkingReport.schema.json` |
| `apply` | `CaseworkApplyReport` | `ApplyReport.schema.json` |
| `check` | `CaseworkCheckReport` | `CheckReport.schema.json` |
| `doctor` | `CaseworkDoctorReport` | `DoctorReport.schema.json` |
| `explain` | `CaseworkExplainReport` | `ExplainReport.schema.json` |
| `init` | `CaseworkInitReport` | `InitReport.schema.json` |
| `lifecycle` | `CaseworkLifecycleReport` | `LifecycleReport.schema.json` |
| `package` and `package --dry-run` | `CaseworkPackageReport` | `PackageReport.schema.json` |
| `plan` | `CaseworkPlanReport` | `PlanReport.schema.json` |
| `retention erase` | `CaseworkRetentionEraseReport` | `RetentionEraseReport.schema.json` |
| `simulate` | `CaseworkSimulationReport` | `SimulationReport.schema.json` |
| `source add` | `CaseworkSourceAddReport` | `SourceAddReport.schema.json` |
| `status` | `CaseworkStatusReport` | `StatusReport.schema.json` |
| `test` | `CaseworkTestReport` | `TestReport.schema.json` |
| `dev`, `dev start`, and `dev stop` | `CaseworkDevReport` | `DevReport.schema.json` |
| `dev events` | `CaseworkDevEventsReport` | `DevEventsReport.schema.json` |
| `dev grant` | `CaseworkDevGrantReport` | `DevGrantReport.schema.json` |
| `dev identity` | `CaseworkDevIdentityReport` | `DevIdentityReport.schema.json` |
| `dev token` | `CaseworkDevTokenReport` | `DevTokenReport.schema.json` |
| invalid command arguments, and the removed `db migrate` | `CaseworkUsageReport` | `UsageReport.schema.json` |

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

- the `target` of each request in `CaseworkCheckReport.effective.sources`
- `CaseworkSimulationReport.clock`
- `CaseworkSourceAddReport.bregAuthoringChanges`, `bregAuthoringPatch`, and
  `candidateRuntimeBinding`
- `CaseworkDevReport.sources` and `CaseworkDevReport.clients`

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

Each report format registers an example in
`products/casework/examples/formats/reports/`: the output of one command, run
from the repository root, with the checkout's path removed from `package`'s
`project`. A command whose successful report needs a database, an issuer, a
BReg project, or a running development session (`attempt`, `retention erase`, `apply`, `plan`,
`status`, `doctor`, `source add`, and every `dev` command except
`dev identity`) has its refusal as its example.
`crates/registry-caseworkctl/tests/report_examples.rs` fails when an example differs from what its command writes, and the contract
test validates each example against its schema. Regenerate the examples after
an intentional report change:

```sh
CASEWORKCTL_WRITE_REPORT_EXAMPLES=1 cargo test -p registry-caseworkctl --test report_examples
```

Regenerate the schemas after an intentional contract edit:

```sh
python3 products/casework/scripts/generate_cli_schemas.py
python3 products/casework/scripts/generate_cli_schemas.py --check
```
