# Casework CLI reports

Every `caseworkctl --format json` command writes one JSON report to standard
output. The command exit is 0 for success, 1 for a domain refusal, 2 for invalid
usage and 3 for an unavailable file, process or service. Diagnostics contain a
code, source path, message and suggested recovery action; they omit rejected
scalar values and credentials.

```json
{
  "ok": true,
  "command": "check",
  "status": "complete",
  "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
  "kind": "CaseworkReport",
  "diagnostics": [],
  "data": {
    "project": "./review-project",
    "policyBindings": [],
    "filesChecked": 1,
    "networkAccess": false,
    "databaseAccess": false
  }
}
```

[report.schema.json](report.schema.json) is the command-tagged union of the
owning Rust output DTOs. Command-specific data is under `data`; a failure that
cannot produce data carries diagnostics without `data`. The commands are
`init`, `check`, `explain`, `test`, `types`, `provider-add`, `provider-pair`, `lifecycle`,
`package`, `doctor`, `plan`, `apply`, `status`, `dev`, `dev-events`, `dev-token`,
`dev-grant`, `dev-identity`, and `usage`. Dev reports expose session state as
`data.state`; the envelope status remains the command outcome.

Policy, context, stage, outcome, routing, clock, staffing and activation shapes
come from their owning DTO schemas. Presentation labels remain inspectable in
`explain`; policy bindings identify behavior. Package digests cover every
captured authored byte, including labels and provider export files.
Each explained policy also reports `usedQueues`, `decidingProfiles`,
`eligibleDecidingProfiles`, and `dependencyScope`. The report lists every
project clock, calendar, and trusted producer at project level. The policy's
`dependencies` retain the whole-project access-profile, queue, team, and inbox
closure; the narrower usage lists do not change binding scope.

`v1alpha2` makes `usedQueues`, `decidingProfiles`,
`eligibleDecidingProfiles`, and `dependencyScope` required on every explained
policy, and makes project-level `clocks`, `calendars`, and `trustedProducers`
required on every successful `explain` report. Consumers of `v1alpha1` must
accept the `v1alpha2` namespace and these required members together.

Regenerate or verify the contract from the repository root:

```sh
python3 products/casework/scripts/generate_cli_schemas.py
python3 products/casework/scripts/generate_cli_schemas.py --check
```

The generator has no separate hand-maintained field definitions. The focused
Rust report tests validate actual offline command outputs against this schema
and reject unknown payload fields before serialization.
