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
  "version": "0.44.0-dev",
  "project": "./review-project",
  "policyBindings": [],
  "filesChecked": 1,
  "networkAccess": false,
  "databaseAccess": false,
  "diagnostics": []
}
```

[report.schema.json](report.schema.json) is the command-tagged union of the
owning Rust output DTOs. Command-specific members are flat; a failure carries
the common envelope and diagnostics, and may either omit command-specific
members or carry one complete typed command payload. Partial payloads are
invalid. The commands are
`init`, `check`, `explain`, `test`, `types`, `provider-add`, `provider-pair`, `lifecycle`,
`package`, `doctor`, `plan`, `apply`, `status`, `dev`, `dev-events`, `dev-token`,
`dev-grant`, `dev-identity`, and `usage`; `internal` is the closed failure-only
variant used when a hidden command or panic stops unexpectedly. Dev and
provider-add reports expose their command result as `outcome`; the envelope
`status` remains the process result class.

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
