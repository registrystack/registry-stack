# Registry Coordinator changelog

## Unreleased

- Registry Coordinator is a new, optional product for controlled
  institutional pilots. The `coordinator` service executes one activated
  workflow package: a finite, acyclic plan whose steps are `wait-until`,
  `call`, `choose`, and `finish`, with bounded pure Rhai functions for field
  mapping and branch selection. PostgreSQL 17 or newer holds each run, its
  encrypted input, outputs, and prepared commands. `README.md` is the
  orientation, `PILOT-CONTRACT.md` the supported boundary, and
  `DEPLOYMENT.md` the runbook.
- A `call` step names one of eight operations, each reached through the
  maintained client of the product that owns the effect: `read-record` and
  `invoke-breg-action` (Base Registry Engine), `submit-message` (Messaging),
  `read-scheduling`, `read-availability`, and `create-appointment`
  (Scheduling), `external-get` (an operator-configured HTTP read), and
  `evaluate-decision` (an operator-configured decision service). The
  receiving product authorizes every call; the Coordinator inherits none of
  its authority and writes to no other product's database.
- Five formats carry the shared envelope:
  `id.registrystack.org/formats/coordinator/project/v1alpha1`
  (`CoordinatorProject`, `workflow.yaml`),
  `id.registrystack.org/formats/coordinator/runtime/v1alpha1`
  (`CoordinatorRuntimeConfig`, `runtime.yaml`),
  `id.registrystack.org/formats/coordinator/scenarios/v1alpha1`
  (`CoordinatorScenarios`, `scenarios.yaml`),
  `id.registrystack.org/formats/coordinator/definition-snapshot/v1alpha1`
  (`CoordinatorDefinitionSnapshot`, the definition a package seals), and
  `id.registrystack.org/formats/coordinator/ctl-report/v1alpha1`
  (`CoordinatorCtlReport`, the `--format json` report). The three authored
  files are read by the shared Registry Stack reader, and their JSON Schemas
  are published under `generated/`.
- `coordinatorctl` authors and operates a deployment. `init`, `check`,
  `explain`, `test`, `package`, and `openapi` run offline. `plan`, `apply`,
  and `deployment-status` read the runtime file and the database; only
  `apply` migrates, and the service never migrates at startup. `start`,
  `status`, `list`, `inspect`, `retry-same`, `cancel`, `reconcile`, `doctor`,
  `restore-hold`, `release-restore-hold`, `release-admission-hold`,
  `complete-execution-recovery`, and `retain` call the authenticated HTTP
  API. Exit codes are 0 for accepted input, 1 for refused input, 2 for
  command usage, and 3 for an unavailable resource.
- The HTTP API serves `/health`, `/ready`, and the `/v1` routes that
  `generated/openapi/coordinator.openapi.json` describes. Every refusal
  carries one code of the form `coordinator.<area>.<condition>`, written the
  same way in the HTTP answer and the `coordinatorctl` report.
- The Coordinator has no export in `@registrystack/client` or the Python
  client. An application calls the HTTP API.
- `SECURITY-REVIEW-NOTES.md` lists the authentication, authorization,
  custody, and audit facts of this first release.
