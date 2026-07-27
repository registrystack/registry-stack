# Spreadsheet Registry Stack project

This starter publishes a protected records API from the synthetic workbook in
`data/public_works_projects.xlsx`.

From this project directory:

```bash
registryctl authoring editor --project-dir .
registryctl test --project-dir .
bash checks/validate-negative-workbooks.sh
registryctl preflight --project-dir . --environment local
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

`registryctl test` reports `PASS: 0/0 fixtures passed` because this records-only
project has no source-integration fixtures. The maintained negative-workbook
check uses temporary project copies to prove that duplicate primary keys and
formula-bearing sources fail through Registry Relay's production XLSX
validation. It does not modify this project or print workbook values.

Adapt the workbook under `data/`, then keep `entities/projects.yaml`,
`environments/local.yaml`, and the explicit API projection aligned with its
`Projects` sheet. `project_file` is the contained authoring source checked by
preflight. `path` is the read-only container path emitted to Registry Relay.

Spreadsheet fields start as sensitive and are published only when they are
listed in `api.projection`. Review the service purpose, sensitivity,
access-rights classification, and projection before using real data.
