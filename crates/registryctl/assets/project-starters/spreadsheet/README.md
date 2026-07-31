# Spreadsheet Registry Stack project

This starter publishes a protected records API from the synthetic workbook in
`data/public_works_projects.xlsx`.

From this project directory:

```bash
registryctl -C . tooling editor
registryctl -C . test
registryctl -C . dev --environment local --detach
registryctl -C . dev --environment local smoke
registryctl -C . dev --environment local down
registryctl -C . check --environment local --explain
registryctl -C . build --environment local
```

Adapt the workbook under `data/`, then keep `entities/projects.yaml`,
`environments/local.yaml`, and the explicit API projection aligned with its
`Projects` sheet. `project_file` is the contained authoring source checked by
preflight. `path` is the read-only container path emitted to Registry Relay.

Spreadsheet fields start as sensitive and are published only when they are
listed in `api.projection`. Review the service purpose, sensitivity,
access-rights classification, and projection before using real data.

The authored `local` environment selects the synthetic `match` fixture for the
project snapshot integration, so `registryctl dev` needs no integration or
fixture flags. Generated development lanes under `.registry-stack/dev-artifacts/`
and bound runtime state under `.registry-stack/dev/` are disposable, ignored by
Git, and are not production inputs.
