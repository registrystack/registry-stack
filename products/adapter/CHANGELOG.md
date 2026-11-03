# Registry Adapter changelog

## Unreleased

- BREAKING: `asyncCompletion.mode` is renamed `asyncCompletion.type` in an
  Adapter project binding. There is no alias and the project `apiVersion` is
  unchanged, so a project that still writes `mode` is refused at that key
  with `config.removed-key`, which names `type` as the replacement. Rename
  the member and keep its value (`status-link` or `bounded-wait`).
