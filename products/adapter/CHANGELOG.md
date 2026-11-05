# Registry Adapter changelog

## Unreleased

- BREAKING: the configured `govstack-consultation` profile, the
  `dhis2-govstack` example and its fixtures are removed. A deployment moves to
  the built-in GovStack Consultation profile by declaring a `consultation:`
  section in its project (see `examples/dhis2-consultation`). A configured
  profile that names itself `govstack-consultation` no longer gets any
  GovStack behaviour.
- BREAKING: the `dhis2-tracker` pack's `page-tracked-entities` and
  `page-tracked-entities-by-org-unit` routes take a required
  `tie_breaker_attribute` parameter, the UID of a unique program attribute.
  They page by `createdAt:desc,<attribute>:asc` because DHIS2 2.43 refuses
  `trackedEntity` as a sort key. Add the parameter to each templated route
  that uses them and re-lock the project.
- Remove the `range`, `set-membership` and `prefix` source comparisons, which
  no pack used. Only `equality` remains.
- BREAKING: `asyncCompletion.mode` is renamed `asyncCompletion.type` in an
  Adapter project binding. There is no alias and the project `apiVersion` is
  unchanged, so a project that still writes `mode` is refused at that key
  with `config.removed-key`, which names `type` as the replacement. Rename
  the member and keep its value (`status-link` or `bounded-wait`).
