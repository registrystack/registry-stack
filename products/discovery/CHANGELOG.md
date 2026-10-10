# Changelog

## Unreleased

- BREAKING: `origins.yaml` and mapping files are read by the shared
  configuration reader. They refuse `${...}`, unknown, duplicate, and null
  keys, and a repeated `evidenceTypeIds` entry, at the line and column of
  each; each file holds at most 1 MiB (a mapping file was allowed 20 MiB,
  and a mapping above 1 MiB is not supported in this release) and
  `catalogUrl` at most 2048 characters.
- BREAKING: the index opens with
  `apiVersion: id.registrystack.org/formats/discovery/index/v1alpha1` and
  `kind: DiscoveryIndex`. Rebuild every package with `discoveryctl package`
  and repin `package.expectedDigest`.
- BREAKING: `discoveryctl check` prints the shared diagnostics and a summary
  line, writes the shared ctl report with `--format json`, and checks one
  runtime file (`--runtime-config`) or one index (`--index`) on its own.
- The origins, evidence-mapping, and runtime JSON Schemas are generated from
  the reader types and take their identifiers on id.registrystack.org.

Migration steps and the diagnostic code table:
`release/notes/config-conventions/discovery.md`.
