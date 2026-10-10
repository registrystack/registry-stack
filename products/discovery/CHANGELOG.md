# Changelog

## Unreleased

- BREAKING: the Node.js and Python bindings carry the transport kind
  `response-too-large` (was `response_too_large`), the word the shared HTTP
  primitives now write (CFG-NAME-2). Migration: compare against the new
  word. No file an adopter writes changes.
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
- BREAKING: the Node and Python Discovery bindings spell `DiscoveryClientError`
  `kind` values (`no-matching-service`, `ambiguous-selection`,
  `no-matching-alternative`, `ambiguous-alternative`, `capability-mismatch`,
  `local-acceptance-refused`, `selection-changed`) and `problem` values
  (`invalid-request`, `not-found`, `result-bound-exceeded`) in kebab-case.
- The origins, evidence-mapping, and runtime JSON Schemas are generated from
  the reader types and take their identifiers on id.registrystack.org.
- BREAKING: `runtime.yaml` declares
  `apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1`.
  The earlier `registry.registrystack.org/discovery-runtime/v1alpha1` is
  refused as `config.retired-api-version` at `/apiVersion`, and the message
  names the replacement. Edit the first line of every runtime file.
- BREAKING: `origins.yaml` and mapping files open with `apiVersion` and
  `kind` instead of `schemaVersion`: an origins file writes
  `apiVersion: id.registrystack.org/formats/discovery/origins/v1alpha1` and
  `kind: DiscoveryOrigins`, a mapping file
  `apiVersion: id.registrystack.org/formats/discovery/evidence-mapping/v1alpha1`
  and `kind: DiscoveryEvidenceMapping`. `schemaVersion` is refused as
  `config.removed-key`, and the message names the two lines to write.
  Replace the first line of each file; the packaged index is unchanged.
- BREAKING: the two `runtime.yaml` timeouts are written in milliseconds.
  `limits.requestTimeoutSeconds` is `listener.requestTimeoutMilliseconds`
  and `limits.shutdownTimeoutSeconds` is `limits.shutdownGraceMilliseconds`,
  each from 1000 to 300000. The old keys are refused as
  `config.removed-key` with the replacement named. Move the request timeout
  under `listener`, rename both keys, and multiply each value by 1000.

Migration steps and the diagnostic code table:
`release/notes/config-conventions/discovery.md`.
