# Changelog

## Unreleased

- BREAKING: A runtime configuration file is refused with
  `platform.runtime-config.unsafe-file` when it or an ancestor directory is not
  owned by root or the runtime user, or is writable by group or others. A
  root-owned sticky ancestor stays allowed.

## 0.44.0 - 2026-10-27

- `registry-render check --bundle` reads an optional
  `check-acceptances.yaml`. An exact, reasoned acceptance keeps its warning
  visible while allowing `--deny-warnings` to pass; errors remain refusals.
- Add shared OIDC resource-token authentication to the serving adapter, with
  `render:render` scope and cached signing-key readiness. Legacy API keys remain
  available. Audit callers fingerprint the exact verified credential.
- BREAKING: HTTP problem codes change from bare Render slugs to `render.*`
  codes in the shared six-member envelope. HTTP details use fixed safe guidance;
  local CLI diagnostics retain their detail and existing exit codes. Missing
  scope returns 403, unavailable verification returns 503, and unknown routes
  return a typed 404. Their new CLI categories use exits 23, 24 and 25.
- Add bounded Rust, Node and Python serving clients with validation before token
  acquisition, canonical token-provider errors, and explicit transport outcome
  uncertainty. Default unified packages retain the seven-product roster;
  `--include-render` adds Render to explicit local candidates while its
  release-client hold remains in place.
- Document the observed v0.43.0 native and emulated worker results, their differing
  inputs and environment, and the unresolved cause of the emulator failure.
- PDF responses expose `X-Registry-Warning-Count`, including zero, so callers
  can withhold a PDF with render warnings. The JSON response retains warning
  details; headers contain only the count.
- Add Linux arm64 and macOS arm64 release packaging and a transactional installer.
  The macOS archive retains the FIPS library beside the executable.
## 0.43.0 - 2026-10-21

- BREAKING: label values now use the shared display-text rules and refuse Unicode
  controls that can invisibly reorder human-readable text while retaining
  multilingual joiners and direction marks.
- BREAKING: a bundle now refuses document ids or label keys that differ only by `-`
  versus `_` in one namespace and reports both authored definitions.

## 0.42.0 - 2026-10-20

- `registry-render init` prints a first render command that runs as printed
  from any directory: its `--data` path names the scaffold's own fixture.

## 0.41.0 - 2026-10-13

- No user-visible product changes in this release.

## v0.40.0 - 2026-10-11

- Runtime file flags use the help text "Runtime configuration file" and
  show `ABSOLUTE_FILE` wherever an absolute input path is required.

- A label table with no envelope is told the whole shape: after the envelope
  lines, write the label keys as a mapping under `labels:`.
- BREAKING: `manifest.yaml` opens with
  `apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1`, and each
  document names its files with `entryFile` and `schemaFile` in place of
  `entry` and `schema`. The previous apiVersion and keys are refused with a
  diagnostic naming the replacement.
- BREAKING: each `labels/<locale>.yaml` opens with
  `apiVersion: id.registrystack.org/formats/render/labels/v1alpha1` and
  `kind: RenderLabels` and holds its keys under `labels`. Label keys,
  document ids, and label locales are local identifiers: a lowercase letter,
  then up to 63 lowercase letters, digits, `-`, or `_`.
- BREAKING: the manifest and label tables are read by the shared
  configuration reader. They refuse `${...}`, unknown, duplicate, and null
  keys, and a repeated locale, at the line and column of each; every missing
  or refused file in a bundle is reported in one run, and a failure prints
  the reader's diagnostics after Render's own sentence (`--json` adds them
  to the problem document as `diagnostics`).
- BREAKING: `runtime.yaml` opens with
  `apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1` and
  takes the shared member names: `listener.shutdownGraceMilliseconds` (the
  seconds value times 1000), `limits.maximumOutputBytes`,
  `limits.maximumRequestBytes`, `limits.maximumConcurrentRenders`, and
  `audit.retentionDays`. The previous apiVersion and keys are refused with a
  diagnostic naming the replacement.
- BREAKING: every runtime limit is bounded: `renderTimeoutSeconds` is 1 to
  3600, and `maximumOutputBytes` and `maximumRequestBytes` are at least 1.
- BREAKING: a refused runtime file prints every finding in the shared
  diagnostic shape on standard error, each at its line and column. A public
  `listener.bind` is refused wherever the file is read, not only when serve
  starts.
- BREAKING: `bundleVersion` and each document's `version` count from 1; 0 is
  refused with `config.out-of-range`.
- BREAKING: `registry-render check` is the offline check. It reports every
  finding in the shared diagnostic shape with a summary line, writes one
  `RenderCtlReport` document under `--format json`, takes
  `--deny-warnings`, and exits 0, 1 (refused), 2 (usage), or 3 (unreadable
  input) in place of the problem kind's code (3, 4, 7, 8, or 20).
  `--runtime-config` alone checks the runtime file without a package or
  secret, and `--environment` substitutes `${VAR}` from the current
  environment. `--require-audit-under` takes an absolute directory and
  needs `--runtime-config`. Every YAML file in a bundle is identified by its
  envelope: a file of another kind is refused by `check` and `package`, and
  an unused label table or a file without an envelope is a warning. A link
  on an `entryFile` or `schemaFile` path is refused at that member, before
  any finding about the package as a whole.
- JSON Schemas for the bundle manifest, label tables, and runtime file are
  generated from the reader types under `products/render/schemas`, and
  `editors/configure.py render` maps them.
- Rebuild every package with `registry-render package` and repin
  `package.expectedDigest`: the maintained example digests moved, and their
  PDF and data hashes did not.

Migration steps and the diagnostic code table:
`release/notes/config-conventions/render.md`.
