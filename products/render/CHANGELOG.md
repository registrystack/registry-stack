# Changelog

## Unreleased

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
- Rebuild every package with `registry-render package` and repin
  `package.expectedDigest`: the maintained example digests moved, and their
  PDF and data hashes did not.

Migration steps and the diagnostic code table:
`release/notes/config-conventions/render.md`.
