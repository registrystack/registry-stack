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
- Rebuild every package with `registry-render package` and repin
  `package.expectedDigest`: the maintained example digests moved, and their
  PDF and data hashes did not.

Migration steps and the diagnostic code table:
`release/notes/config-conventions/render.md`.
