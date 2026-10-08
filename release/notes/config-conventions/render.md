# Registry Render: configuration conventions

Track: small products (Discovery, Render, Manifest, platform tooling files).

Render is experimental, so its spellings are normalized in this release
rather than held for the stable release.

## BREAKING changes

1. **The bundle manifest moves to id.registrystack.org and names its
   files.** `manifest.yaml` opens with
   `apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1` (was
   `render.registrystack.org/v1alpha1`), and each document writes
   `entryFile` and `schemaFile` (were `entry` and `schema`). The previous
   apiVersion is refused with `config.retired-api-version`, and the previous
   keys with `config.removed-key`. Migration: change the `apiVersion` line,
   rename each document's `entry:` to `entryFile:` and `schema:` to
   `schemaFile:`, keeping their values.
2. **Each label table gets an envelope.** `labels/<locale>.yaml` opens with
   `apiVersion: id.registrystack.org/formats/render/labels/v1alpha1` and
   `kind: RenderLabels`, and its keys move under `labels:`. A table without
   the envelope is refused with `config.missing-envelope`. Migration: add
   the two envelope lines at the top of each table, then a `labels:` line,
   and indent the existing keys by two spaces under it. The template receives
   the same flat key-to-text map, so templates and PDF bytes are unchanged.
3. **Document ids, label locales, and label keys are local identifiers**:
   a lowercase letter, then up to 63 lowercase letters, digits, `-`, or `_`
   (`config.invalid-value` at the offending id, locale, or key). Ids and
   locales were lowercase kebab-case of any length, which also allowed a
   leading digit or `-`; label keys were any text. Migration: rename an id,
   locale, or key that starts with a digit or `-`, holds an uppercase letter
   or `.`, or is longer than 64 characters, and the template lookups and
   locale requests that use it.
4. **The manifest and label tables are read by the shared reader.** They
   refuse `${...}` with `config.substitution-not-allowed` (CFG-SEC-2), and an
   unknown, duplicate, or null key with `config.unknown-key`,
   `yaml.duplicate-key`, or `config.null-value`, each at its line and column;
   a repeated locale is `config.duplicate-item` and a repeated document id
   `config.duplicate-id`. Each file holds at most 1 MiB. Migration: correct
   the file as each diagnostic names.
5. **Failure output carries the shared diagnostics.** A refused bundle
   prints `registry-render: <sentence>` and then every diagnostic in the
   shared shape (`error[code] file:line:col /pointer`, the message, then
   `next:` with the fix) and a summary line; every missing or refused file in
   the bundle is reported in one run instead of the first. With `--json` the
   RFC 9457 problem document carries the same findings as a `diagnostics`
   array. Problem kinds and exit codes are unchanged. Migration: a script
   that matched the previous free-text `detail` should read `diagnostics`
   instead.
6. **Package digests move.** A bundle rewritten to the new spellings has
   new bytes, so its package digest changes. Migration: rebuild with
   `registry-render package --bundle <source> --output <new directory>` and
   copy the printed digest into `package.expectedDigest` if you pin it.

## Other changes

- `registry-render init` writes the new spellings and puts the
  `# yaml-language-server: $schema=...` line first in the manifest and in
  each label table (CFG-SCHEMA-7). It refuses a `--locale` that is not a
  local identifier.

## Diagnostic codes, old to new

Before this release no Render configuration finding carried a code: each
failure was one problem document whose `detail` was a sentence, with the
kind and exit code below. The kinds and exit codes are unchanged; the
findings now ride in `diagnostics` with these codes.

| Before (problem kind, sentence) | Code now |
|---|---|
| `manifest-invalid`, `manifest.yaml is not valid: ...` | the reader's `yaml.*` and `config.*` codes, for example `yaml.duplicate-key`, `config.unknown-key`, `config.null-value`, `config.missing-key`, `config.missing-envelope`, `config.duplicate-id`, `config.duplicate-item` |
| `manifest-invalid`, `manifest apiVersion must be ...` / `manifest kind must be ...` | `config.retired-api-version`, `config.unsupported-api-version`, `config.wrong-kind` |
| `manifest-invalid`, `manifest.yaml key hashes is no longer accepted ...` | `config.removed-key` |
| `manifest-invalid`, `document id must be lowercase kebab-case ...`, `label name must be kebab-case ...` | `config.invalid-value` |
| `manifest-invalid`, `duplicate document id ...` | `config.duplicate-id` |
| `manifest-invalid`, `... entry must be a .typ path inside the bundle` | `render.bundle.invalid-entry-file` |
| `manifest-invalid`, `... schema must be a .json path inside the bundle` | `render.bundle.invalid-schema-file` |
| `manifest-invalid`, an environment expression in the manifest | `config.substitution-not-allowed` |
| `manifest-invalid`, entry file absent from the bundle | `render.bundle.missing-entry-file` |
| `manifest-invalid`, schema file absent or not JSON | `render.bundle.missing-schema-file`, `render.bundle.invalid-schema` |
| `labels-invalid`, label table absent | `render.bundle.missing-labels` |
| `labels-invalid`, label table not a string map | the reader's codes, for example `config.missing-envelope`, `config.expected-string`, `config.invalid-value` |
| `labels-invalid`, key sets diverge across locales | `render.labels.missing-key` |
| `font-invalid`, a bundle font cannot be loaded | `render.font.invalid` |
| `font-invalid`, no font draws a label character | `render.labels.uncovered-character` |
