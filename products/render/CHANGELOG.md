# Changelog

## Unreleased

- Add optional PAdES document sealing. A document type names a `seal` in its
  manifest, and a `signing.seals` block in the runtime file binds each seal to
  a private key reference, a certificate chain file, a timestamp policy
  (`timestampAuthority` for baseline B-T, or the named `withoutTimestamp`
  choice for B-B) and the OIDC clients allowed to use it. With seals, `serve`
  adds `POST /v1/seal/{type}`, which needs the new `render:seal` scope (not
  implied by `render:render`; the legacy API key never seals) and returns the
  sealed PDF with `documentDigest` over the first revision,
  `signedFileDigest` over the whole file, `dataDigest`, the package's
  `packageDigest` in the form `package.expectedDigest` takes, and
  `seal.certificateDigest`, each labelled `sha256:<hex>` (on the PDF answer,
  `X-Registry-Document-Digest`, `X-Registry-Signed-File-Digest`,
  `X-Registry-Data-Digest`, `X-Registry-Package-Digest` and
  `X-Registry-Certificate-Digest`). The render worker answers
  with the first revision only, and `serve` writes the signature field after
  it, so `documentDigest` covers every byte the worker wrote; an answer that
  is not a single-revision PDF is refused. A failing timestamp fails the request
  and never falls back to B-B. Seals in flight, which hold no render slot
  while they sign and wait on the authority, are bounded by
  `limits.maximumConcurrentRenders`; one more is refused with `rate-limited`
  (429). On SIGTERM the drain waits for seals in flight as it does for
  renders, within `listener.shutdownGraceMilliseconds`. `/v1/documents` names each document type's served seal as
  `seal`. `/ready` adds a `signing` member per seal and
  stays ready while a seal is unavailable; `serve` logs a warning at startup
  for a seal that cannot sign or expires within 30 days. Audit entries add the value-free
  `sealId`, `documentDigest`, `signedFileDigest`, `certificateDigest` and
  `timestampTokenDigest`, labelled as in the answer; a `timestamp-failed` response entry adds `reason`,
  the value-free name of the failing check, which a `seal refused` log warning
  repeats. The payload gains a `signing` member on the seal route
  only. A seal declared `trust: test-only` says so in the JSON `seal`
  member, an `X-Registry-Seal-Test-Only` header, `/ready`, the audit and
  one startup warning, and the `init` scaffold prints the seal block with
  its test line. `registry-render-client` gains `RenderClient::seal`, whose
  `SealedDocument` carries `package_digest` and `seal.test_only`; its success
  bodies now tolerate members it does not know, on both routes, and its seal
  types are `#[non_exhaustive]`. Its `render` takes the same optional
  `correlation_key` as `seal`, sent as `Idempotency-Key` and checked when
  echoed, and `RenderClientError` reports an uncertain exchange through
  `is_outcome_unknown()` in place of a public field. The Node and Python
  bindings gain `seal`, and both methods there take the optional correlation
  key. `check --environment` reads each seal's certificate chain, and it and `serve` warn about a seal certificate whose extended key usage names no document-signing purpose, and refuse a chain file whose first
  certificate, taken as the seal certificate, is a CA certificate. veraPDF
  has passed a test template at every accepted PDF/A level and at PDF/UA-1,
  rendered and sealed (`EVIDENCE.md`). A seal key `serve` cannot read is refused with the secret provider's reason, and its text is erased once parsed. New problem
  kinds with exit codes: `signing-unavailable` (26), `seal-certificate-invalid`
  (27), `timestamp-failed` (28), `document-not-sealable` (29) and
  `seal-client-not-allowed` (30). Render writes PAdES baseline B-B and B-T
  signatures; `EVIDENCE.md` records the pyHanko, EU DSS and veraPDF runs on
  sealed files `serve` answered. Render makes no eIDAS qualification claim.
- Every supervised render worker (`serve` and `compile`) starts from an empty
  environment, keeping only the dynamic loader's library search paths, so a
  credential in the parent's environment is not passed to the process that runs
  template code. Worker tuning variables such as `RAYON_NUM_THREADS` or
  `MALLOC_ARENA_MAX` no longer reach the worker either.
- The render route's JSON answer adds `pdfDigest` and `dataDigest`, and its
  PDF answer `X-Registry-Pdf-Digest` and `X-Registry-Data-Digest`: the same
  hashes labelled `sha256:<hex>`, the form `package.expectedDigest` takes.
  `pdfSha256`, `dataSha256`, `X-Registry-Pdf-Sha256` and
  `X-Registry-Data-Sha256` are deprecated and still sent. The OpenAPI document
  marks them deprecated and now declares each route's response headers and
  JSON members. `compile --format json` adds `pdfDigest`, `dataDigest` and
  `packageDigest` beside `pdfSha256`, `dataSha256` and `bundleHash`.
  `registry-render-client`'s `RenderedDocument` gains `pdf_digest` and
  `data_digest`, which it requires and checks against the bare hex, so it
  needs a server from this release; the Node and Python bindings return
  them.
- `serve` reads a render worker's answer straight into its typed form,
  refusing a member it does not know at its name, so a malformed answer
  costs the serving process no more memory than the answer's own bytes.
- The default HTTP problem detail reads "The request was refused; ..." in
  place of "The render request was refused; ...", since the seal route
  answers it too. The problem codes are unchanged.
- The render timeout also bounds a worker's exit after it answers: a worker
  that does not exit, or leaves a process holding its standard error open, is
  killed at the deadline with a warning, and its answer is kept, so it no
  longer holds the request and its render slot.
- On Linux, `serve` marks itself non-dumpable at startup, before it reads any
  secret: it writes no core dump, and another process running as the same user
  cannot read its `/proc` environment or memory.

## 0.45.0 - 2026-11-03

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
