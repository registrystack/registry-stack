# Registry Document Store changelog

## Unreleased

- BREAKING: A runtime configuration file is refused with
  `platform.runtime-config.unsafe-file` when it or an ancestor directory is not
  owned by root or the runtime user, or is writable by group or others. A
  root-owned sticky ancestor stays allowed.
- Adopt the shared platform implementations for the access-token algorithm
  roster (still exactly RS256 and ES256), framework-rejection normalization
  (400, 413, 415 and 422 answer the same `request.*` problem codes) and the
  stop signal. `serve` refuses startup with the signal error when a stop-signal
  handler cannot be installed; SIGINT is now installed at startup alongside
  SIGTERM.

First release of the Document Store: custody of document bytes for an owning
system, exact-version document grants, content verification before release,
scheduled erasure, and after-commit document events, served over `/v1/` with
`documentsctl` for operators. The product is held out of releases until it is
published. Under citizen delivery the reserving system sees a document's
metadata and status only: it cannot grant, read the bytes, or list the grants
(`GET /v1/documents/{documentId}/grants` is the custodian's alone and answers
the reserving system `profile.not-authorized`), so the issuer never learns
whom the citizen shared with.

`documentsctl check --project` reads an optional `check-acceptances.yaml`,
keeps exactly matched warnings visible with their reasons, and excludes only
those accepted warnings from `--deny-warnings`.
