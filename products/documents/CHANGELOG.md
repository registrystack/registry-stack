# Registry Document Store changelog

## Unreleased

The Document Store is held out of releases.

- The product skeleton: `registry-documents-core`, the `registry-documents`
  runtime and `documents` binary, `registry-documentsctl` and the
  `documentsctl` binary, and the `registry-documents-client` Rust client.
- `DocumentsProject` and `DocumentsRuntimeConfig` formats at `v1alpha1`, with
  generated JSON Schemas, starter examples, and `documentsctl check`.
- The runtime checks its whole configuration before it binds, confirms its
  database answers, and serves only `GET /health`; every other route answers
  `request.not-found`.
- The `registry-documents` problem vocabulary is published in the identifiers
  catalog.
