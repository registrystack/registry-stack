# Registry Document Store changelog

## Unreleased

First release of the Document Store: custody of document bytes for an owning
system, exact-version document grants, content verification before release,
scheduled erasure, and after-commit document events, served over `/v1/` with
`documentsctl` for operators. The product is held out of releases until it is
published. Under citizen delivery the reserving system sees a document's
metadata and status only: it cannot grant, read the bytes, or list the grants
(`GET /v1/documents/{documentId}/grants` is the custodian's alone and answers
the reserving system `profile.not-authorized`), so the issuer never learns
whom the citizen shared with.
