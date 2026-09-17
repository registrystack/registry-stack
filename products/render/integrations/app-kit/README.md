# App Kit integration sketch (`registry-documents` skill)

The kit-side capability follows the kit's extension anatomy (brief rows →
config → host route → page → walked journey). This file is the stack-side
contract the kit skill implements; it lands in the App Kit repository when
the capability is built there.

## Brief rows (agreed before any template is written)

Paper is a disclosure surface: fields printed on a document leave every
access profile behind, and the QR prints a public verify URL. The skill's
brief must carry `agreed` rows for:

- which fields appear on each document type (the field list is the
  decision, not a rendering detail);
- the reliance/verification wording printed next to the QR;
- where the QR points (the host's public origin, the
  `registry-public-check` answer contract on the verify page);
- who signs off each bundle version (`registry-render seal` + review).

## Config (host, `taskDispatch` precedent)

```
APP_DOCUMENTS_FILE=/path/to/documents.json
```

`documents.json` maps document types to loopback destinations with
credential files — exact loopback paths, no query or fragment, secrets read
from files at load, mirroring the kit's task-dispatch configuration:

```json
{
  "receipt": {
    "url": "http://127.0.0.1:3200/v1/render/receipt",
    "credentialFile": "/secrets/render-api-key"
  }
}
```

The bundle lives under `project/deployment/render/bundle/` so the kit's
writes-stay-in-`project/` boundary holds; `deployment/local.py` supervises
`registry-render serve` beside breg and casework.

## Host route (one block, the established pattern)

page → app-runtime hook → host `POST /api/documents/{type}/render` →
session-authorized breg reads assemble `data` (the end user's token; no
service account) → loopback call to `registry-render serve`
(Accept: application/pdf) → stream the PDF to the browser, or upload as a
breg attachment and store
`pdfSha256`/`dataSha256` on the record. The verify URL (record-held
unguessable token) is assembled by the host and passed as data; the QR is
the template's job.

## Journey to walk (DoD row)

A staff user prints a receipt from a record → the PDF attaches to breg with
matching sha256 fields → scanning the QR resolves the verify page.
`COMPLETED with 0 flags` per the kit gate.
