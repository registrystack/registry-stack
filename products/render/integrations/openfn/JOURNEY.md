# OpenFn journey record (walked 2026-09-17)

The DoD's OpenFn row, walked end to end without the App Kit: a job in the
kit's tested idiom reads record data back through a least-privilege breg
reader profile whose readable fields equal the template data contract,
renders via `Accept: application/json`, delivers the PDF, and a dead-letter
replay produces byte-identical output.

## What ran

| Piece | Version / shape |
| --- | --- |
| OpenFn CLI | 1.40.1 (`openfn execute`, kit-style flags: `--no-autoinstall --no-expand-adaptors --no-cache-steps`) |
| Adaptor | `@openfn/language-common` 3.3.4 (`util.request`, `parseAs: "json"`) |
| render | this repo's binary, `render serve` on loopback: sealed receipt bundle, API key + audit key in owner-only files |
| breg | v0.32.0 dev stack (`bregctl dev`: PostgreSQL + ThunderID issuer + registry, all loopback) |
| job | `receipt-delivery.js` (this directory), notify.js idiom |

## breg side (least-privilege read-back)

An authored project extends the domain-neutral example's `record` entity
with the receipt template's twelve data-contract fields and a reader
profile:

```yaml
# accessProfiles entry
- id: record-reader
  requiredScopes: [registry:generic:read]
  requiredPurposes: [registry-reporting]
  permissions:
    - entity: record
      operations: [get]          # no list, no filterable fields
      readableFields: [reference, payer-name-ar, payer-name-fr, payer-nni,
                       wilaya, amount, currency, date, method-ar,
                       purpose-ar, verify-url, bidi-note]
      rowBoundaries:
        - {field: status, claim: registry_record_status, operator: equals}
```

breg exposes field ids under camelCase HTTP property names
(`payerNameAr`); the job maps that spelling to the template's kebab-case
JSON Schema keys with an explicit, reviewed table and refuses any
projection whose key set is not exactly the contract. A seeded record
(`code: WALK-RECEIPT-000123`, `status: active`) carries the public example
fixture values. `bregctl check` passes; the project's schema-test journey
suite passes (the reader row-boundary steps were updated to `get`
semantics: within the claim → 200, outside after retire → 404
`resource.not_found`).

A reader GET by `recordIdentifier` returns exactly:

```
domainData keys: amount, bidiNote, currency, date, methodAr, payerNameAr,
                 payerNameFr, payerNni, purposeAr, reference, verifyUrl, wilaya
```

No `code`, `label`, `group`, or `status` reaches the renderer. An
operator GET on the same record returns all sixteen fields — the narrowing
is the profile's, not the caller's.

## Walked sequence (same event, same `eventEffectId` throughout)

1. **Happy delivery.** `bregctl dev token reader` mints a 5-minute
   client-credentials token; the job validates configuration, destructures
   the bridge envelope (`state.data = {event, data}`), refuses to invent
   `issuedAt` (uses `transition.at` = the fixture issuance time), reads the
   record back through `record-reader`, renders with
   `Accept: application/json` + `Idempotency-Key: eventEffectId`, and
   delivers the `pdfBase64` to the delivery endpoint. Exit clean; final
   state is minimized: `{data: {receipt: {sha256, version}},
   eventEffectId}` — no token, key, or record data.
   - `pdfSha256` = `ce939b77f78cadda7183ad6ea9207c366a7b579c01cbff73a42f44293b356398`
     — the pinned golden hash from `products/render/golden.json`, i.e. the
     same bytes the CLI, the tests, and the two-OS CI job produce.
   - Delivered bytes on disk hash to the same value.
2. **Delivery outage (dead-letter).** The delivery endpoint returns 503;
   the job aborts after rendering with an `AdaptorError` in the output
   state; nothing is delivered. The render is already recorded in the
   audit ledger.
3. **Recovery replay.** Same event, same `eventEffectId`, fresh reader
   token (production replay shape: credentials rotate, the event does
   not). The job succeeds and delivers a second PDF.
   - `cmp` of the two delivered PDFs: byte-identical.
4. **Read-back negative.** An unknown `recordIdentifier` fails the
   read-back (`404 resource.not_found`); nothing is rendered or delivered.

## Audit ledger

`render audit-verify` (after graceful shutdown; a live writer legitimately
limits verification to sealed segments): **3 record(s) across 1
segment(s)** — one per render attempt including the dead-lettered one.
Every record carries `correlationId` = the job's `eventEffectId`, the
golden `pdfSha256`, and the golden `dataSha256`
(`26bdfa19b95178dc17fe5826cd43dd26b74f29cf0b69e77f61a69b19beaea4dc`).
`Idempotency-Key` stays correlation-only: the byte stability is what makes
at-least-once redelivery safe.

## Why this is the DoD's row and not more

The bridge that dead-letters and replays effects is the kit's event-bridge
(`run.mjs`/worker); the OpenFn CLI execution here replays the same
semantic (identical event + effect id, rotated credential) against the
real job. The delivery endpoint is a loopback sink that records delivered
bytes — an email/SMS adaptor would sit in the same slot with the same
contract.
