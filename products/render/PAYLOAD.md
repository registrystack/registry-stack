# What a template receives

One page for template authors. The renderer injects exactly one input,
`sys.inputs.data`, as a JSON string. Those bytes are the RFC 8785
canonicalization of the envelope below, and the sha256 of those exact bytes
is the `dataSha256` the caller should store on the record.

```typst
#let payload = json(bytes(sys.inputs.data))
#let d = payload.data
#let L = payload.labels.ar
```

## The envelope

```jsonc
{
  "data":   { /* your request data, validated against the document's schema */ },
  "assets": { "photo": "<base64>" },   // request images; served to the
                                       // template as virtual files:
                                       // image("/assets/photo")
  "labels": { "ar": { … }, "fr": { … } }, // every label table the document
                                          // declared in its manifest
  "locale": "ar",                      // present only when the request
                                       // sent one (validated)
  "issuedAt": "2026-09-16T10:32:00Z",  // the document's issuance claim;
                                       // also the world clock and PDF date
  "document": { "id": "receipt", "version": 3 }
}
```

Rules worth internalizing:

- **`labels` is bundle-owned content** — flat YAML string maps under
  `labels/<locale>.yaml`, listed in the manifest's `labels: [...]`. The
  template receives every declared table, so a bilingual document consumes
  both. A key present in one locale and missing from another is a `registry-render
  check` error, not a runtime surprise; a key no locale declares is a
  template error at compile time.
- **`assets` values are the base64 text as received.** The template never
  decodes them — reference the decoded image as `image("/assets/photo")`
  (leading slash: the assets namespace sits at the bundle root). Hashing
  covers the exact bytes.
- **`issuedAt` is the clock.** `datetime.today()`, `set document(date:
  auto)`, and the PDF creation date all derive from it. A re-render with
  the same `issuedAt` and data is byte-identical; changing it changes
  bytes. The instant is normalized to UTC (`2026-09-16T13:32:00+03:00`
  and `2026-09-16T10:32:00Z` are the same render): the caller's UTC
  offset is deliberately not preserved — the envelope carries the `Z`
  form only. A local-date layout can still shift the instant:
  `datetime.today(offset: 3)` answers "what date is it 3 hours after
  issuance". The offset is total hours, so fractional values work and
  land at full-second precision; an offset large enough to overflow the
  shift answers `none` rather than panicking.
- **`document.version` is the template's own version** from the manifest —
  print it on paper if you like. The renderer version appears nowhere in
  the envelope or the PDF bytes.
- **Data is inert.** Values are Typst values, never evaluated; a string
  that looks like code is just a string.
- **Paths are contained.** `image()`/`read()` resolve only inside the
  bundle (and the virtual `/assets/…` namespace); `..`, absolute paths,
  and symlink escapes are refused by the renderer's world.

## Authoring loop

Edit templates freely with upstream tooling (tinymist/VS Code give live
preview if you point them at the bundle). `registry-render compile` runs
unsealed bundles with a notice; `registry-render seal` writes the manifest
hashes; `registry-render serve` requires the sealed bundle.
`registry-render check` verifies everything,
including that every label character is drawable by some bundle or baseline
font — a successful render that prints tofu is wrong on paper, so coverage
gaps are named at check time and warnings fail `--strict` at render time.

See `bundles/` for three complete working examples (bilingual RTL receipt,
PDF/A certificate, ID-1 card with photo). Ground truth when in doubt:

```bash
registry-render compile … --emit-envelope env.json   # the exact injected bytes
```
