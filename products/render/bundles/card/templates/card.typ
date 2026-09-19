// ID-1 (CR80, 85.6×54 mm) beneficiary card, duplex — acceptance document
// for Registry Render. Exercises fixed card geometry, a photo carried in
// the request (virtual `assets/photo`), and the offline QR package.
#import "@preview/zebra:0.1.0": qrcode

#let payload = json(bytes(sys.inputs.data))
#let d = payload.data
#let L = payload.labels

#set text(font: ("Noto Sans", "Noto Naskh Arabic"), size: 6.5pt, lang: "ar")
#set page(width: 85.6mm, height: 54mm, margin: 4mm)

// ---------------- front ----------------
#grid(
  columns: (auto, 1fr, auto),
  column-gutter: 5pt,
  align: (top, top, top),
  // Photo from the request, served as a virtual file by the renderer.
  box(stroke: 0.5pt + black, clip: true)[
    #image("/assets/photo", width: 17mm)
  ],
  text(lang: "ar")[
    #box(stroke: 0.4pt + black, inset: (x: 3pt, y: 1pt), fill: luma(230))[*#L.ar.title*]
    #v(0.3em)
    *#L.ar.name:* #d.name-ar \
    *#L.ar.id:* #text(lang: "fr")[#d.id] \
    *#L.ar.region:* #d.region \
    *#L.ar.category:* #d.category \
    #v(0.25em)
    #text(lang: "fr", size: 6pt)[#d.name-fr]
  ],
  align(top, qrcode(d.verify-url, width: 15mm, quiet-zone: true)),
)
#v(1fr)
#grid(
  columns: (1fr, auto),
  text(lang: "ar", size: 6pt)[#L.ar.program · #L.ar.valid: #text(lang: "fr")[#d.valid-until]],
  text(lang: "fr", size: 5.5pt, fill: gray)[#text(lang: "fr")[#d.reference]],
)

// ---------------- back ----------------
#pagebreak()
#grid(
  columns: (1fr, auto),
  align(top)[
    #box(stroke: 0.4pt + black, inset: (x: 3pt, y: 1pt), fill: luma(230))[*#L.ar.title* — *#L.fr.title*]
    #v(0.4em)
    #set par(justify: true)
    #text(lang: "ar", size: 6pt)[#d.bidi-note]
    #v(0.5em)
    #text(lang: "fr", size: 6pt, fill: gray)[#L.fr.call-center]
  ],
  align(top, box(stroke: 0.5pt + black, clip: true)[
    #image("/assets/photo", width: 12mm)
  ]),
)
#v(1fr)
#align(right, text(lang: "fr", size: 5.5pt, fill: gray)[#text(lang: "fr")[#d.verify-url]])
