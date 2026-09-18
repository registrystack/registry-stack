// Archival registration certificate — acceptance document for Registry
// Render. Monolingual, PDF/A-4, rendered with the binary's baseline font
// set only (the bundle carries no fonts): the minimal-bundle guarantee.
#import "@preview/zebra:0.1.0": qrcode

#let payload = json(bytes(sys.inputs.data))
#let d = payload.data
#let L = payload.labels.en

#set text(font: ("Libertinus Serif", "DejaVu Sans Mono"), size: 11pt, lang: "en")
#set page(paper: "a4", margin: 2.4cm)

#align(center)[
  #text(size: 10pt, tracking: 2.5pt)[REGISTRY]
  #v(0.2em)
  #text(size: 22pt, weight: "bold")[#L.title]
  #v(1.2em)
]

#align(center)[
  #box(inset: (x: 14pt, y: 10pt), stroke: 0.8pt + black)[
    #text(size: 14pt)[#d.recipient-name]
  ]
]
#v(1.6em)

#align(center)[
  #block(width: 78%, text(size: 10.5pt, align(center)[#L.body-1 #L.body-2]))
]
#v(2.4em)

#grid(
  columns: (1fr, auto),
  grid(
    columns: (auto, auto),
    inset: 8pt,
    align: (right, left),
    stroke: 0.5pt + luma(160),
    text()[*#L.recipient:*], text()[#d.recipient-name],
    text()[*#L.identifier:*], text()[#d.registry-identifier],
    text()[*#L.recorded:*], text()[#d.recorded-date],
    text()[*#L.valid-until:*], text()[#d.valid-until],
    text()[*Reference:*], text()[#d.reference],
  ),
  grid(
    columns: (auto,),
    align: center,
    qrcode(d.verify-url, width: 24mm, quiet-zone: true),
    text(size: 7.5pt, fill: gray)[#d.verify-url],
  ),
)

#v(1fr)

#grid(
  columns: (1fr, auto),
  text(size: 8.5pt, fill: gray)[
    #L.seal · #payload.issuedAt · #payload.document.id v#payload.document.version
  ],
  text(size: 8.5pt, fill: gray)[#d.reference],
)
