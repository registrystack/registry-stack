// Bilingual (ar/fr) payment receipt — acceptance document for Registry
// Render. Exercises RTL typesetting, mixed-script lines, justification, a
// bundled Arabic font, and an offline QR package.
#import "@preview/zebra:0.1.0": qrcode

// The renderer injects the canonical envelope as `sys.inputs.data`.
#let payload = json(bytes(sys.inputs.data))
#let d = payload.data
#let L = payload.labels

#set text(font: ("Noto Sans", "Noto Naskh Arabic"), size: 10pt, lang: "ar")
#set page(paper: "a5", flipped: true, margin: 13mm,
  footer: context [
    #set text(size: 7pt, lang: "fr")
    #line(length: 100%, stroke: 0.4pt + gray)
    #v(-1em)
    #grid(
      columns: (1fr, auto),
      [#text(fill: gray)[#L.ar.footnote — #L.fr.system-generated]],
      text(fill: gray)[#payload.document.id v#payload.document.version],
    )
  ])

// ---- header: institution + title, QR verification block --------------------
#grid(
  columns: (1fr, auto),
  align: (right, top),
  text(lang: "ar")[
    #text(size: 15pt, weight: "bold")[#L.ar.institution]
    #v(0.35em)
    #box(stroke: 0.6pt + black, inset: (x: 6pt, y: 3pt))[
      #text(size: 12pt, weight: "bold")[#L.ar.title]
    ]
  ],
  grid(
    columns: (auto, auto),
    column-gutter: 8pt,
    align: center,
    qrcode(d.verify-url, width: 20mm, quiet-zone: true),
    text(size: 6.8pt, lang: "fr")[*#L.fr.verify* \
      #text(fill: gray)[#d.verify-url] \
      #v(0.4em) \
      #text(fill: gray)[#L.fr.ref: #d.reference]],
  ),
)

#v(0.8em)

// ---- parties: payer (Arabic name, Latin NNI) -------------------------------
#text(lang: "ar")[
  *#L.ar.payer:* #d.payer-name-ar \
  *#L.ar.nni:* #d.payer-nni — *#L.ar.wilaya:* #d.wilaya
]
#v(0.5em)
#text(lang: "fr", size: 8.5pt, fill: gray)[
  #L.fr.payer: #d.payer-name-fr · NNI: #d.payer-nni
]

#v(1.2em)

// ---- amount table -----------------------------------------------------------
#grid(
  columns: (1fr, auto, auto, auto),
  inset: 6pt,
  stroke: 0.5pt + black,
  fill: (x, y) => if y == 0 { luma(235) },
  text(lang: "ar")[*#L.ar.details*], text(lang: "ar")[*#L.ar.amount*],
  text(lang: "ar")[*#L.ar.date*], text(lang: "ar")[*#L.ar.method*],
  text(lang: "ar")[#d.purpose-ar], text(lang: "fr", weight: "bold", size: 12pt)[#d.amount #d.currency],
  [#d.date], text(lang: "ar")[#d.method-ar],
)

#v(1fr)

// ---- bidi line: Arabic sentence with embedded Latin reference ---------------
#align(right)[
  #set par(justify: true)
  #text(lang: "ar")[
    #d.bidi-note
  ]
]
