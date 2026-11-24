#import "@preview/zebra:0.1.0": qrcode

#let envelope = json(bytes(sys.inputs.data))
#let d = envelope.data
#let L = envelope.labels.en
#let signing = envelope.at("signing", default: none)
#let test-seal = signing != none and signing.testOnly
#let signer-name = if signing == none { none } else { signing.at("signerName", default: L.at("fallback-signer")) }
#let status-title = if signing == none { L.at("title-unsigned") } else if test-seal { L.at("title-test-seal") } else { L.at("title-seal-preview") }
#let status-label = if signing == none { L.at("status-unsigned") } else if test-seal { L.at("status-test-seal") } else { L.at("status-seal-preview") }
#let status-note = if signing == none [
  #L.at("unsigned-note")
] else if test-seal [
  #L.at("test-seal-authority") #signer-name. *#L.at("test-seal-note")*
] else [
  #L.at("seal-authority") #signer-name. #L.at("seal-preview-note")
]
#let ink = rgb("#182e30")
#let teal = rgb("#215652")
#let muted = rgb("#395b58")
#let rule-color = rgb("#adbeb8")
#let wash = rgb("#edf4f0")
#let mono = "DejaVu Sans Mono"
#let small(body) = text(font: mono, size: 8.5pt, tracking: 0.35pt, body)
#let month-names = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December")
#let parts = envelope.issuedAt.slice(0, 10).split("-").map(int)
#let extract-date = str(parts.at(2)) + " " + month-names.at(parts.at(1) - 1) + " " + str(parts.at(0))
#let areas = (:
  "https://example.invalid/areas/northbridge": "Northbridge",
)
#let locality = areas.at(d.area, default: d.area)
#let verify-url = d.at("verify-url")
#let verify-parts = verify-url.split("?ref=")
#assert(verify-parts.len() == 2 and verify-parts.at(1) == d.reference, message: "verification URL reference must match the document reference")
#let manual-url = verify-parts.at(0)
#let detail(label, value) = block(width: 100%)[
  #grid(columns: (4.7cm, 1fr), column-gutter: 12pt, align: left + horizon,
    text(size: 10pt, fill: muted)[#label],
    text(size: 11.5pt, weight: "semibold")[#value],
  )
  #v(2pt)
  #line(length: 100%, stroke: 0.45pt + rule-color)
]

#set document(title: L.title + " (" + status-title + ")", author: L.authority)
#set page(paper: "a4", margin: (x: 2.15cm, top: 1.35cm, bottom: 1.25cm))
#set text(font: ("Libertinus Serif", "DejaVu Sans Mono"), size: 12pt, fill: ink, lang: "en")
#set par(leading: 0.68em, spacing: 0.95em)

#line(length: 100%, stroke: 2.2pt + teal)
#v(4pt)
#grid(columns: (1fr, auto), align: left + horizon,
  text(size: 15pt, weight: "semibold")[#L.authority],
  box(fill: wash, inset: (x: 9pt, y: 5pt), small[#status-label]),
)
#v(0.5cm)

#text(size: 30pt, weight: "bold", tracking: -0.35pt)[#L.title]
#v(1pt)
#text(size: 12.5pt)[#L.subtitle]
#v(0.35cm)

#block(width: 100%, inset: (x: 14pt, y: 10pt), fill: wash, stroke: (left: 3pt + teal))[
  #text(fill: muted, small[#L.at("registered-person")])
  #v(1pt)
  #text(size: 24pt, weight: "bold")[#d.at("forename") #d.at("surname")]
  #v(2pt)
  #grid(columns: (auto, 1fr), column-gutter: 11pt, align: horizon,
    text(size: 10pt, fill: muted)[#L.at("person-number")],
    text(font: mono, size: 11pt)[#d.at("record-number")],
  )
]
#v(0.35cm)

#text(size: 17pt, weight: "semibold")[#L.at("register-details")]
#v(4pt)
#detail(L.at("given-name"), d.at("forename"))
#detail(L.at("family-name"), d.at("surname"))
#detail(L.at("jurisdiction"), locality)
#detail(L.at("register"), L.at("register-name"))
#detail(L.at("extract-prepared"), extract-date)

#v(0.3cm)
#text(size: 17pt, weight: "semibold")[#L.at("verify-heading")]
#v(4pt)
#grid(
  columns: (1fr, 34mm),
  column-gutter: 18pt,
  align: (left + top, center + top),
  block(width: 100%, inset: (x: 12pt, y: 9pt), fill: wash, stroke: 0.45pt + rule-color)[
    #text(fill: muted, small[#L.at("document-reference")])
    #v(2pt)
    #text(font: mono, size: 10pt, weight: "semibold")[#d.reference]
    #v(6pt)
    #text(fill: muted, small[#L.at("manual-lookup")])
    #v(2pt)
    #text(font: mono, size: 8.5pt, fill: teal)[#link(manual-url)[#manual-url]]
    #v(3pt)
    #text(size: 8pt, fill: muted)[#L.at("manual-lookup-help")]
  ],
  block(width: 34mm)[
    #align(center)[
      // The QR carries only the opaque verification URL and test reference, never record fields.
      #link(verify-url)[#qrcode(verify-url, width: 28mm, quiet-zone: true, background-fill: white)]
      #v(3pt)
      #text(size: 8.5pt, fill: muted)[#L.at("scan-to-verify")]
    ]
  ],
)

#v(1fr)
#block(breakable: false)[
  #line(length: 100%, stroke: 0.9pt + teal)
  #v(4pt)
  #text(size: 11.5pt, weight: "bold")[#L.at("about-heading")]
  #v(1pt)
  #text(size: 9.5pt)[#L.at("fictional-prefix") #status-note]
]
