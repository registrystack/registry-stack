#let payload = json(bytes(sys.inputs.data))
#let d = payload.data
#let signing = payload.at("signing", default: none)
#set document(title: [Notice #d.reference])
#set text(font: "Libertinus Serif", size: 11pt, lang: "en")
#set page(paper: "a5", margin: 2cm)

#text(size: 15pt, weight: "bold")[Notice #d.reference]
#v(0.6em)
#d.body

#v(1fr)
#if signing != none [
  #box(stroke: 0.6pt + black, inset: 8pt)[
    *Electronically sealed* by #signing.at("signerName", default: "the issuing authority").
    #if signing.testOnly [ \ TEST SEAL: not a valid official document. ]
  ]
]
Issued #payload.issuedAt, document version #payload.document.version.
