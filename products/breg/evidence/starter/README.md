# BReg assertion authoring fragment

This directory is an authoring fragment, not a complete EvidenceProject and not
an `evidencectl init --starter` input. First initialize `../offline-starter` and
import the explicit registry's Source as described in the parent README.

Copy `functions/` and `fixtures/` into the editable project's corresponding
directories. In its existing `evidence.yaml`, append the `functions` entries and
merge the `assertionDefinitions` entries from `definitions.yaml.fragment`.
This is ordinary authoring, not a separate import format. Do not replace the
existing Sources, selector profiles, Functions or offline definition.

`record-active` answers one boolean using `by-code`. `record-status-pair` uses
`by-registration-number` and releases the reviewed active/retired pair. Both
reference the imported `registry-status` Source and have their own fixtures.
A new complete target generated with `target new --local` gives each definition
an explicit local grant; review that authority separately from source credentials.
