# BReg public check authoring fragment

This directory is an authoring fragment, not a complete EvidenceProject and not
an `evidencectl init --starter` input. It shows a public check that reads a
registry through a `bregctl generate evidence-source --public-check` export.

The parent registry has no check code. Add a string field with id `check-code`
and API name `checkCode`, 24 characters long, to the `record` type, and make it
readable by the access profiles that read `status`. Then export the Source:

```sh
bregctl generate evidence-source ./registry \
  --access-profile evidence-source --record-type record \
  --selector by-code --fields status,check-code \
  --source-id registry-check --connection registry \
  --authentication oauth2-private-key-jwt --public-check \
  --output ./registry-check-export
evidencectl source import ./registry-check-export --project ./evidence
```

Copy `functions/`, `fixtures/` and `schemas/` into the editable project's
corresponding directories. In its existing `evidence.yaml`, merge the
`functions` and `assertionDefinitions` entries from `definitions.yaml.fragment`.

`record-check` declares `publicCheck` with `check-code` as its check code fact.
Declaring it opens nothing. A target authority activates the route with
`publicCheck: {definition: record-check}`.

Evidence compares the check code only after the Source returns a record. The
export therefore states each fact's type and nothing else, and the derive
Function checks content after the comparison. It maps `active` to `valid` and
`retired` to `revoked`, and refuses any other status. The fixtures run the
relying path. They cover a record issued before check codes existed, a status
outside the vocabulary, a mistyped status and a returned identity that differs
from the request.

`evidencectl check` refuses this definition over an export made without
`--public-check` (`public-check-facts-content`).
