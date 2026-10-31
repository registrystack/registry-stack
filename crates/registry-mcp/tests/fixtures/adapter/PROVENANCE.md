# Adapter compatibility fixture

The golden effective contract was emitted by the real `adapter effective-contract`
command from Adapter commit
`8c43e6ce6eda1220f4bda73d706eb0ff9b5fa1a8`.
It used this directory's `runtime.yaml` and `govstack-facilities/project.yaml`
with the producer's pinned `govstack-consultation` profile and
`dhis2-tracker` pack.

The export uses only synthetic identifiers and secret placeholders. It opens
no listener and contacts no database, issuer, or source. The compatibility test
pins both the complete file bytes and the producer-computed contract digest.
Regenerate it only with the exact producer revision named above, or update this
record and the fixed expectations together after reviewing producer drift.

The `breg-facilities/project.yaml` fixture proves the same non-person facility
data configuration through the second supported facade. Native tests keep the
actual Adapter binary and tracked producer fixtures outside this repository.

The `optional-pagination` fixture was emitted by the same producer revision.
Its local profile differs only by omitting `pageSizeDefault` from the
read-only POST search, which makes the producer export its anchored
cursor-or-page-size presence schema. The fixed export exercises consumer
compatibility with that real producer shape.
