# Generated business identifiers

The UUID in each BReg record envelope remains the stable record identity.
Use a generated `string` field for an institution-facing number or code. It is
readable like an ordinary field, but callers and Actions cannot set or patch it.
Do not grant it in `writableFields` or a Function write ceiling.

Add `generate` to a stored `string` field. The complete
[acceptance project](acceptance/generated-identifiers/registry.yaml) shows both
strategies and a Proposal Action:

```yaml
- id: number
  type: string
  required: true
  minimumLength: 6
  maximumLength: 32
  classification: internal
  generate: {type: sequence, prefix: "APP-", minimumDigits: 4, scope: [jurisdiction]}
- id: code
  type: string
  required: true
  minimumLength: 12
  maximumLength: 12
  classification: internal
  generate: {type: random, prefix: "REF-", length: 8}
```

`sequence` allocates `APP-0001`, `APP-0002`, and so on within each distinct
`jurisdiction`. `minimumDigits` pads the number but does not cap the sequence;
the field's `maximumLength` must fit its full range. `random` generates the
specified number of characters after the prefix. Its default alphabet is
`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`; `alphabet` can replace it with distinct
printable ASCII characters. Choose enough length for the expected number of
records. BReg retries a collision within a bounded attempt count and refuses
the create if the code space cannot supply a free value.

`scope` lists required stored scalar fields. BReg includes their values in
both the allocation namespace and a database uniqueness constraint. Omit it
for one namespace across that Record type. Include the scope fields when
looking up a scoped identifier, since the same code can exist in another scope.
The compiler limits the combined maximum size of the identifier field and its
scope fields to a 1 KiB index budget. For string and text fields, it counts
four bytes per character to cover UTF-8 values, including retained identifiers
seeded during migration. Use short keys for scope fields rather than descriptions.
A scope field cannot change after
the record is created, because moving a number to another namespace would
invalidate its issued meaning. Issued values are never recycled, including
after a record is tombstoned or erased. Sequences are monotonic, not gapless.

Direct create, batch/import create, and Action create allocate in the write
transaction. A Proposal allocates on Submit and freezes the exact values in
its reviewed effects. A replay of Submit, Apply, or Retry reuses those values.
Revising and submitting again can allocate fresh values; canceled or replaced
values remain reserved.

For a new registry, the compiler installs allocation state and the unique
constraint with the initial schema. Enabling generation on a field in an
existing registry requires a reviewed migration. Backfill any missing values
first, then the compiler seeds reservations and sequence high-water marks from
retained rows and checks uniqueness before activation. Existing identifiers
are preserved. Changing or removing an active generation rule is currently
unsupported, so plan prefix, scope, and alphabet as part of the issuing scheme.
