# Audit activation and package identity

`activationId` is the UUID of the activation under which an operation is
observed. `packageRevision` is a `sha256:` package digest. Neither name is an
alias for the other. An audit record may omit a field it does not carry.

The following schema versions use `activationId` in place of the previous
misnamed `packageRevision` activation field:

| Event class | Schema |
| --- | --- |
| Requests, terminal responses, refusals, unfinished responses and Review recovery | `breg-audit/v3` |
| History erasure | `breg-history-erasure-audit/v3` |
| History rebaseline | `breg-history-rebaseline-audit/v3` |
| Field encryption maintenance | `breg-field-encryption-audit/v3` |
| Attachment verification | `breg-attachment-verification-audit/v3` |
| Evidence retention | `breg-evidence-retention-audit/v2` |
| Hook delivery attempts and transitions | `breg-hook-audit/v1` |
| Receipt retention | `breg-idempotency-retention-audit/v2` |
| Attachment cleanup | `breg-attachment-cleanup-audit/v2` |
| Access-log exemption | `breg-access-log/v2` |
| Import authority transitions | `breg-import-authority-audit/v2` |

Import authority transitions also carry `authorityActivationId`, the activation
that originally opened the authority. On supersession it differs from the
current `activationId`; both identities remain observable. An unfinished response
preserves the attempt's identity. Hook delivery records
name the activation captured with the delivery, including retained work from
an earlier activation. `packageRevision` remains reserved for package digests.

This is an audit-field contract change only. Except as stated below,
reference-hash domain strings, context inputs and their values remain
unchanged, including Review recovery
and import authority operator/reason references. Historical schema versions
retain their historical interpretation; readers must branch on the schema.

Hook delivery entries are one exception. `breg-hook-audit/v1` replaces
`breg-webhook-audit/v3`, every entry carries `"event": "breg.hook-delivery"`,
and the keyed event and delivery references are derived under the
`breg-hook-event-v1` and `breg-hook-delivery-v1` domains. A reference written
under the earlier `breg-webhook-*` domains does not match one written under
the hook domains for the same delivery, so a reader joining hook delivery
entries across the change must branch on the schema.

Attachment verification entries are the second exception.
`breg-attachment-verification-audit/v3` replaces
`breg-attachment-verification-audit/v2` with the same record fields, and the
keyed verification reference is derived under the
`breg-attachment-verification-v2` domain from the verification id and the
lease token of the attempt, in place of the `breg-attachment-verification-v1`
domain over the content digest, content type, and lease id. A reference
written under the earlier domain does not match one written under the later
domain for the same verification, so a reader joining verification entries
across the change must branch on the schema.

The committed `crates/registry-breg/tests/fixtures/audit-identity-goldens.json` pins the identity
field projection for every affected event class. The PostgreSQL harness checks
those goldens and identity value types on captured audit entries
across request and operator journeys. The Evidence-retention regression refuses
an activation under `packageRevision`; the import-authority supersession journey
pins both the current and original activation. Existing hash and audit-pairing
assertions continue to apply.

Read authorization refusals may carry `refusalReason` with one of three fixed
values: `surface_unavailable`, `profile_admission`, or `select_overreach`.
These distinguish unavailable authorized surfaces, profile admission refusals,
and withheld or unknown projection fields. They contain no claim, purpose,
field, credential, or Record value and do not change the caller's response.
A refusal without one of these causes may omit the field.
