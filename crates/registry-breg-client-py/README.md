# registry-breg-client-py

Internal PyO3 binding for `registry-breg-client`. The release process bundles
this module into the public `registry-stack-client` wheel. It is not published
as a standalone PyPI project.

Use `action.with_reason(text)` on a promoted `reject_request` or
`request_revision` action to add optional reviewer text. It returns a copy and
validates before network effects. The original action omits the reason. Text
is preserved exactly, allows an empty string, and is limited to 4096 Unicode
characters with NUL refused. Reuse the same action and idempotency key for an
explicit retry.

## Request attachments

Governed binary slots are engine-owned. They are never set through create,
JSON Patch, or request effects. Select them from a caller-filtered contract,
then use the three exchanges the engine advertises.

```python
contract = client.registry_contract(profile)
slot, = contract.select_attachments("company", profile)
upload = slot.prepare_upload("application/pdf", data)
client.upload_attachment(slot, record_id, etag, upload, "upload-supporting-file-1")
stored = client.download_attachment(slot, record_id, proposal_version)
client.delete_attachment(slot, record_id, next_etag, "remove-supporting-file-1")
```

`slot` carries the served policy: `slot_identifier`, `required_for_submit`,
`maximum_bytes`, `content_types`, `accepts_content_type(value)`, and the
`can_download`, `can_upload`, and `can_remove` routes the caller's profile was
granted. `prepare_upload` refuses an empty body, a body larger than
`maximum_bytes`, and any content type outside `content_types` before a request
is built, so a refused upload never leaves the process. Uploads and removals
need the record's current ETag and a caller-chosen idempotency key, exactly like
`patch_record`.

`slot.value_in(record)` reads the engine-owned projection of the slot out of one
record mapping: a `kind` of `not_selected`, `empty`, or `filled`, with a `value`
holding `proposal_version`, `byte_size`, `sha256`, `content_type`,
`uploaded_at`, `uploaded_by`, `erased`, and `verification_status` when the slot
is filled.

A download requires the proposal version and returns the stored bytes with their
stored content type. A retained older value may carry a content type the current
policy no longer accepts. The response is bounded by both the slot capacity and
the client's `max_response_bytes`, so raise `max_response_bytes` when a slot may
hold more than the default bound.
