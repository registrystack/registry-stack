# Submit a Proposal with a required file

This project changes a target Record's name through a manual Proposal. Its
`support` slot requires one text file before Submit. The caller holds the
`clerk` profile and a direct `jurisdiction` claim matching the target.

Start the Proposal with `target` and `value`, then follow its attachment upload
link with a `text/plain` body. Before upload, Submit is unavailable with
`attachment-required` and recovery `correct-input`. Calling Submit still
answers `422 attachment.required` with `fieldPath: /attachments/support`.
Upload the file, read the updated Proposal, and follow its available Submit
link. Apply uses the exact submitted version and effect digest.

The committed `openapi.json` is generated from `registry.yaml`. Its Submit
responses include the required-file problem and verification outcomes.
The authoring check warns that `package.sourceRevision` is absent. Set it to
your source revision when preparing a production package.

From the repository root:

```sh
cargo run --locked -p registry-bregctl -- check products/breg/examples/required-attachment
cargo run --locked -p registry-breg --example example-artifacts -- \
  --output generated-required-attachment --project required-attachment
```
