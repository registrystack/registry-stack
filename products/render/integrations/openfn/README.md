# OpenFn standalone integration

`registry-render serve` is callable from a plain OpenFn job; no App Kit involved.
This integration was walked end to end (real OpenFn CLI, real `registry-render
serve`, real breg dev registry with a least-privilege reader profile) against
an earlier BReg release. It has not been re-walked against the current Record,
Action, and Proposal model, so use the current BReg examples for the read-back
step.

Deployment shape:

1. Run the binary with a runtime file (verified package, loopback bind, API
   key in an owner-only file, audit file or `stdout` destination):
   `registry-render serve --runtime-config /etc/registry-render/runtime.yaml`
2. Put the API key *value* in the job's private configuration (kit
   precedent: `notification.json`), beside the breg reader token and the
   delivery adaptor's key.
3. Use `receipt-job.js` as the starting point: configuration validation,
   bridge-envelope destructuring, `parseAs: "json"`, status checks,
   minimized return.
4. Read document data back through breg with a reader access profile whose
   `readableFields` equal the template's data contract; lifecycle events
   project only the record id. breg exposes field ids as camelCase HTTP
   property names, so the job carries a reviewed camelCase→schema-key
   table and refuses any projection that is not exactly the contract.

Why the JSON variant exists: OpenFn's `util.request` parses bodies as text,
so raw PDF bytes would be corrupted in transport; `Accept:
application/json` returns `{pdfBase64, pdfDigest, dataDigest,
documentVersion, warnings}` plus the deprecated bare hex `pdfSha256` and
`dataSha256`, which `receipt-job.js` still reads. `Idempotency-Key` is correlation-only — deterministic
rendering is the real idempotency, so the event bridge's at-least-once
redelivery and dead-letter replays can never issue conflicting documents.
