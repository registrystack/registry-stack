# G2P disbursement project

This project accepts one approved instruction record identity, asks the bound
Adapter payment connection to submit it, waits for the named `disbursement`
completion, and reports an exact provider confirmation back to the owning
instruction registry. Coordinator never receives the amount, recipient
destination, funding account, provider request, or provider evidence.

The three outcomes are deliberately narrow:

- `confirmation-recorded` returns the Adapter's exact `ProviderConfirmation`.
  It means the pinned provider reported completion and the owning instruction
  was updated. It does not claim end-recipient credit or final settlement.
- `disbursement-failed` returns the verified failed provider observation. It
  does not report a confirmation or authorize a replacement submission.
- `disbursement-unresolved` has no output. A wait timeout, or an accepted,
  pending, or unknown observation, does not prove failure and must not start a
  new disbursement.

An uncertain `request-disbursement` is held and cannot use `retry-same`.
Reconcile it only through the Adapter's read-only lookup for the exact saved
instruction and key. An uncertain `record-provider-confirmation` may use
`retry-same`, which resends only the saved reporting command under its saved
key. Neither recovery path permits a fresh provider submission.

## Check and package

From the repository root, use binaries built from this checkout:

```sh
coordinatorctl check --project products/coordinator/examples/g2p-disbursements --explain
coordinatorctl test --project products/coordinator/examples/g2p-disbursements
coordinatorctl package \
  --project products/coordinator/examples/g2p-disbursements \
  --output /absolute/private/g2p-disbursements-package
```

Copy `runtime.yaml` outside the package. Replace its package root and digest,
database URLs, PostgreSQL role, issuer, JWKS source, Adapter and token
endpoints, listener, secret root, and audit path. The payment connection must
select an Adapter connection whose own policy resolves the approved
instruction and provider binding. Give Coordinator only the Adapter payment
capability. Keep instruction-read and provider-reporting grants with the
Adapter reporter identity.

Start a run with `input.example.json` after replacing the synthetic UUID and
version with the exact immutable instruction record. Use a unique admission
key and the currently reported `workflowRevision`. Status belongs to the
admitting caller; inspection and recovery use the separately authorized
operator identity.

After a terminal run, accept only named outcome `confirmation-recorded` and
verify its instruction record ID, instruction ID and version, disbursement ID,
binding revision, exact money, provider reference, simulation marker, and
provider-result digest before any downstream service proceeds.
