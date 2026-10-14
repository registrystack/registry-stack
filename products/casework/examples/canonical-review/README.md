# Canonical review authoring example

This project combines a submitted-context decision with a BReg Proposal review. The checked-in schema is the exact `correct-address` review-context schema exported by the maintained BReg example. The producer contract ID, revision and file digest in `casework.yaml` match those bytes.

Run `caseworkctl check products/casework/examples/canonical-review` offline. Before packaging for a connected runtime, build the matching BReg package and run `caseworkctl provider pair products/casework/examples/canonical-review --provider-id facility-proposal-context --breg-package BREG_PACKAGE --action-id correct-address --apply`. Pairing writes the governed context export and pins the producer registry revision. Then configure `runtime.yaml` with `contextProviders.facility-registry` transport and a purpose-specific `casework-review-status` service credential. The human selects an authorized BReg source profile per request. Recheck and package Casework; use the actual compiled policy binding in requests.

The source schema is vendored for offline policy compilation. BReg remains the authority for current human disclosure and reviewability. A Casework service credential never supplies displayed fields.
