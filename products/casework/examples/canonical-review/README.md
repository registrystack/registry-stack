# Canonical review authoring example

This project combines a submitted-context decision with a BReg Proposal review. The checked-in schema is the exact `correct-address` review-context schema exported by the maintained BReg example. The producer contract ID, revision and file digest in `casework.yaml` match those bytes.

Create this project with `caseworkctl init ./review --template canonical-review`,
then run `caseworkctl check ./review` offline. The installed template includes
the owner-authored policy, vendored context schema, local teaching clients,
and offline editor schemas.

Before packaging for a connected runtime, build the matching BReg package and run:

```sh
caseworkctl provider pair ./review --provider-id facility-proposal-context \
  --breg-package BREG_PACKAGE --action-id correct-address --apply
```

Pairing verifies the native source, Action and context contract against the
already vendored schema and exact pins, then writes the provider description.
The registry revision is diagnostic metadata; unrelated package changes do not
change the accepted context binding. Configure `runtime.yaml` with
`contextProviders.facility-registry`
transport and a purpose-specific `casework-review-status` service credential.
The human selects an authorized BReg source profile per request. Recheck and
package Casework. A producer may select the policy by ID, or supply its compiled
version and digest as a strict expectation. Each accepted review keeps the
concrete policy binding.

For a connected synthetic local demonstration, `bregctl examples review
./reviewed-session --approve` composes the installed facility and canonical
review templates and their public CLIs. The explicit flag uses Casework's normal
staff decision API. Without it, the review remains pending. The source keeps
its own disclosure and application authority throughout.

The source schema is vendored for offline policy compilation. BReg remains the authority for current human disclosure and reviewability. A Casework service credential never supplies displayed fields.
