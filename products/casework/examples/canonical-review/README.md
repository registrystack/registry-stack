# Canonical review authoring example

This project combines a submitted-context decision with a BReg Proposal review. The checked-in schema is the exact `correct-address` review-context schema exported by the maintained BReg example. The producer contract ID, revision and file digest in `casework.yaml` match those bytes.

Create this project with `caseworkctl init ./review --template canonical-review`,
then run `caseworkctl check ./review` offline. The installed template includes
the owner-authored policy, vendored context schema, local teaching clients,
and offline editor schemas.

For a connected runtime, build the matching BReg package and pair it before
packaging Casework.

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

## Approve an exact task as Staff

Run `bregctl --format json examples review ./reviewed-session` to start the
connected demonstration and leave the Proposal pending. Set `CASEWORK_URL`
and `CASEWORK_PROJECT` to `caseworkUrl` and `caseworkProject` from its JSON
report. Run `caseworkctl --format json dev token staff "$CASEWORK_PROJECT"`
to refresh the reviewer's owner-only header file, and set `STAFF_HEADER` to
the returned `headerFile` path. The file carries the bearer and Casework profile.

With that header file and `Registry-Source-Profile: proposal-reviewer`, read
`GET /v1/review-tasks` and inspect the selected task's current context at
`GET /v1/review-tasks/{taskId}/context`. Set `TASK_ID` to the UUID you reviewed.
The facility example admits this reviewer with Casework's `staff` profile and
BReg's `proposal-reviewer` profile, which requires `registry:proposal:review`.

From the directory containing this README, run the
[staff example](approve-task.sh) with Bash, `curl` and `jq`.

```sh
bash ./approve-task.sh "$CASEWORK_URL" "$TASK_ID" "$STAFF_HEADER" proposal-reviewer
```

The script reads and claims that task with its quoted `If-Match` revision.
It verifies that the claim returned the same task in the held state and uses
that holding's revision as `If-Match` for the decision. If the task changes in
between, the decision is refused. Both writes carry an `Idempotency-Key`.
The open-task requests send `Registry-Source-Profile` so BReg can enforce
current disclosure for this reviewer.

After HTTP 204, the script reads `GET /v1/review-tasks/{taskId}` with the
same Staff header and checks `decidedByCaller` before printing
`decisionReceipt`. The retained receipt uses current Casework authority.
If the decision response is lost, read that exact task with the same
reviewer identity and check the receipt before attempting another write.

## Show review progress to the applicant

On your copy of the paired facility project, enable `readableReviewProgress: true`
on the `facility-correction-author` grant for `correct-address`.
That grant already declares `ownership: caller` and `get-review-status`.
In the paired Casework project, configure the stages of `facility-address-review`
with the codes you want applicants to see.

```yaml
stages:
  - id: address-review
    publicProgressCode: initial-verification
    queue: facility-addresses
    decidingProfiles: [staff]
    excludeInitiator: true
    requiredApprovals: 1
  - id: address-validation
    publicProgressCode: final-validation
    queue: facility-addresses
    decidingProfiles: [supervisor]
    excludePreviousStageReviewers: true
    requiredApprovals: 1
```

Make sure the second stage has an eligible supervisor.
Recheck and package both projects, and update any strict review policy pin to
the new binding for future submissions.
Start and submit the Proposal as the applicant.
Using only that applicant's BReg credential, read
`GET /v1/proposals/{id}/review-status?accessProfile=facility-correction-author&include=progress`.
After acceptance, the first stage supplies `initial-verification`.
Approve the first task as Staff using the procedure above, then read the same
BReg URL to see `final-validation`.
Omit a stage's `publicProgressCode` when its status should stay internal.
If progress is absent, show the handoff and result from the same response.

The paired PostgreSQL test drives the real BReg and Casework HTTP routes through
both stages and a return and resubmission.
With `BREG_TEST_DATABASE_URL` and `CASEWORK_REVIEW_TEST_DATABASE_URL` set to
disposable PostgreSQL databases, run from the Registry Stack checkout.

```sh
cargo test --locked -p registry-casework --features postgres-test \
  --test breg_review_journey native_proposal_requires_pinned_casework_approval_before_breg_apply
```
