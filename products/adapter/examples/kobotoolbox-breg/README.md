# BReg project for the direct KoboToolbox job

This is the Base Registry Engine (BReg) half of the direct job in
[`../kobotoolbox-job/`](../kobotoolbox-job/README.md). It holds what the job's
destination needs on the BReg side:

- the `household` record type, with a `sourceSubmissionId` lookup;
- the `register-household` Action, a Proposal with inputs `sourceSubmissionId`,
  `respondentName` and `householdSize`, the same inputs the job-owned mapping
  `register-household.rhai` produces;
- the `ingestion` access profile that `job.yaml` names, for a service client
  `adapter-kobo-ingestion` with scope `registry:write`, limited by a row
  boundary to the records it owns; and
- the Proposal review setting, `review: {type: none}`.

The files are synthetic. Change the project id, base IRI, client id, scope and
the `owner` value in `scripts/register-household.rhai` to your deployment's,
and keep them equal to the destination binding in the runtime file.

## Review policy

`review: {type: none}` applies the Plan when the job submits the Proposal, with
no human review. It suits a synthetic trial. For a pilot that needs a person to
approve, use `type: required` with a review authority, as in
`products/breg/examples/reviewed-change/registry.yaml`. The ingestion service
starts and submits the Proposal, so the review policy must accept a service
initiator. A policy that requires a human initiator refuses the Proposal before
any task exists. Do not relax a production policy only to copy this example.

## Check it

From the repository root:

```sh
cargo run --locked -p registry-bregctl -- check products/adapter/examples/kobotoolbox-breg
```

The check reads the project only. It does not start BReg or contact an
identity provider. Package the project, apply it, and bind the
`adapter-kobo-ingestion` client with the operator steps in
[`products/breg`](../../../breg/README.md). Then run the direct job as
[the Kobo runbook](../kobotoolbox-job/OPERATIONS.md) describes.
