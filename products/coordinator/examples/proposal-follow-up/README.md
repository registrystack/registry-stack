# Proposal application follow-up project

Use this synthetic project to start an exact Base Registry Engine (BReg) Action as a Proposal,
submit its draft separately, wait for application evidence, and then request a separate Messaging
notice. Review approval alone does not release the notice.

From the repository root:

```sh
coordinatorctl check --project products/coordinator/examples/proposal-follow-up --explain
coordinatorctl test --project products/coordinator/examples/proposal-follow-up
```

The `facilities` contract import is the owning BReg-generated Action export. `start-correction`
selects `correct-address` through that import and pins its revision, Proposal mode, review policy,
application policy, input, output, and declared refusals. The owning public fixture is
`products/breg/examples/coordinator-actions`; regenerate and review its Action export when its
contract changes rather than copying a schema into the workflow.

The workflow performs these separate stages:

1. `start-draft` invokes the exact Action and returns a draft under `proposal`. A validated
   declared refusal finishes `correction-refused` without submission.
2. `submit` passes that draft to `breg.submit-proposal/v1`, freezing its submission identity.
3. `await-application` waits on `completion: {step: submit, name: application}` for fourteen days.
   The observer requires the exact Proposal, Action revision, submission version, and effect digest.
4. An authoritative `applied` completion reaches `notify`, which submits the independently
   authorized notice. A `closed` completion finishes `proposal-closed` without a notice.
5. Timeout finishes `application-wait-expired`. BReg may continue its own work; this outcome neither
   cancels the Proposal nor establishes application failure.

Blocked, mismatched, unknown, and uncertain evidence stays held. Unknown submission does not begin
application observation. Recovery retains the original preparation and identity, acquires current
product authority, and preserves observation floors and deadlines. A refused notice leaves the
BReg application intact. Messaging acceptance is distinct from delivery.

The institution supplies a BReg profile and identity authorized for the exact Action, Proposal
submission, and application observation, with the exported review/application policy configured
in the owning products. Messaging independently authorizes its sender, template, and recipient.
Caller policies separately authorize this Workflow and operator recovery. The runtime template
uses synthetic HTTPS endpoints and secret references; adapt it outside the package and follow the
[deployment runbook](../../DEPLOYMENT.md).

Offline cases cover application, closure, timeout, declared refusal, notice refusal, and unknown
submission. They do not prove a real reviewed Proposal journey. The owning Casework/BReg checkpoint
integration remains required before this example can claim native reviewed-path acceptance.
