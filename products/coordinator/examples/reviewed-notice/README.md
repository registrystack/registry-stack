# Reviewed notice project

Use this synthetic example when a run must hand an application to human review
in Registry Casework, wait for the decision, and send a notice through Registry
Messaging only when the review approves it. The workflow, pure functions,
deterministic scenarios and runtime template form one complete project.

From the repository root, run the offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/reviewed-notice --explain
coordinatorctl test --project products/coordinator/examples/reviewed-notice
```

The run starts at once and has a `deadlineSeconds` of 2592000 (thirty days):

1. `submit-review` submits one review request of kind `application-review` to
   Casework as the review producer. The request names the application version
   and digest under review and submits the only context a reviewer sees, the
   application identifier and version, so Casework needs no source adapter.
2. `await-review` waits for the result of that request for at most fourteen
   days (`timeoutSeconds: 1209600`). Casework's completion event wakes the
   run; the event carries no result and only prompts a read. The Coordinator
   reads the result with the producer identity when the wait starts, on each
   wake and every `resultCheckSeconds` (900 in the runtime template) as a
   fallback, and keeps waiting while the review is open.
3. `decide` chooses on the result's `status`. `approved` continues to
   `notify`, `rejected` finishes with outcome `rejected`, and every other
   settled status (`changes-requested`, `answered`, `cancelled` and
   `superseded`) finishes with outcome `not-decided` and that status.
4. `notify` submits one message with sender profile `transactional`, template
   `application-approved` version `1` and locale `en` to the input `email`. The
   message cites the review result by `resultId` and repeats none of its
   content.
5. `notice-sent` finishes with the Messaging `messageId` and the `resultId`.

When the fourteen days pass without a settled result, `withdraw` cancels the
review request in Casework and `confirm-withdrawal` chooses on the
cancellation's `/outcome`. `cancelled` finishes with outcome `withdrawn` and
the `resultId` Casework recorded for the cancellation. A reviewer can decide in
the moment before the cancellation reaches Casework: the cancellation then
reports `already-terminal` with that decision, and the run finishes with
outcome `decided-late`, the decision's `status` and its `resultId`. The run
sends no notice for a late decision; an operator reads the outcome and follows
up in Casework. Any workflow that withdraws a review routes on the cancel
step's `/outcome` the same way, since only `cancelled` means the withdrawal
ended the review. A result that settles in the final read at the timeout wins
over the timeout and continues at `decide`.

The result a read returns must belong to the accepted request: the same
request, subject, policy and submission digest. Any other result fails the run
with `invalid-response`. An unknown request fails with
`review-request-unknown` and an expired result with `review-result-expired`.
Casework supersedes a request that is still under review when the same
producer submits another for the same application and kind, whatever its
version. Every run of this flow submits as producer `coordinator`, so a second
run for the same application supersedes the first: the first run reads
`superseded` and finishes `not-decided`, and the second run waits for the
replacement review.

The scenarios cover an approved review and its notice, a rejected review with
no notice, a request for changes that is not a decision, a withdrawal after
fourteen days without a decision, a decision recorded shortly before the
withdrawal that finishes `decided-late`, and a notice refused after an
approval. They use synthetic replies
and review results only, so they do not prove Casework review policy, reviewer
authority, completion delivery, Messaging policy or provider delivery.

For a deployment, the institution must supply these prerequisites:

- Casework declares review kind `application-review` version `1` with
  `purpose: approval`, `contextStrategy: submitted` and a `displaySchema` that
  accepts `applicationId` and `applicationVersion`. Its rejection and
  change-request outcomes are Casework policy; the workflow reads only the
  settled `status`.
- Casework declares review producer `coordinator` for kind
  `application-review` and source namespace `applications`, with the issuer and
  subject of the Coordinator's Casework client and a `completion` block whose
  `recipientBinding` is `coordinator-v1`.
- Casework's runtime configuration lists that producer's completion
  destination under `reviewCompletionDestinations`. Its `url` is the
  Coordinator's `/v1/review-completions` route on the main listener and its
  `bearerTokenRef` names the same secret as the Coordinator's
  `completion.bearerTokenRef`. The Coordinator accepts only an
  `Authorization: Bearer` header, so do not configure a custom header.
- The token endpoint registers the `coordinator-review-producer` client for
  resource `urn:example:casework` with scope `casework:review`, and the
  `coordinator-notices` client for resource `urn:example:messaging` with scope
  `messaging:send`. Casework admits the producer client to its
  `coordinator-producer` profile.
- Messaging permits sender profile `transactional`, template
  `application-approved` version `1` and locale `en` for the notices caller.
- Callers hold a Coordinator access token for the `reviewed-notice` flow, and
  an explicit operator policy grants inspection and recovery separately.

The runtime template uses HTTPS reference endpoints and secret references only.
Copy it outside the package and adapt its endpoints, PostgreSQL identity and
roles, clients, completion secret and package pin. Follow
[the deployment runbook](../../DEPLOYMENT.md) for installation and apply.
