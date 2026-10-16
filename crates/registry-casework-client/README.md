# Registry Casework client

`registry-casework-client` is the canonical bounded Rust client for Registry
Casework. Its public model is ReviewPolicy, ReviewRequest, ReviewTask, Decision,
and ReviewResult, with policy discovery, producer admission and recovery,
review task staffing, private decision drafts, receipts, and Directory operations.
A ReviewResult records the review outcome and grants no authority to mutate
another product. It does not contain Base Registry
Engine routes or policy authority.

Reviewer discovery accepts the optional `ReviewTaskOwnership::AssignedToMe`
or `Unclaimed` filter. `supervisory_review_tasks` is a separate bounded view
for current supervisors of served queues; its rows contain only task and
accountability references, and its state is a holder-free string. A single decided-task read includes
`decision_receipt` only when `decided_by_caller` is true, so response-loss
recovery exposes the caller's own decision without private reasons or result
data.

`own_review_decisions(auth, &OwnReviewDecisionQuery)` discovers the caller's
retained decisions after a fresh sign-in. Optional queue, limit and continuation
select a bounded page ordered newest decision first. Each `OwnReviewDecision`
contains task/request ids, current queue, the retained producer
`requester_reference`, and the same own `decision_receipt` a single task read
returns. Current deciding profile, team, queue, source and result retention
checks apply; prior holding is not authorship.

Every receipt names the `outcome` its decision selected and includes the
optional `outcome_label` from the decision's pinned policy, so later policy
edits cannot relabel a selection. The separately audited Supervisor `review_accountability` read also
exposes that receipt through accountability retention, after result erasure.
No context or structured result is added to either read.

Set `SupervisoryReviewTaskQuery::request_id` to the canonical request UUID to
find a shared request before pagination. It composes with queue, limit and
continuation, and the client rejects a response row for another request.
Unknown or inaccessible requests return the same neutral empty page under
current list semantics. A reference grants no authority to decide, read review
content or retrieve the separate audited accountability record.

Pass review-task `next_cursor` values unchanged with the same caller, profiles
and query filters. A continuation is an opaque snapshot cursor valid for at most 15 minutes.
Changes to holdings, membership or current visibility can invalidate it.
On `410 review.result-expired`, restart without the cursor. A page
whose `status` is not `complete` always carries `next_cursor`; the client
refuses one without it as a malformed response. Task rows remain
subject to current source visibility, Casework membership and retention.

Producer, human-review, and Directory calls take a bearer token and explicit
Casework profile. Agent assertion and grant-status calls take only a bearer
token and grant ID. Current-source task reads take the human caller's source
profile. Submitted-context tasks need no provider. It never retains a
human token or follows redirects, and it resends a mutation only under the
bounded same-key retry below. Direct mutations carry the task or directory
revision the caller displayed and a caller-supplied idempotency key.
Response-loss recovery reuses the original key. Read the decided task to
recover the caller's retained receipt; producers poll the accepted request or
resume the authenticated result feed.

The native Rust `CaseworkTaskAssertionSource` obtains a fresh task assertion
using only the agent's narrow bootstrap scope. A Casework 4xx refusal, including
an expired, revoked, or absent grant, becomes a fixed-text invalid credential
error. HTTP 408, 429, 5xx, and transport failures remain transient. The source does
not resend an assertion request or expose remote problem values in token errors.

## Unknown outcomes and the same-key retry

A 5xx answer may follow a commit, and so may a timeout or a broken exchange
after the request was sent. `CaseworkClientError::is_outcome_unknown()`
reports those cases, and an oversized or unparseable answer, as true; it is
false for a request defect, a connection that was never established, and
every typed 4xx refusal such as `idempotency.key-reused` (409) or
`idempotency.expired` (410). A 410 does not run the mutation again, but an
earlier attempt under the key committed and only its stored response was
erased by retention: reconcile the original operation, by reading the task,
review request, or directory, before choosing a new key.
`CaseworkClientError::mutation_class()` agrees with it: `Ambiguous` exactly
when the outcome is unknown.

The client resends a keyed mutation whose outcome is unknown, with the same
key, headers, and body bytes, at most twice by default, waiting 250 ms and
then 500 ms, or the service's `Retry-After` when that is longer and at most 5
seconds. Casework answers every 503 with `Retry-After: 5`, so a resend after
one waits 5 seconds. A longer requested wait ends the retries. Configure the
count with `CaseworkClientConfig::with_max_mutation_retries` (0 to 2; 0
disables the resend). Reads, unkeyed operations (task grant revocations, task
assertions and previews), and the review request create
and cancel calls, which go through the review client's single exchange, are
never resent. Each attempt has the full request timeout, so a call can take up
to three request timeouts plus the waits.

When the returned error still reports `is_outcome_unknown()`, recover by
sending the same request with the same key, which the service replays or
settles. A new key could apply the mutation twice. A refusal that answers a
resend does not prove the earlier attempt left no effect, so the client then
returns the earlier unknown-outcome error instead of the refusal.

## ReviewTask staffing

`ReviewStaffingQuery` selects an exact five-part `SubjectBinding`, a visible
reference, queue and ownership; `ReviewTaskSort` chooses due, subject or
reference ordering. Partial bindings fail before I/O. `next_review_task` returns
one eligible task or `None`; `review_task_holdings` returns a bounded page.
Keep the caller, source profile, selectors and sort unchanged across cursors.
Current-source disclosure is rechecked before matching and ordering; a broad
live-reference query can require narrowing, and stale continuation is refused.

Caseload movement and clock recomputation use preview and apply calls. Apply
sends the returned preview ID and the caller's idempotency key. The service
revision-fences the preview's complete task set and refuses changed work
atomically. Clock recomputation uses each request's pinned policy closure.
Admission sends the exact reviewed or explicitly accepted discovered
`PolicyBinding` in `ReviewCreateRequest`. Compute its producer-bound digest
locally with `submission_digest(producer_id, source_namespace, &request)`;
Node and Python expose that same implementation as `submissionDigest` and
`submission_digest`. A changed expected binding is refused without accepting
work. Keep the binding, request, key, and digest unchanged during recovery.
