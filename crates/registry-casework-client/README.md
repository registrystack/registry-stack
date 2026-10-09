# Registry Casework client

`registry-casework-client` is the canonical bounded Rust client for Registry
Casework. It exposes Casework's source-neutral work-item and directory HTTP
contract, including unified review request, result, task, draft, history,
accountability, and kind discovery routes. It does not contain Base Registry
Engine routes or policy authority.

Reviewer discovery accepts the optional `ReviewTaskOwnership::AssignedToMe`
or `Unclaimed` filter. `supervisory_review_tasks` is a separate bounded view
for current supervisors of served queues; its rows contain only task and
accountability references, and its state is a holder-free string. A single decided-task read includes
`decision_receipt` only when `decided_by_caller` is true, so response-loss
recovery exposes the caller's own decision without private reasons or result
data.

The client takes a bearer token and explicit Casework profile for each call.
Source-reading calls also take an explicit source profile. It never retains a
human token or follows redirects, and it resends a mutation only under the
bounded same-key retry below. Direct mutations carry the item or directory
revision the caller displayed and a caller-supplied idempotency key.
Response-loss recovery reuses the original key and the server's stored
prepared attempt.

## Unknown outcomes and the same-key retry

A 5xx answer may follow a commit, and so may a timeout or a broken exchange
after the request was sent. `CaseworkClientError::is_outcome_unknown()`
reports those cases, and an oversized or unparseable answer, as true; it is
false for a request defect, a connection that was never established, and
every typed 4xx refusal such as `idempotency.key-reused` (409) or
`idempotency.expired` (410). A 410 does not run the mutation again, but there
an earlier attempt under the key committed and only its stored response was
erased by retention: reconcile the original operation, by reading the item,
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
assertions, decision recovery, and previews), and the review request create
and cancel calls, which go through the review client's single exchange, are
never resent. Each attempt has the full request timeout, so a call can take up
to three request timeouts plus the waits.

When the returned error still reports `is_outcome_unknown()`, recover by
sending the same request with the same key, which the service replays or
settles. A new key could apply the mutation twice. A refusal that answers a
resend does not prove the earlier attempt left no effect, so the client then
returns the earlier unknown-outcome error instead of the refusal.
