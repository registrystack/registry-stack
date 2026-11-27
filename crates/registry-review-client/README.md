# Registry review client

`registry-review-client` is the bounded, runtime-free HTTP client for the
producer-facing review handoff contract. It creates or recovers review
requests, reads their bindings, retrieves terminal results, pages the
requester result feed, cancels unfinished requests, and pages, reads and
answers reviewer asks.

The producer selects an explicitly granted provider profile with
`Registry-Review-Profile`. Failures accept bounded, well-formed opaque provider problem URIs and
bounded Review validation headers. Provider task APIs and policy evaluators
remain outside this client.

Creation requires a policy selector and submission digest. A selector with only
`id` accepts the trusted provider's concrete current policy; adding both `version`
and `digest` requires an exact pin. The accepted response must match that selector,
subject and original submission digest. Result lookup
requires the accepted request binding and refuses a response unless its
request, subject, policy, and submission digest all match exactly. A producer
must persist that accepted binding before consuming a terminal result.

`request_progress` performs one `GET` with `include=progress` and returns the
optional bounded `ReviewProgressCode`. It refuses a response unless the full
accepted request, subject, policy and submission digest match exactly, and it
refuses a progress code on terminal work. It does not infer progress from the
provider's raw stage identifier or retain an earlier code across failures.

`create_or_recover_request_for_producer` also compares the expected configured
producer ID with `Registry-Review-Producer` when the provider supplies it.
An acceptance naming another producer returns `ProducerIdentityMismatch` only
when its digest binds that producer, the request's subject source, and the
complete original request. The error carries both bounded IDs. A stale or
otherwise incorrect digest remains a protocol failure. It remains an ambiguous mutation outcome because the
provider may already retain that review. Missing metadata remains compatible
only when the original digest matches exactly; malformed or duplicate metadata
is a protocol failure. Every subject and policy check still applies, and no
failure grants permission to retry with a fresh idempotency key.

Authentication is supplied for each call. The client does not retain
credentials, retry mutations, follow redirects, use ambient proxies, evaluate
review policy, operate reviewer tasks, or apply a source-system result.

`ask_feed`, `ask` and `answer_ask` follow the result feed and result read where
they can. The feed refuses nil identifiers and a cursor that is not its final
entry, and a cursor past retention surfaces as a 410 `Problem`. `ask` and
`answer_ask` take the accepted request binding, as the result read and cancel
do, and refuse a response whose request, ask or subject differs from it.
`answer_ask` posts only the subject binding and answer time with an
idempotency key, and refuses an answer for another subject before any request.
Its typed outcomes are `Answered`, `ConcealedOrUnknown` for an empty 404, and
`NotOpen` for a 409 whose problem code is `review.ask-not-open`. Any other 404
or 409, including a problem document, is a `Problem` error. A success must be
the same ask, answered, with the `answeredAt` that was sent. None of them
retries. See the protocol README for the rules a producer follows when it
consumes the feed.
