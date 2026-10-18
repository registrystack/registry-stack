# Registry review client

`registry-review-client` is the bounded, runtime-free HTTP client for the
producer-facing review handoff contract. It creates or recovers review
requests, reads their bindings, retrieves terminal results, pages the
requester result feed, and cancels unfinished requests.

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

`create_or_recover_request_for_producer` also compares the expected configured
producer ID with `Registry-Review-Producer` when the provider supplies it.
A validated acceptance naming another producer returns `ProducerIdentityMismatch`
with both bounded IDs. It remains an ambiguous mutation outcome because the
provider may already retain that review. Missing metadata remains compatible
only when the original digest matches exactly; malformed or duplicate metadata
is a protocol failure. Every subject and policy check still applies, and no
failure grants permission to retry with a fresh idempotency key.

Authentication is supplied for each call. The client does not retain
credentials, retry mutations, follow redirects, use ambient proxies, evaluate
review policy, operate reviewer tasks, or apply a source-system result.
