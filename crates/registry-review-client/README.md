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

Authentication is supplied for each call. The client does not retain
credentials, retry mutations, follow redirects, use ambient proxies, evaluate
review policy, operate reviewer tasks, or apply a source-system result.
