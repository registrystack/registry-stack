# Registry review client

`registry-review-client` is the bounded, runtime-free HTTP client for the
producer-facing review handoff contract. It creates or recovers review
requests, reads their bindings, retrieves terminal results, pages the
requester result feed, and cancels unfinished requests.

Creation requires the producer's expected submission digest. Result lookup
requires the accepted request binding and refuses a response unless its
request, subject, policy, and submission digest all match exactly. A producer
must persist that accepted binding before consuming a terminal result.

Authentication is supplied for each call. The client does not retain
credentials, retry mutations, follow redirects, use ambient proxies, evaluate
review policy, operate reviewer tasks, or apply a source-system result.
