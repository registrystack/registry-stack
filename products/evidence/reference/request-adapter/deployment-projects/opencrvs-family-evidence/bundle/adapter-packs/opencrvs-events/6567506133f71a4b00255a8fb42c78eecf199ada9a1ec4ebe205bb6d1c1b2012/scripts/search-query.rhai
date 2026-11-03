// The event-search body for one facade page of registered events.
//
// The engine evaluates the send's `body` expression on the exchange
// (CONCEPT 8.11.3). The query is the one scripts/get-query.rhai sends
// without the tracking-ID clause. The limit is the caller's page size (the
// `pageSize` facade input, bounded by the profile, lowercased to
// `pagesize` in the script's headers), and the offset is the position the
// engine restored from the caller's cursor into AdapterContinuation (absent
// on the first page, so 0). One facade page is one upstream page
// (CONCEPT 8.11.2). The continuation this pack seals is the offset itself,
// an integer, so scripts/next-continuation.rhai reads the same property.
// Pure and deterministic; no I/O.
fn search_query(exchange) {
    let limit = exchange.headers.pagesize;
    if limit == () {
        throw "request carries no page size";
    }
    let offset = exchange.properties.AdapterContinuation;
    if offset == () {
        offset = 0;
    }
    #{
        query: #{
            type: "and",
            clauses: [#{
                eventType: exchange.properties.opencrvsEventType,
                status: #{ type: "exact", term: "REGISTERED" }
            }]
        },
        limit: limit,
        offset: offset
    }
}
