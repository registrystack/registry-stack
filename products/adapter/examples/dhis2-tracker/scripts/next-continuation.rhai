// The continuation the search route hands back to the engine.
//
// The engine evaluates the route's setProperty expression on the exchange
// (CONCEPT 8.11.3). AdapterNextContinuation is the one property a route
// sets that the engine reads (CONCEPT 8.11.2): its value is sealed into
// the caller's nextCursor, and absent or null means the last page, so
// the engine seals no cursor. `dhis2Page` is the page this run fetched
// (scripts/seed-page.rhai) and `dhis2TotalPages` the total the reply's
// page block reported; another facade page continues only while the
// source's total holds one more. A reply with no usable total is the
// last page rather than a cursor that would page blind. Pure and
// deterministic; no I/O.
fn next_continuation(exchange) {
    let page = exchange.properties.dhis2Page;
    let total = exchange.properties.dhis2TotalPages;
    if total == () || total <= 0 {
        return ();
    }
    if page < total {
        return page + 1;
    }
    ()
}
