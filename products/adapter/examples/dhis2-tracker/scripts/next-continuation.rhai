// The continuation the search route hands back to the engine.
//
// The engine evaluates the route's setProperty expression on the exchange
// (CONCEPT 8.11.3). AdapterNextContinuation is the one property a route
// sets that the engine reads (CONCEPT 8.11.2): its value is sealed into
// the caller's nextCursor, and absent or null means the last page, so
// the engine seals no cursor. `dhis2Page` is the page this run fetched
// (scripts/seed-page.rhai); the reply's `pager.pageCount` counts the
// pages (in 2.41 the pager is always present and totalPages=true, which
// the route always sends, adds total and pageCount). A reply with no
// pager or no pageCount is an unexpected shape and throws rather than
// ending the paging silently; a pageCount of 0 is a legitimate empty
// result with no cursor. Pure and deterministic; no I/O.
fn next_continuation(exchange) {
    let body = exchange.body;
    if body.pager == () {
        throw "tracker reply carries no pager";
    }
    let count = body.pager.pageCount;
    if count == () {
        throw "tracker reply carries no pager.pageCount";
    }
    if count == 0 {
        return ();
    }
    let page = exchange.properties.dhis2Page;
    if page < count {
        return page + 1;
    }
    ()
}
