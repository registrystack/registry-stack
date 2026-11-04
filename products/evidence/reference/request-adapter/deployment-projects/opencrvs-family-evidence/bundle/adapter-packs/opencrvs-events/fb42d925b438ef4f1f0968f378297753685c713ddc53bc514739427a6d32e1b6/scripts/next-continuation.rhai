// The continuation the search route hands back to the engine.
//
// The engine evaluates the route's setProperty expression on the exchange
// (CONCEPT 8.11.3). AdapterNextContinuation is the one property a route
// sets that the engine reads (CONCEPT 8.11.2): its value is sealed into the
// caller's nextCursor, and absent or null means the last page. The position
// is an offset: the offset this page started at
// (AdapterContinuation, absent on the first page) plus the number of
// results it returned, while `total` says more remain. Advancing by the
// results returned, not the limit asked, never skips a row if the source
// shortens a page. A page that returns no results while rows remain would
// loop forever, so it throws. The route has already refused an unsound page
// (scripts/page-sound.rhai). Pure and deterministic; no I/O.
fn next_continuation(exchange) {
    let offset = exchange.properties.AdapterContinuation;
    if offset == () {
        offset = 0;
    }
    let next = offset + exchange.body.results.len();
    if next >= exchange.body.total {
        return ();
    }
    if exchange.body.results.len() == 0 {
        throw "event search returned no results while rows remain";
    }
    next
}
