// The tracker page the search route fetches for this facade page.
//
// The engine evaluates the route's setProperty expression on the exchange
// (CONCEPT 8.11.3). The engine restores the caller's continuation into
// the AdapterContinuation property, absent on the first page (CONCEPT
// 8.11.2); this pack's continuation value is the next DHIS2 page number,
// so the seed is that number, or the first page when the caller sent no
// cursor. The route reads the seeded property in its `page` query
// parameter and scripts/next-continuation.rhai carries the position back
// out. Pure and deterministic; no I/O.
fn seed_page(exchange) {
    let continuation = exchange.properties.AdapterContinuation;
    if continuation == () {
        return 1;
    }
    continuation
}
