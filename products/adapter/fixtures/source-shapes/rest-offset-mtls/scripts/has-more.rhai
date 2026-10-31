// Whether the offset loop fetches another page.
//
// Written to hold under both readings of `doWhile`: the LoopStep doc says
// the predicate runs after each iteration (do-while); Camel's loop page
// calls the mode "the while loop", which reads as a test before each
// iteration, though the page does not show the timing. Before the first
// fetch no total is known, so the answer is true either way.
//
// Reads exchange properties the fetch route sets (`pageOffset`,
// `pageLimit`, `upstreamTotal`). That only works because the loop calls the
// fetch route with `to: direct:`, which shares the exchange; see the README.
fn has_more(exchange) {
    let total = exchange.properties.upstreamTotal;
    if total == () {
        return true;
    }
    exchange.properties.pageOffset < total
}
