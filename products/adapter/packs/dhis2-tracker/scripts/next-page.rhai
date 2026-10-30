// The page number the tracker search loop asks for next.
//
// The engine evaluates the loop step's property expression on the
// exchange (CONCEPT 8.11.3). `dhis2Page` is the property the search
// route seeds at 1 and advances after each fetch (see
// scripts/has-more-pages.rhai). Pure and deterministic; no I/O.
fn next_page(exchange) {
    exchange.properties.dhis2Page + 1
}
