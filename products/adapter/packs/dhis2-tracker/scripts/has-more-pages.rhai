// Whether the tracker search loop fetches another page.
//
// The engine evaluates the loop's `doWhile` predicate on the exchange
// (CONCEPT 8.11.3: the one read-only map `#{ body, headers, properties }`).
// The route carries the loop position in properties: `dhis2Page` is the
// page the next fetch asks for, seeded at 1 before the loop and advanced
// by scripts/next-page.rhai after each fetch, and `dhis2TotalPages` is
// the total the last fetch reported (DHIS2 fills it only when the request
// carries totalPages=true, which this pack always sends). The first page
// always fetches; a later page fetches only while the source's total
// holds it, and a fetch that reports no usable total ends the loop rather
// than paging blind. The reviewed page bound is the loop's
// maximumIterations, which the engine enforces itself. Pure and
// deterministic; no I/O.
fn has_more_pages(exchange) {
    let page = exchange.properties.dhis2Page;
    let total = exchange.properties.dhis2TotalPages;
    if total == () || total <= 0 {
        return page == 1;
    }
    page <= total
}
