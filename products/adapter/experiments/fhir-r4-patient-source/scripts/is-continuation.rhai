// Whether the fetch is a continuation page rather than the first search.
//
// The engine is assumed to call `is_continuation` with the exchange map;
// the first iteration has no `fhirNextUrl` property yet. Pure and
// deterministic; no I/O.
fn is_continuation(exchange) {
    let next = next_url(exchange);
    next != () && next != ""
}

fn next_url(exchange) {
    let next = exchange.properties.fhirNextUrl;
    if next == () || type_of(next) != "array" {
        return next;
    }
    let url = ();
    for link in next {
        if link.relation == "next" {
            if url != () {
                throw "the searchset carries more than one next link";
            }
            url = link.url;
        }
    }
    url
}
