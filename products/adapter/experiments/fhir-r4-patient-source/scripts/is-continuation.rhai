// Whether the fetch is a continuation page rather than the first search.
//
// The engine is assumed to call `is_continuation` with the exchange map;
// the first iteration has no `fhirNextUrl` property yet. Pure and
// deterministic; no I/O.
fn is_continuation(exchange) {
    let next = exchange.properties.fhirNextUrl;
    next != () && next != ""
}
