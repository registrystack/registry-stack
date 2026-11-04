// Whether a search page is one the route may map.
//
// The engine evaluates this `choice` predicate on the exchange
// (CONCEPT 8.11.3), whose body is the search reply. A page is sound when
// `total` is a non-negative integer, `results` is an array no longer than
// `total`, and every result carries an id and a string trackingId and is of
// the configured event type with status REGISTERED, as the query asked.
// Anything else is a source problem, not a page to shape. Pure and
// deterministic; no I/O.
fn is_sound_page(exchange) {
    let body = exchange.body;
    if body == () || body.total == () || body.results == () {
        return false;
    }
    if type_of(body.total) != "i64" || body.total < 0 {
        return false;
    }
    if type_of(body.results) != "array" || body.results.len() > body.total {
        return false;
    }
    for event in body.results {
        if event.id == () || type_of(event.trackingId) != "string"
            || event["type"] != exchange.properties.opencrvsEventType
            || event.status != "REGISTERED" {
            return false;
        }
    }
    true
}
