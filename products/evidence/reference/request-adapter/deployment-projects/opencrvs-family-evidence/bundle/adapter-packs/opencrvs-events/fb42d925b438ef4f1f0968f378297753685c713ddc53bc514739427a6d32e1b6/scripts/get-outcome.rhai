// What a tracking-ID search answered, as two predicates for the lookup
// route's `choice`.
//
// The engine evaluates each predicate on the exchange (CONCEPT 8.11.3),
// whose body is the search reply (`total` and `results`, the shape of the
// reviewed Evidence reference, response-match.json). The route reads them
// in order and treats everything neither one accepts as a source problem,
// never as a guessed record:
//   - is_missing: total is 0 and no result came back. The source holds no
//     registered event of this type under that tracking ID.
//   - is_unique_match: total is 1, exactly one result came back, its
//     trackingId is a string equal to the requested one, its type is the
//     configured event type, and its status is REGISTERED. A second result
//     (the request's limit of 2 exists to show it), a different or
//     differently typed trackingId, a wrong event type, or a total that
//     disagrees with the results is neither predicate's case.
// Pure and deterministic; no I/O.
fn is_missing(exchange) {
    let body = exchange.body;
    if body == () || body.total == () || body.results == () {
        return false;
    }
    body.total == 0 && body.results.len() == 0
}

fn is_unique_match(exchange) {
    let body = exchange.body;
    if body == () || body.total == () || body.results == () {
        return false;
    }
    if body.total != 1 || body.results.len() != 1 {
        return false;
    }
    let event = body.results[0];
    event.trackingId == exchange.headers.recordid
        && type_of(event.trackingId) == "string"
        && event["type"] == exchange.properties.opencrvsEventType
        && event.status == "REGISTERED"
        && event.id != ()
}
