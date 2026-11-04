// Whether an upstream HTTP failure carries the source's bad-request status.
//
// A send that raises upstream.http answers with the source's error body,
// and DHIS2 writes every error body in its consistent web API envelope,
// whose httpStatusCode field carries the HTTP status (DHIS2
// documentation, "Introduction", Error and info messages). The engine
// evaluates this clause's `onWhen` predicate on the exchange
// (CONCEPT 8.11.3), whose body is that error body, so only the 400
// answer maps to the caller's invalid input; any other upstream HTTP
// outcome falls through unmatched. A body that is absent matches
// nothing. Pure and deterministic; no I/O.
fn is_bad_request(exchange) {
    let body = exchange.body;
    if body == () {
        return false;
    }
    body.httpStatusCode == 400
}
