// Whether an upstream HTTP failure carries the source's not-found status.
//
// A send that raises upstream.http answers with the source's error body,
// and DHIS2 writes every error body in its consistent web API envelope,
// whose httpStatusCode field carries the HTTP status (DHIS2
// documentation, "Introduction", Error and info messages). The engine
// calls `is_not_found` with that body as this clause's onWhen predicate,
// so only the 404 answer maps to the facade's not-found problem; any
// other upstream HTTP outcome falls through unmatched. A body that is
// absent matches nothing. Pure and deterministic; no I/O.
fn is_not_found(body) {
    if body == () {
        return false;
    }
    body.httpStatusCode == 404
}
