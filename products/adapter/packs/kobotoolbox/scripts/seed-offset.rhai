// The offset the kobo-submissions route fetches in this run.
//
// The engine evaluates the route's setProperty expression on the
// exchange (CONCEPT 8.11.3). In job mode the exchange starts with the
// job cursor under the closed property `AdapterJobCursor`, absent on
// the first run (CONCEPT 17.2); this pack's cursor value is the
// `next` object the route handed out with the previous page, so the
// seed is that object's `offset`, or 0 on the first run. A cursor of
// the wrong shape throws rather than silently restarting at 0. Pure
// and deterministic; no I/O.
fn seed_offset(exchange) {
    let cursor = exchange.properties.AdapterJobCursor;
    if cursor == () {
        return 0;
    }
    if cursor.type_of() != "map" {
        throw "the job cursor is not an object";
    }
    let offset = cursor["offset"];
    if offset == () {
        throw "the job cursor carries no offset";
    }
    if offset.type_of() != "i64" {
        throw "the job cursor offset is not an integer";
    }
    offset
}
