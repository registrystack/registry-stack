// The `query` filter the kobo-submissions route sends in this run.
//
// The engine evaluates the route's setProperty expression on the
// exchange (CONCEPT 8.11.3). In job mode the exchange starts with the
// job cursor under the closed property `AdapterJobCursor`, absent on
// the first run (CONCEPT 17.2); this pack's cursor value is the
// `next` object the route handed out with the previous page,
// `{afterId: <the last _id read>}`. The seed is the Kobo `query`
// parameter (MongoDB syntax, kpi/docs/api/v2/data/list.md) that reads
// past that id, `{"_id":{"$gt":<afterId>}}`, or nothing on the first
// run: a null property leaves the query parameter out of the send. A
// cursor of the wrong shape throws rather than silently restarting
// from the first submission. Pure and deterministic; no I/O.
fn seed_query(exchange) {
    let cursor = exchange.properties.AdapterJobCursor;
    if cursor == () {
        return ();
    }
    if cursor.type_of() != "map" {
        throw "the job cursor is not an object";
    }
    let after = cursor["afterId"];
    if after == () {
        throw "the job cursor carries no afterId";
    }
    if after.type_of() != "i64" {
        throw "the job cursor afterId is not an integer";
    }
    `{"_id":{"$gt":${after}}}`
}
