// The position the odk-submissions and odk-repeats routes fetch in
// this run.
//
// The engine evaluates the route's setProperty expressions on the
// exchange (CONCEPT 8.11.3). In job mode the exchange starts with the
// job cursor under the closed property `AdapterJobCursor`, absent on
// the first run (CONCEPT 17.2). The odk-submissions cursor is
// `{nextLink: <url>}` when a continuation follows and absent on the
// first run; the odk-repeats cursor is `{offset: <n>}` or absent. One
// file, two seeds, one reader: a cursor of the wrong shape throws
// rather than silently restarting. Pure and deterministic; no I/O.
fn cursor_member(exchange, member, expected_type) {
    let cursor = exchange.properties.AdapterJobCursor;
    if cursor == () {
        return ();
    }
    if cursor.type_of() != "map" {
        throw "the job cursor is not an object";
    }
    let value = cursor[member];
    if value == () {
        return ();
    }
    if value.type_of() != expected_type {
        throw "the job cursor member has the wrong type";
    }
    value
}

// The nextLink the odk-submissions route follows with an
// origin-pinned send (CONCEPT 8.11.5), absent on the first run.
fn seed_next_link(exchange) {
    cursor_member(exchange, "nextLink", "string")
}

// The repeat-set offset the odk-repeats route sends as `$skip`, 0 on
// the first run.
fn seed_repeat_offset(exchange) {
    let offset = cursor_member(exchange, "offset", "i64");
    if offset == () {
        return 0;
    }
    offset
}
