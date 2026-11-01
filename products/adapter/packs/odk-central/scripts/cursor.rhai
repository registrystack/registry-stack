// The position the odk-submissions and odk-repeats routes fetch in
// this run.
//
// The engine evaluates the route's setProperty expressions on the
// exchange (CONCEPT 8.11.3). In job mode the exchange starts with the
// job cursor under the closed property `AdapterJobCursor`, absent on
// the first run (CONCEPT 17.2). The odk-submissions cursor is
// `{submissionDate: <rendered date>, seen: [<__id>, ...]}`, the
// submission date of the last row read and the ids already read at
// exactly that date; the odk-repeats cursor is `{offset: <n>}`. One
// file, two seeds: a cursor of the wrong shape throws rather than
// silently restarting from the first row. Pure and deterministic; no
// I/O.

// The `$filter` the odk-submissions route sends, absent on the first
// run: `__system/submissionDate ge <submissionDate>` (the documented
// filterable submission date and `ge` operator of
// https://docs.getodk.org/central-api-odata-endpoints/). The bound is
// inclusive because Central renders dates to the millisecond while it
// stores finer ones, so two submissions can share one rendered date
// across a page boundary; scripts/shape-page.rhai drops the ids the
// cursor already lists as seen. The date travels into the OData
// literal, so it must be made of date characters only.
fn seed_filter(exchange) {
    let cursor = exchange.properties.AdapterJobCursor;
    if cursor == () {
        return ();
    }
    if cursor.type_of() != "map" {
        throw "the job cursor is not an object";
    }
    let date = cursor["submissionDate"];
    if date == () || date.type_of() != "string" || date == "" {
        throw "the job cursor carries no submissionDate";
    }
    for character in date.chars() {
        if !"0123456789-:.TZ+".contains(character) {
            throw "the job cursor submissionDate is not a date";
        }
    }
    let seen = cursor["seen"];
    if seen == () || seen.type_of() != "array" {
        throw "the job cursor carries no seen list";
    }
    for id in seen {
        if id.type_of() != "string" {
            throw "the job cursor seen list holds a non-string id";
        }
    }
    `__system/submissionDate ge ${date}`
}

// The repeat-set offset the odk-repeats route sends as `$skip`, 0 on
// the first run.
fn seed_repeat_offset(exchange) {
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
    if offset.type_of() != "i64" || offset < 0 {
        throw "the job cursor offset is not a non-negative integer";
    }
    offset
}
