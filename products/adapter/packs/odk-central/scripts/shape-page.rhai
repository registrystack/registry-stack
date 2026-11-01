// The item page the odk-submissions route returns: the F5 item
// contract of CONCEPT 17.2, `{items: [{key, revision, value}], next}`.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). The reply body is the OData page: the
// entities under `value` (the OData page of
// https://docs.getodk.org/central-api-odata-endpoints/). The route
// asks for `$orderby=__system/submissionDate asc` and, past the first
// run, `$filter=__system/submissionDate ge <cursor date>`; the reply's
// own `@odata.nextLink` is never read, because Central's `$skiptoken`
// pages in its default newest-first order, which an ongoing scan
// cannot resume from.
//
// Item mapping (probe-gated, see the pack README): key = the
// entity's `__id` (the documented OData key, the submission
// `instanceId`), revision = `__system/updatedAt`, or
// `__system/submissionDate` while the submission was never edited
// (Central leaves `updatedAt` null until the first edit,
// https://docs.getodk.org/central-api-submission-management/), value
// = the entity object as returned.
//
// The resumption cursor: `{submissionDate, seen}`, the rendered date
// of the last row and every id the reply carried at that date. The
// filter's bound is inclusive, so the next reply starts with the rows
// at the cursor date again; those whose id the cursor lists as seen
// are dropped, the rest are new. An empty reply hands the incoming
// cursor back unchanged, and a first run with nothing to read hands
// out no cursor, so an ongoing scan holds its place at the tail. A
// reply out of submission-date order or reaching back before the
// cursor date throws. More than 40 ids at one rendered date throws
// too: the cursor would outgrow its 2 KiB bound (CONCEPT 17.2), and a
// page of nothing but seen rows would never move on. Pure and
// deterministic; no I/O.
fn shape_page(exchange) {
    let body = exchange.body;
    let rows = body["value"];
    if rows == () {
        throw "OData reply carries no value";
    }
    if rows.type_of() != "array" {
        throw "OData reply value is not an array";
    }
    let cursor = exchange.properties.AdapterJobCursor;
    let from = ();
    let seen = [];
    if cursor != () {
        from = cursor["submissionDate"];
        seen = cursor["seen"];
    }
    let items = [];
    let date = ();
    let at_date = [];
    for row in rows {
        let id = row["__id"];
        if id == () || id.type_of() != "string" {
            throw "submission entity carries no __id";
        }
        let system = row["__system"];
        if system == () || system.type_of() != "map" {
            throw "submission entity carries no __system";
        }
        let submitted = system["submissionDate"];
        if submitted == () || submitted.type_of() != "string" {
            throw "submission entity carries no __system/submissionDate";
        }
        let floor = date;
        if floor == () {
            floor = from;
        }
        if floor != () && submitted < floor {
            throw "OData reply is not in submission-date order past the cursor";
        }
        if submitted != date {
            date = submitted;
            at_date = [];
        }
        at_date.push(id);
        if submitted == from && seen.contains(id) {
            continue;
        }
        let revision = system["updatedAt"];
        if revision == () {
            revision = submitted;
        }
        items.push(#{
            key: id,
            revision: revision,
            value: row
        });
    }
    if date == () {
        if from == () {
            return #{ items: items };
        }
        return #{ items: items, next: #{ submissionDate: from, seen: seen } };
    }
    if at_date.len() > 40 {
        throw "more than 40 submissions share one rendered submission date";
    }
    #{ items: items, next: #{ submissionDate: date, seen: at_date } }
}
