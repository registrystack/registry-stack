// The item page the kobo-submissions route returns: the F5 item
// contract of CONCEPT 17.2, `{items: [{key, revision, value}], next}`.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). By then the route's split has turned the
// reply's `results` into the items of scripts/shape-item.rhai, in
// reply order; the reply's own `next` URL was never read, so the
// cursor stays the pack's own `{afterId}` object and paging remains
// origin-pinned by construction.
//
// Read order: the route asks for `sort={"_id":1}` and, past the first
// run, `query={"_id":{"$gt":<afterId>}}`, so every page continues
// strictly after the last submission read. A page whose `_id` values
// do not climb past the cursor means the server ignored the sort or the
// filter, and the script throws rather than hand out a position that
// skips or repeats submissions.
//
// The resumption cursor: a page with submissions hands out
// `{afterId: <its last _id>}`, whether full or short, so an ongoing
// scan holds its place at the tail and the next pass reads only what
// arrived since. An empty page hands the incoming cursor back
// unchanged, and on a first run with nothing to read there is no
// position to keep, so no cursor. Pure and deterministic; no I/O.
fn shape_page(exchange) {
    let items = exchange.body;
    if items.type_of() != "array" {
        throw "the split items are not an array";
    }
    let cursor = exchange.properties.AdapterJobCursor;
    let last = ();
    if cursor != () {
        last = cursor["afterId"];
    }
    for item in items {
        let id = item.value["_id"];
        if last != () && id <= last {
            throw "kobo reply is not in ascending _id order past the cursor";
        }
        last = id;
    }
    if last == () {
        return #{ items: items };
    }
    #{ items: items, next: #{ afterId: last } }
}
