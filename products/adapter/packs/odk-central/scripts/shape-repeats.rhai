// The item page the odk-repeats route returns: one repeat entity set
// (Central exposes each repeat as its own entity set, for example
// `Submissions.household.member`), the F5 item contract of CONCEPT
// 17.2.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). The reply body is one page of the
// deployment's repeat entity set, shaped like any OData page. The
// route asks for `$orderby=$root/Submissions/__system/submissionDate
// asc` (repeat rows ordered by their parent submission's date) and
// `$skip` from the cursor's offset; the reply's `@odata.nextLink` is
// never read.
//
// Item mapping (probe-gated, see the pack README): key = the repeat
// row's own `__id`, which Central derives from the parent instance and
// the row's position. Each row also carries its parent's instance id
// under a `__Submissions-id` member (`__Submissions-<group>-id` for a
// repeat nested in a group); the script requires one so that a binding
// to a non-repeat entity set fails instead of passing submissions off
// as repeat rows, and `value` carries it unchanged. The revision is
// `__system/updatedAt` where a row carries one; a repeat row carries
// no `__system`, so its item carries no revision.
//
// The resumption cursor: `{offset: <offset + rows read>}`, handed out
// on every page, an empty one included, so an ongoing scan holds its
// place at the tail. Pure and deterministic; no I/O.
fn shape_repeats(exchange) {
    let body = exchange.body;
    let rows = body["value"];
    if rows == () {
        throw "OData reply carries no value";
    }
    if rows.type_of() != "array" {
        throw "OData reply value is not an array";
    }
    let offset = exchange.properties.odkRepeatOffset;
    if offset == () {
        throw "odkRepeatOffset property is absent";
    }
    let items = [];
    for row in rows {
        let id = row["__id"];
        if id == () || id.type_of() != "string" {
            throw "repeat entity carries no __id";
        }
        let parent = false;
        for name in row.keys() {
            if name.starts_with("__Submissions") && name.ends_with("-id") {
                parent = true;
            }
        }
        if !parent {
            throw "repeat entity carries no __Submissions parent reference";
        }
        let item = #{ key: id, value: row };
        let system = row["__system"];
        if system != () && system["updatedAt"] != () {
            item.revision = system["updatedAt"];
        }
        items.push(item);
    }
    #{ items: items, next: #{ offset: offset + rows.len() } }
}
