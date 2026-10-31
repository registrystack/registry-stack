// The item page the odk-repeats route returns: the repeat-table
// sketch of the pack README, the F5 item contract of CONCEPT 17.2.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). The reply body is one page of the
// deployment's repeat entity set (Central exposes repeats as separate
// entity sets, for example `Submissions.children.child`), shaped like
// any OData page.
//
// The key composition is the sketch's open question, stated rather
// than hidden: the OData page of
// https://docs.getodk.org/central-api-odata-endpoints/ names no member
// by which a repeat entity references its parent submission and no
// within-parent ordinal, so this script reads the hypothesized
// `__parent-id` and composes the key as
// `<parent>/<absolute row position>`, where the absolute position is
// the cursor's accumulated row count plus the position within this
// page. Both parts are probe-gated; if Central exposes a stable parent
// reference and ordinal, the composition stays; if not, the consumer
// should deduplicate on the repeat row's own `__id`, which `value`
// carries unchanged. The revision is `__system/updatedAt` where
// present, and the item carries no revision where absent. The cursor
// hands the nextLink on as written (the send follows the engine's
// origin-pinned link rules, CONCEPT 8.11.5) beside the accumulated
// count the key needs; no nextLink, no cursor. Pure and deterministic;
// no I/O.
fn shape_repeats(exchange) {
    let body = exchange.body;
    let rows = body["value"];
    if rows == () {
        throw "OData reply carries no value";
    }
    if rows.type_of() != "array" {
        throw "OData reply value is not an array";
    }
    let consumed = exchange.properties.odkRepeatStart;
    if consumed == () {
        throw "odkRepeatStart property is absent";
    }
    let items = [];
    let position = 0;
    for row in rows {
        let parent = row["__parent-id"];
        if parent == () {
            throw "repeat entity carries no parent reference";
        }
        let item = #{ key: `${parent}/${consumed + position}`, value: row };
        let system = row["__system"];
        if system != () && system["updatedAt"] != () {
            item.revision = system["updatedAt"];
        }
        items.push(item);
        position += 1;
    }
    let link = body["@odata.nextLink"];
    if link == () {
        return #{ items: items };
    }
    if link.type_of() != "string" {
        throw "OData nextLink is not a string";
    }
    #{ items: items,
       next: #{ offset: consumed + position, nextLink: link } }
}
