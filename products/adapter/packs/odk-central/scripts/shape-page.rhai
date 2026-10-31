# The item page the odk-submissions route returns: the F5 item
# contract of CONCEPT 17.2, `{items: [{key, revision, value}], next}`.
#
# The engine evaluates the route's final setBody expression on the
# exchange (CONCEPT 8.11.3). The reply body is the OData page:
# the entities under `value`, the optional `@odata.count`, and the
# optional `@odata.nextLink` (the OData page of
# https://docs.getodk.org/central-api-odata-endpoints/: with `$top`
# the reply carries the nextLink, and since Central v2023.4 it holds a
# `$skiptoken` opaque cursor). The link is handed out as written and
# the next run sends it through the engine's origin-pinned link rules,
# never a reparse.
#
# Item mapping (probe-gated, see the pack README): key = the
# entity's `__id` (the documented OData key), revision =
# `__system/updatedAt` (hypothesis: changes on edit), value = the
# entity object as returned. A page whose cursor grows beyond the
# 2 KiB cursor bound fails the run (CONCEPT 17.2); a Central
# nextLink stays far below it. The `@odata.nextLink` presence is the
# continue signal: no nextLink, no cursor. Pages may shift when
# submissions arrive while a job runs; the route declares
# `key-deduplicated` recovery for exactly that reason. Pure and
# deterministic; no I/O.
fn shape_page(exchange) {
    let body = exchange.body;
    let rows = body["value"];
    if rows == () {
        throw "OData reply carries no value";
    }
    if rows.type_of() != "array" {
        throw "OData reply value is not an array";
    }
    let items = [];
    for row in rows {
        let id = row["__id"];
        if id == () {
            throw "submission entity carries no __id";
        }
        let revision = ();
        let system = row["__system"];
        if system != () {
            revision = system["updatedAt"];
        }
        if revision == () {
            throw "submission entity carries no __system/updatedAt";
        }
        items.push(#{
            key: `${id}`,
            revision: revision,
            value: row
        });
    }
    let link = body["@odata.nextLink"];
    if link == () {
        return #{ items: items };
    }
    if link.type_of() != "string" {
        throw "OData nextLink is not a string";
    }
    #{ items: items, next: #{ nextLink: link } }
}
