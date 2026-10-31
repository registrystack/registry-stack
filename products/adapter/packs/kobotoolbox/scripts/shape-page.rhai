# The item page the kobo-submissions route returns: the F5 item
# contract of CONCEPT 17.2, `{items: [{key, revision, value}], next}`.
#
# The engine evaluates the route's final setBody expression on the
# exchange (CONCEPT 8.11.3). The reply body is the Kobo data-endpoint
# envelope `{count, next, previous, results}`; this script reads
# `results` and nothing else, and never follows the reply's `next` URL:
# the cursor stays the pack's own `{offset}` object, so paging remains
# origin-pinned by construction.
#
# Item mapping (both parts are probe-gated hypotheses, see the pack
# README): key = the submission's `_id` as text, revision = `_uuid`,
# value = the submission object as returned, `_validation_status`
# included only as read-only passthrough inside `value`. A submission
# without `_id` or `_uuid` throws: a page that cannot be keyed or
# revisioned is an unexpected shape, never a silently weaker item.
#
# The resumption cursor: the fixed page size of the route's `limit`
# query (100 in pack.yaml; the two constants move together) is the
# fullness test. A full page hands out `{offset: start + 100}`; a short
# or empty page hands out no cursor, so the job stops until its next
# run re-reads at that offset. Offset pages shift under concurrent
# submissions; the route declares `key-deduplicated` recovery for
# exactly that reason. Pure and deterministic; no I/O.
fn shape_page(exchange) {
    let body = exchange.body;
    let page = body["results"];
    if page == () {
        throw "kobo reply carries no results";
    }
    if page.type_of() != "array" {
        throw "kobo reply results is not an array";
    }
    let start = exchange.properties.koboStart;
    if start == () {
        throw "koboStart property is absent";
    }
    let items = [];
    for submission in page {
        let id = submission["_id"];
        if id == () {
            throw "submission carries no _id";
        }
        let revision = submission["_uuid"];
        if revision == () {
            throw "submission carries no _uuid";
        }
        items.push(#{
            key: `${id}`,
            revision: revision,
            value: submission
        });
    }
    if items.len() < 100 {
        return #{ items: items };
    }
    #{ items: items, next: #{ offset: start + 100 } }
}
