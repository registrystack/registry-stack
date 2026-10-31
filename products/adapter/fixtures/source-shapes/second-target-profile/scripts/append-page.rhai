// Appends the fetched JSON:API page (`body.data`) to the households
// gathered so far (`properties.households`), refusing a resource id seen on
// an earlier page. This repeats `jsonArrayAppend` with `uniqueBy: id` by
// hand: that strategy exists only on `enrich`, and `enrich` would drop the
// paging properties the fetch route sets (see the README).
fn append_page(exchange) {
    let gathered = exchange.properties.households;
    if gathered == () {
        gathered = [];
    }
    let page = exchange.body.data;
    if type_of(page) != "array" {
        throw "the page carries no data array";
    }
    for resource in page {
        if resource.type != "households" {
            throw "a page resource is not a household";
        }
        for seen in gathered {
            if seen.id == resource.id {
                throw "a household repeats across pages";
            }
        }
        gathered.push(resource);
    }
    gathered
}
