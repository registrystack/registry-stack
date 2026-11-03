// Keep only the reviewed response leaves before provider-schema validation.
// An unrelated field cannot enter a fact or assertion.
fn project(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" || !raw.contains("items") || raw.items.type_of() != "array"
        || !raw.contains("pageInfo") || raw.pageInfo.type_of() != "map" {
        throw "invalid-page";
    }
    let items = [];
    for item in raw.items {
        if item.type_of() != "map" || !item.contains("domainData") || item.domainData.type_of() != "map" {
            throw "invalid-record";
        }
        let record = #{};
        for field in ["recordReference", "region"] {
            if item.domainData.contains(field) { record[field] = item.domainData[field]; }
        }
        items.push(#{domainData: record});
    }
    let page = #{};
    if raw.pageInfo.contains("nextCursor") { page.nextCursor = raw.pageInfo.nextCursor; }
    #{items: items, pageInfo: page}
}

// A page has no total count. Both its length and further-page cursor must
// prove a unique match. One bounded request never follows a second page.
fn lookup(exchange) {
    let response = exchange.body;
    let items = response.items;
    let has_more = response.pageInfo.nextCursor != ();
    if items.len() == 0 {
        // An empty page claiming further pages contradicts itself.
        if has_more { throw "inconsistent-empty-page"; }
        return #{lookup: "no-match"};
    }
    if items.len() > 1 || has_more { return #{lookup: "ambiguous"}; }
    let record = items[0].domainData;
    // Ambiguous pages need no complete record, but a unique record must carry
    // its own reference for derivation's authorized-subject equality check.
    if !record.contains("recordReference") { throw "missing-record-reference"; }
    let facts = #{record_reference: record.recordReference};
    // A missing region settles explicitly unresolved before derivation.
    if !record.contains("region") { return #{lookup: "unresolved"}; }
    facts.official_residence_code = record.region;
    #{lookup: "matched", facts: facts}
}
