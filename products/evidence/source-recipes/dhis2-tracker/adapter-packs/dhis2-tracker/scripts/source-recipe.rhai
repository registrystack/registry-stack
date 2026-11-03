// The pack route projects only reviewed provider members before validation.
// Exact returned identity remains a private fact and must agree with the
// minimized authorized input before any facts reach assertion derivation.
fn selected_members(value, names) {
    if value.type_of() != "map" { return value; }
    let selected = #{};
    for name in names {
        if value.contains(name) { selected[name] = value[name]; }
    }
    selected
}

fn project_response(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { return raw; }
    let projected = #{};
    if raw.contains("pager") {
        projected.pager = selected_members(raw.pager, ["page", "pageSize", "total", "pageCount"]);
    }
    if raw.contains("trackedEntities") {
        if raw.trackedEntities.type_of() != "array" {
            projected.trackedEntities = raw.trackedEntities;
        } else {
            let records = [];
            for record in raw.trackedEntities {
                if record.type_of() != "map" {
                    records.push(record);
                    continue;
                }
                let selected = selected_members(record, ["trackedEntity"]);
                if record.contains("attributes") {
                    if record.attributes.type_of() != "array" {
                        selected.attributes = record.attributes;
                    } else {
                        let attributes = [];
                        for attribute in record.attributes {
                            attributes.push(selected_members(attribute, ["attribute", "value"]));
                        }
                        selected.attributes = attributes;
                    }
                }
                records.push(selected);
            }
            projected.trackedEntities = records;
        }
    }
    projected
}

fn lookup(exchange) {
    let response = exchange.body;
    let pager = response.pager;
    let records = response.trackedEntities;
    let expected_page_count = (pager.total + pager.pageSize - 1) / pager.pageSize;
    if pager.pageCount != expected_page_count { throw "inconsistent-page-count"; }
    if pager.total == 0 {
        if records.len() != 0 { throw "inconsistent-empty-page"; }
        return #{lookup: "no-match"};
    }
    if pager.total > 1 {
        if records.len() != 2 { throw "inconsistent-ambiguous-page"; }
        return #{lookup: "ambiguous"};
    }
    if records.len() != 1 { throw "inconsistent-unique-page"; }

    let record = records[0];
    if !record.contains("trackedEntity") { throw "missing-tracked-entity"; }
    let returned_reference = record.trackedEntity;
    let expected_reference = exchange.properties.requestedRecordReference;
    if returned_reference.type_of() != expected_reference.type_of() || returned_reference != expected_reference {
        throw "returned-identity-mismatch";
    }
    if !record.contains("attributes") { throw "missing-attributes"; }
    let found = [];
    for attribute in record.attributes {
        if attribute.attribute == "Sta00000001" { found.push(attribute.value); }
    }
    if found.len() != 1 { throw "status-attribute-not-unique"; }
    #{lookup: "matched", facts: #{
        record_reference: returned_reference,
        status_code: found[0]
    }}
}
