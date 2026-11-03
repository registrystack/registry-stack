// Minimize the provider envelope before its pinned schema is checked.
fn project(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { throw "invalid-envelope"; }
    let projected = #{total: raw.total};
    if raw.records.type_of() != "array" { throw "invalid-records"; }
    let records = [];
    for original in raw.records {
        if original.type_of() != "map" { throw "invalid-record"; }
        let record = #{};
        if original.contains("returned_child_reference") { record["returned_child_reference"] = original["returned_child_reference"]; }
        if original.contains("parent_references") { record["parent_references"] = original["parent_references"]; }
        if original.contains("reference_namespace") { record["reference_namespace"] = original["reference_namespace"]; }
        if original.contains("relationship_set_contract") { record["relationship_set_contract"] = original["relationship_set_contract"]; }
        if original.contains("relationship_set_complete") { record["relationship_set_complete"] = original["relationship_set_complete"]; }
        records.push(record);
    }
    projected.records = records;
    projected
}

// The caller's grant and subject binding remain outside this provider script.
fn lookup(exchange) {
    let response = exchange.body;
    if response.records.len > 2 { throw "too-many-records"; }
    if response.total == 0 { if response.records.len != 0 { throw "inconsistent-absence"; } return #{lookup: "no-match"}; }
    if response.total > 1 { if response.records.len < 2 { throw "inconsistent-ambiguity"; } return #{lookup: "ambiguous"}; }
    if response.records.len != 1 { throw "inconsistent-record"; }
    let record = response.records[0];
    if !record.contains("returned_child_reference") || !record.contains("parent_references") { throw "incomplete-relationship"; }
    if record.reference_namespace != "urn:example:fixture:person-reference" || record.relationship_set_contract != "urn:example:fixture:legal-parent-set:v1" || record.relationship_set_complete != true { throw "relationship-contract"; }
    #{lookup: "matched", facts: record}
}

fn request(exchange) { #{lookup: #{record_reference: exchange.body["record_reference"]}, fields: ["returned_child_reference", "parent_references", "reference_namespace", "relationship_set_contract", "relationship_set_complete"], limit: 2} }
