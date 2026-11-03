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
        if original.contains("licence_state") { record["licence_state"] = original["licence_state"]; }
        if original.contains("valid_from") { record["valid_from"] = original["valid_from"]; }
        if original.contains("valid_until") { record["valid_until"] = original["valid_until"]; }
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
    if !record.contains("licence_state") || !record.contains("valid_from") || !record.contains("valid_until") { return #{lookup: "unresolved"}; }
    #{lookup: "matched", facts: record}
}
