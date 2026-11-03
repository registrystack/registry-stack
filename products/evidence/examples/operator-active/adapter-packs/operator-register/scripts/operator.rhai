// Minimize the provider response before its pinned schema is checked.
fn project(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { throw "invalid-envelope"; }

    let projected = #{};
    if raw.contains("total") { projected.total = raw.total; }
    if raw.contains("record") {
        let raw_record = raw.record;
        if raw_record.type_of() != "map" {
            projected.record = raw_record;
        } else {
            let record = #{};
            if raw_record.contains("operator_id") { record.operator_id = raw_record.operator_id; }
            if raw_record.contains("active") { record.active = raw_record.active; }
            if raw_record.contains("status") { record.status = raw_record.status; }
            if raw_record.contains("address_canary") { record.address_canary = raw_record.address_canary; }
            projected.record = record;
        }
    }
    projected
}

// Resolve one exact operator record and expose only the reviewed private facts.
fn lookup(exchange) {
    let response = exchange.body;
    if response.total == 0 { return #{lookup: "no-match"}; }
    if response.total != 1 { return #{lookup: "ambiguous"}; }
    if !response.contains("record") { throw "missing-record"; }

    let record = response.record;
    if !record.contains("operator_id") || !record.contains("active") || !record.contains("status") || !record.contains("address_canary") { throw "missing-fact"; }
    if record.operator_id != exchange.properties["operator-id"] { throw "identity-mismatch"; }

    #{lookup: "matched", facts: #{
        active: record.active,
        status: record.status,
        "address-canary": record.address_canary,
    }}
}
