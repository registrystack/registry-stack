// Exact identity resolution for the synthetic register. No source credentials or caller context enter this script.
fn unique_record(exchange) {
    let response = exchange.body;
    if response.type_of() != "map" || response.total.type_of() != "i64" || response.total < 0 || response.total > 2 { throw "invalid-total"; }
    if response.total == 0 || response.total == 2 { return (); }
    let record = response.record;
    if record.type_of() != "map" || record.record_id != exchange.properties["record-id"] { throw "identity-mismatch"; }
    record
}

fn unresolved_count(exchange) {
    if exchange.body.total == 0 { #{lookup: "no-match"} } else { #{lookup: "ambiguous"} }
}

fn person(exchange) {
    let record = unique_record(exchange);
    if record == () { return unresolved_count(exchange); }
    if record.birth_date == () || record.residence_region == () || record.address_canary == () { throw "missing-fact"; }
    #{lookup: "matched", facts: #{ "birth-date": record.birth_date, "residence-region": record.residence_region, "address-canary": record.address_canary }}
}

fn licence(exchange) {
    let record = unique_record(exchange);
    if record == () { return unresolved_count(exchange); }
    if record.status == () { throw "missing-fact"; }
    #{lookup: "matched", facts: #{status: record.status}}
}

fn parents(exchange) {
    let record = unique_record(exchange);
    if record == () { return unresolved_count(exchange); }
    if record.complete != true || record.parents.type_of() != "array" { throw "relationship-contract"; }
    #{lookup: "matched", facts: #{parents: record.parents}}
}
