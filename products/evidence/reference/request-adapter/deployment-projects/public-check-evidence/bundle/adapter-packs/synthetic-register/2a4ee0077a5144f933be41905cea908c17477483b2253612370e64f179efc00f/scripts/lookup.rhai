// Exact identity resolution for the synthetic certificate register. No source credentials or caller context enter this script.
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

// A record issued before check codes existed has no check_code; the fact is left out so the public check never matches it.
fn certificate(exchange) {
    let record = unique_record(exchange);
    if record == () { return unresolved_count(exchange); }
    if record.status == () || record.holder_name == () || record.issued_on == () || record.expires_on == () { throw "missing-fact"; }
    let facts = #{status: record.status, holderName: record.holder_name, issuedOn: record.issued_on, expiresOn: record.expires_on};
    if record.check_code != () { facts.checkCode = record.check_code; }
    #{lookup: "matched", facts: facts}
}
