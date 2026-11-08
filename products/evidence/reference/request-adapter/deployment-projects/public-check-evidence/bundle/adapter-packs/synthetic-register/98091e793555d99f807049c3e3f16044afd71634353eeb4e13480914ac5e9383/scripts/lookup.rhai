// Exact identity resolution for the synthetic certificate register. No source credentials or caller context enter this script.
fn unique_record(exchange) {
    let response = exchange.body;
    if response.type_of() != "map" || response.total.type_of() != "i64" || response.total < 0 || response.total > 2 { throw "invalid-total"; }
    if response.total == 0 || response.total == 2 { return (); }
    let record = response.record;
    if record.type_of() != "map" || record.record_id != exchange.properties["record-id"] { return (); }
    record
}

fn unresolved_count(exchange) {
    if exchange.body.total == 2 { #{lookup: "ambiguous"} } else { #{lookup: "no-match"} }
}

// The public check compares the check code only after a record is returned, so a refusal that depends on one record's content
// (a schema failure, a throw) would show that the record exists. This script therefore never throws on record content:
// a record that is not for the requested number is a no-match, and a fact that is absent or not a string is left out.
// The derivation runs after the comparison and refuses what it cannot use.
fn string_facts(record) {
    let names = #{status: "status", holderName: "holder_name", issuedOn: "issued_on", expiresOn: "expires_on", checkCode: "check_code"};
    let facts = #{};
    for fact in names.keys() {
        let value = record[names[fact]];
        if value.type_of() == "string" { facts[fact] = value; }
    }
    facts
}

// A record issued before check codes existed has no check_code; the fact is left out so the public check never matches it.
fn certificate(exchange) {
    let record = unique_record(exchange);
    if record == () { return unresolved_count(exchange); }
    #{lookup: "matched", facts: string_facts(record)}
}
