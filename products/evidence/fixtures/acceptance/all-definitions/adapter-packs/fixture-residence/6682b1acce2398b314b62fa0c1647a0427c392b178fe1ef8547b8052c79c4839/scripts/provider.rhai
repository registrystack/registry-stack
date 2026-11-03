// Minimize the provider envelope before its pinned schema is checked.
fn project(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { throw "invalid-envelope"; }
    let projected = #{total: raw.total};
    if raw.contains("official_residence_code") { projected.official_residence_code = raw.official_residence_code; }
    projected
}

// The caller's grant and subject binding remain outside this provider script.
fn lookup(exchange) {
    let response = exchange.body;
    if response.total == 0 { if response.len() != 1 { throw "inconsistent-absence"; } return #{lookup: "no-match"}; }
    if response.total > 1 { return #{lookup: "ambiguous"}; }
    if !response.contains("official_residence_code") { return #{lookup: "unresolved"}; }
    #{lookup: "matched", facts: #{official_residence_code: response["official_residence_code"]}}
}

fn request(exchange) { #{lookup: #{record_reference: exchange.body["record_reference"]}, fields: ["official_residence_code"], limit: 2} }
