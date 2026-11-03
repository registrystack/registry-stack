// Minimize the provider envelope before its pinned schema is checked.
fn project(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { throw "invalid-envelope"; }
    let projected = #{total: raw.total};
    if raw.contains("date_of_birth") { projected.date_of_birth = raw.date_of_birth; }
    projected
}

// The caller's grant and subject binding remain outside this provider script.
fn lookup(exchange) {
    let response = exchange.body;
    if response.total == 0 { if response.len() != 1 { throw "inconsistent-absence"; } return #{lookup: "no-match"}; }
    if response.total > 1 { return #{lookup: "ambiguous"}; }
    if !response.contains("date_of_birth") { return #{lookup: "unresolved"}; }
    #{lookup: "matched", facts: #{date_of_birth: response["date_of_birth"]}}
}

fn request(exchange) { #{lookup: #{given_name: exchange.body["given_name"], family_name: exchange.body["family_name"], birth_date: exchange.body["birth_date"]}, fields: ["date_of_birth"], limit: 2} }
