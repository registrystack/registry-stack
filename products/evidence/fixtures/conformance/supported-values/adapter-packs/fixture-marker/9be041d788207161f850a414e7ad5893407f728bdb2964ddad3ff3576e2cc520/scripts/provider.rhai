// Minimize the provider envelope before its pinned schema is checked.
fn project(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { throw "invalid-envelope"; }
    let projected = #{total: raw.total};
    if raw.contains("marker") { projected.marker = raw.marker; }
    projected
}

// The caller's grant and subject binding remain outside this provider script.
fn lookup(exchange) {
    let response = exchange.body;
    if response.total == 0 { if response.len() != 1 { throw "inconsistent-absence"; } return #{lookup: "no-match"}; }
    if response.total > 1 { return #{lookup: "ambiguous"}; }
    if !response.contains("marker") { return #{lookup: "unresolved"}; }
    #{lookup: "matched", facts: #{marker: response["marker"]}}
}

fn request(exchange) { #{lookup: #{opaque_id: exchange.body["opaque_id"]}, fields: ["marker"], limit: 2} }
