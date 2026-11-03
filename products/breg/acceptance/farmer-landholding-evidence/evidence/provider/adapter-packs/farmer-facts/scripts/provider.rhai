fn request_status(exchange) {
    #{reference: exchange.body.reference, fields: ["reference", "active"], limit: 2}
}

fn request_category(exchange) {
    #{reference: exchange.body.reference, fields: ["reference", "category"], limit: 2}
}

fn project_status(exchange) {
    let raw = exchange.body;
    let projected = #{total: raw.total};
    if raw.contains("reference") { projected.reference = raw.reference; }
    if raw.contains("active") { projected.active = raw.active; }
    projected
}

fn project_category(exchange) {
    let raw = exchange.body;
    let projected = #{total: raw.total};
    if raw.contains("reference") { projected.reference = raw.reference; }
    if raw.contains("category") { projected.category = raw.category; }
    projected
}

fn unresolved(exchange) {
    if exchange.body.total == 0 { #{lookup: "no-match"} } else { #{lookup: "ambiguous"} }
}

fn status(exchange) {
    let response = exchange.body;
    if response.total != 1 { return unresolved(exchange); }
    if !response.contains("reference") || response.reference != exchange.properties.reference {
        return #{lookup: "no-match"};
    }
    if !response.contains("active") { return #{lookup: "unresolved"}; }
    #{lookup: "matched", facts: #{active: response.active}}
}

fn category(exchange) {
    let response = exchange.body;
    if response.total != 1 { return unresolved(exchange); }
    if !response.contains("reference") || response.reference != exchange.properties.reference {
        return #{lookup: "no-match"};
    }
    if !response.contains("category") { return #{lookup: "unresolved"}; }
    #{lookup: "matched", facts: #{category: response.category}}
}
