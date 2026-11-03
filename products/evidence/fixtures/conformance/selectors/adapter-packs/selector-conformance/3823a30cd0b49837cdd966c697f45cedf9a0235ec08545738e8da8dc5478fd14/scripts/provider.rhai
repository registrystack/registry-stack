// Inputs contain only the exact reviewed profile fields selected by Evidence.
fn request(exchange) {
    #{selector: exchange.body, requested_fields: ["result"]}
}

// Provider metadata and unrelated fields do not enter the fact contract.
fn project(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" || !raw.contains("matched") { throw "invalid-provider-result"; }
    #{matched: raw.matched}
}

fn lookup(exchange) {
    if exchange.body.matched { return #{lookup: "matched", facts: #{result: true}}; }
    #{lookup: "no-match"}
}
