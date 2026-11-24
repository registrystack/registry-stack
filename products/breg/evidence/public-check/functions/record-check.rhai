// The Source facts carry types only, so this function refuses what it cannot
// use: a status outside active and retired, including a status the Source
// left out. The stored check code is never read here. Evidence compares it
// before derivation and runs this function only for a caller who holds it.
fn derive(facts, selectors, context) {
    let status = "valid";
    if facts.status == "retired" {
        status = "revoked";
    } else if facts.status != "active" {
        throw "unknown-status";
    }
    [
        #{output: "status", value: status},
        #{output: "printed", value: #{
            form: "reviewed-structured-value",
            schema: "urn:example:schema:record-check-fields",
            fields: #{recordStatus: facts.status}
        }}
    ]
}
