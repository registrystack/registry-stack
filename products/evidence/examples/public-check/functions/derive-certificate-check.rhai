// Revocation outranks suspension, and suspension outranks expiry. The stored
// check code is never a fact here; Evidence compares it before derivation.
// The source facts carry types only, so this function refuses what it cannot
// use: a status outside active, suspended and revoked, and a missing or
// malformed name or date. Evidence runs it only for a caller who holds the
// right check code.
fn require_string(value, name) {
    if value.type_of() != "string" || value == "" { throw "missing-" + name; }
    value
}

fn derive(facts, selectors, context) {
    let holder = require_string(facts.holderName, "holder-name");
    let issued = require_string(facts.issuedOn, "issued-on");
    let expires = require_string(facts.expiresOn, "expires-on");
    // parse_date refuses anything that is not a YYYY-MM-DD calendar date.
    parse_date(issued);
    let expiry = parse_date(expires);
    let status = "valid";
    if facts.status == "revoked" {
        status = "revoked";
    } else if facts.status == "suspended" {
        status = "suspended";
    } else if facts.status != "active" {
        throw "unknown-status";
    } else if compare_dates(context.legal_local_date, expiry) > 0 {
        status = "expired";
    }
    [
        #{output: "status", value: status},
        #{output: "printed", value: #{
            form: "reviewed-structured-value",
            schema: "urn:example:schema:certificate-printed-fields",
            fields: #{
                holderName: holder,
                issuedOn: issued,
                expiresOn: expires
            }
        }}
    ]
}
