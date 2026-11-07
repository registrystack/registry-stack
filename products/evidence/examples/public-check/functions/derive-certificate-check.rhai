// Revocation outranks suspension, and suspension outranks expiry. The stored
// check code is never a fact here; Evidence compares it before derivation.
fn derive(facts, selectors, context) {
    let status = "valid";
    if facts.status == "revoked" {
        status = "revoked";
    } else if facts.status == "suspended" {
        status = "suspended";
    } else if compare_dates(context.legal_local_date, parse_date(facts.expiresOn)) > 0 {
        status = "expired";
    }
    [
        #{output: "status", value: status},
        #{output: "printed", value: #{
            form: "reviewed-structured-value",
            schema: "urn:example:schema:certificate-printed-fields",
            fields: #{
                holderName: facts.holderName,
                issuedOn: facts.issuedOn,
                expiresOn: facts.expiresOn
            }
        }}
    ]
}
