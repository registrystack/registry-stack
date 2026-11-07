// Evidence Function derive-certificate-check interface assertion-derive/v1
// Revocation outranks suspension, and suspension outranks expiry. The stored
// check code is never a fact here; Evidence compares it before derivation.
fn authored_derive(facts, selectors, context) {
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

fn derive(facts, selectors, context) {
    let declared = #{
        "printed": "urn:example:concept:certificate-printed-fields:v1",
        "status": "urn:example:concept:certificate-status:v1",
    };
    let values = authored_derive(facts, selectors, context);
    let result = [];
    for value in values {
        if type_of(value) != "map" || !value.contains("output") || !value.contains("value") || value.len() != 2 || !declared.contains(value.output) { throw("undeclared_output"); }
        result.push(#{concept_id: declared[value.output], value: value.value});
    }
    result
}
