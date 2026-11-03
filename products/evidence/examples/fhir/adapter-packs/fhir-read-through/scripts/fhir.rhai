// Minimize raw FHIR resources before pinned provider-schema validation.
fn project_coverage(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { throw "invalid-coverage-resource"; }

    let projected = #{};
    if raw.contains("resourceType") { projected.resourceType = raw.resourceType; }
    if raw.contains("id") { projected.id = raw.id; }
    if raw.contains("status") { projected.status = raw.status; }
    if raw.contains("beneficiary") {
        if raw.beneficiary.type_of() != "map" {
            projected.beneficiary = raw.beneficiary;
        } else {
            let beneficiary = #{};
            if raw.beneficiary.contains("reference") {
                beneficiary.reference = raw.beneficiary.reference;
            }
            projected.beneficiary = beneficiary;
        }
    }
    projected
}

fn lookup_coverage(exchange) {
    let response = exchange.body;
    if response.id != exchange.properties["coverage-id"] {
        throw "coverage-identity-mismatch";
    }
    #{lookup: "matched", facts: #{
        status: response.status,
        "beneficiary-reference": response.beneficiary.reference,
    }}
}

fn project_organization(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { throw "invalid-organization-resource"; }

    let projected = #{};
    if raw.contains("resourceType") { projected.resourceType = raw.resourceType; }
    if raw.contains("id") { projected.id = raw.id; }
    if raw.contains("active") { projected.active = raw.active; }
    if raw.contains("type") {
        if raw.type.type_of() != "array" {
            projected.type = raw.type;
        } else {
            let types = [];
            for raw_type in raw.type {
                if raw_type.type_of() != "map" {
                    types.push(raw_type);
                } else {
                    let organization_type = #{};
                    if raw_type.contains("coding") {
                        if raw_type.coding.type_of() != "array" {
                            organization_type.coding = raw_type.coding;
                        } else {
                            let codings = [];
                            for raw_coding in raw_type.coding {
                                if raw_coding.type_of() != "map" {
                                    codings.push(raw_coding);
                                } else {
                                    let coding = #{};
                                    if raw_coding.contains("system") { coding.system = raw_coding.system; }
                                    if raw_coding.contains("code") { coding.code = raw_coding.code; }
                                    codings.push(coding);
                                }
                            }
                            organization_type.coding = codings;
                        }
                    }
                    types.push(organization_type);
                }
            }
            projected.type = types;
        }
    }
    projected
}

fn lookup_organization(exchange) {
    let response = exchange.body;
    if response.id != exchange.properties["organization-id"] {
        throw "organization-identity-mismatch";
    }

    let coding_count = 0;
    let provider_type = false;
    for organization_type in response.type {
        for coding in organization_type.coding {
            coding_count += 1;
            if coding.system == "http://terminology.hl7.org/CodeSystem/organization-type" &&
               coding.code == "prov" {
                provider_type = true;
            }
        }
    }
    #{lookup: "matched", facts: #{
        active: response.active,
        "provider-type": coding_count == 1 && provider_type,
    }}
}
