fn extract(response, selectors, context) {
    if response.id != selectors.organization.values.organization_id {
        throw("source_protocol_error");
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
    #{outcome: "match", facts: #{
        active: response.active,
        "provider-type": coding_count == 1 && provider_type
    }}
}
