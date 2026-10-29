// JSON:API household resources (https://jsonapi.org/format/#document-resource-objects)
// mapped to breg-records record slot objects.
fn to_households(exchange) {
    let records = [];
    for resource in exchange.properties.households {
        records.push(household(resource));
    }
    records
}

fn household(resource) {
    let attributes = resource.attributes;
    let version = ();
    if resource.meta != () {
        version = resource.meta.version;
    }
    #{
        recordIdentifier: resource.id,
        revisionIdentifier: version,
        domainData: #{
            household_number: attributes.householdNumber,
            region_code: attributes.regionCode,
            member_count: attributes.memberCount,
            registered_on: attributes.registeredOn
        }
    }
}
