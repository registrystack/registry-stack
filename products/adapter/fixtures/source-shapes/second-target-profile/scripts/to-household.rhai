// One JSON:API household resource (`body.data`) mapped to a breg-records
// record slot object. Duplicates the mapping in to-households.rhai: each
// file compiles alone.
fn to_household(exchange) {
    let resource = exchange.body.data;
    if resource == () || resource.type != "households" {
        throw "the document carries no household";
    }
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
