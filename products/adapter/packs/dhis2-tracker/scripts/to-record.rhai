// One DHIS2 tracked entity, mapped to the record slot object the
// facade's response envelope wraps.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3), whose body is the fetched entity.
// The record maps `recordIdentifier` from the DHIS2 UID,
// `revisionIdentifier` from the entity's last-update stamp, and
// `domainData` carrying the scalar tracker properties the bound project
// declares. The `attribute_fields` route parameter is held in the
// `dhis2AttributeMap` property as record field to DHIS2 attribute UID. Only
// mapped attributes cross the source boundary. With the default empty map,
// attributes stay out and the existing base record shape is unchanged.
// An entity without its UID, or a malformed attribute row when a project
// asks to read attributes, is refused. Pure and deterministic; no I/O.
fn to_record(exchange) {
    let entity = exchange.body;
    if entity.trackedEntity == () {
        throw "tracked entity carries no UID";
    }
    let data = #{
        tracked_entity_type: entity.trackedEntityType,
        org_unit: entity.orgUnit,
        created_at: entity.createdAt,
        updated_at: entity.updatedAt
    };
    let map = exchange.properties.dhis2AttributeMap;
    if map != () && map.keys().len > 0 {
        let attributes = entity.attributes;
        if attributes == () {
            throw "tracked entity carries no attributes array";
        }
        let seen = #{};
        for attribute in attributes {
            if attribute.attribute == () || attribute.value == () {
                throw "tracked entity carries a malformed attribute row";
            }
            for field in map.keys() {
                if map[field] == attribute.attribute {
                    if seen[field] == true {
                        throw "tracked entity repeats a mapped attribute";
                    }
                    data[field] = attribute.value;
                    seen[field] = true;
                }
            }
        }
    }
    #{
        recordIdentifier: entity.trackedEntity,
        revisionIdentifier: entity.updatedAt,
        domainData: data
    }
}
