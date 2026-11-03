// The fetched tracker page, mapped record by record.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). The search route answers one facade page
// from one upstream page (CONCEPT 8.11.2), so the body carries exactly
// the entities of the fetched page, the reply's `trackedEntities`
// member. Scripts are per-file units, so this file carries the
// per-entity mapping itself; it mirrors the `to_record` mapping in
// scripts/to-record.rhai, including the project-owned `attribute_fields`
// disclosure map, and the two change together. A reply with no
// `trackedEntities` member is an unexpected shape and throws; an entity
// without its UID, or a malformed attribute row when attributes are mapped,
// throws. Pure and deterministic; no I/O.
fn shape_records(exchange) {
    let instances = exchange.body.trackedEntities;
    if instances == () {
        throw "tracker reply carries no trackedEntities";
    }
    let records = [];
    for entity in instances {
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
        records.push(#{
            recordIdentifier: entity.trackedEntity,
            revisionIdentifier: entity.updatedAt,
            domainData: data
        });
    }
    records
}
