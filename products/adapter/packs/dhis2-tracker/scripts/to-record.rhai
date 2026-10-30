// One DHIS2 tracked entity, mapped to the record slot object the
// facade's response envelope wraps.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3), whose body is the fetched entity.
// The record maps `recordIdentifier` from the DHIS2 UID,
// `revisionIdentifier` from the entity's last-update stamp, and
// `domainData` carrying the scalar tracker properties the bound project
// declares. An entity without its UID is a malformed page: the script
// throws and the engine surfaces the script error class. Pure and
// deterministic; no I/O.
fn to_record(exchange) {
    let entity = exchange.body;
    if entity.trackedEntity == () {
        throw "tracked entity carries no UID";
    }
    #{
        recordIdentifier: entity.trackedEntity,
        revisionIdentifier: entity.updatedAt,
        domainData: #{
            tracked_entity_type: entity.trackedEntityType,
            org_unit: entity.orgUnit,
            created_at: entity.createdAt,
            updated_at: entity.updatedAt
        }
    }
}
