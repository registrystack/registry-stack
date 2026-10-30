// The fetched tracker page, mapped record by record.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). The search route answers one facade page
// from one upstream page (CONCEPT 8.11.2), so the body carries exactly
// the entities of the fetched page, the reply's `trackedEntities`
// member. Scripts are per-file units, so this file carries the
// per-entity mapping itself; it mirrors the `to_record` mapping in
// scripts/to-record.rhai and the two change together. A reply with no
// `trackedEntities` member is an unexpected shape and throws; an
// entity without its UID throws. Pure and deterministic; no I/O.
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
        records.push(#{
            recordIdentifier: entity.trackedEntity,
            revisionIdentifier: entity.updatedAt,
            domainData: #{
                tracked_entity_type: entity.trackedEntityType,
                org_unit: entity.orgUnit,
                created_at: entity.createdAt,
                updated_at: entity.updatedAt
            }
        });
    }
    records
}
