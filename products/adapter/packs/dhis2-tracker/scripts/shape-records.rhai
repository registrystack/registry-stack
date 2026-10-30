// The fetched tracker page, mapped record by record.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). The search route answers one facade page
// from one upstream page (CONCEPT 8.11.2), so the body carries exactly
// the instances of the fetched page, the reply's `instances` member.
// Scripts are per-file units, so this file carries the per-entity
// mapping itself; it mirrors the `to_record` mapping in
// scripts/to-record.rhai and the two change together. An instance
// without its UID throws. Pure and deterministic; no I/O.
fn shape_records(exchange) {
    let instances = exchange.body.instances;
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
