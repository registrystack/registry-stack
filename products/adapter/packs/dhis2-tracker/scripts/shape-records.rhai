// The fetched tracker pages, mapped record by record.
//
// The engine calls `shape_records` with the raw tracker instances the
// search loop accumulated and returns the array of record slot objects
// the facade's collection envelope wraps. Scripts are per-file units, so
// this file carries the per-entity mapping itself; it mirrors the
// `to_record` mapping in scripts/to-record.rhai and the two change
// together. An instance without its UID throws. Pure and deterministic;
// no I/O.
fn shape_records(instances) {
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
