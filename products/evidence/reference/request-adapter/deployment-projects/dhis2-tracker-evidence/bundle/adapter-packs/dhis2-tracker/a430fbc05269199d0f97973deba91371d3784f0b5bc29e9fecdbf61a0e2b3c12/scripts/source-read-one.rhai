// One DHIS2 tracked entity in the source-neutral acquisition contract.
//
// This route deliberately preserves the source entity under `value`. A
// deployment-owned transform selects the caller-visible fields later. The
// stable DHIS2 tracked-entity UID is the item key and the server update stamp
// is its observed revision. Pure and deterministic; no I/O.
fn source_read_one(exchange) {
    let entity = exchange.body;
    if entity.trackedEntity == () {
        throw "tracked entity carries no UID";
    }
    if entity.trackedEntity != exchange.properties.dhis2SourceRecordId {
        throw "tracked entity identity does not match the requested native ID";
    }
    let item = #{key: entity.trackedEntity, value: entity};
    if entity.updatedAt != () {
        item.revision = entity.updatedAt;
    }
    #{items: [item]}
}
