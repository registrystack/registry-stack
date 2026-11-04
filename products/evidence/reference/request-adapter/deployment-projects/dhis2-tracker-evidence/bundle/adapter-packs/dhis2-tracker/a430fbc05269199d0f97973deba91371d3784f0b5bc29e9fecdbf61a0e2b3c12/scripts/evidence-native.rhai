// Wrap one validated native DHIS2 entity in Evidence's lookup result. The
// returned UID must equal the authorized input, so a provider cannot answer
// one person's request with another person's facts. No domain fields are
// selected or renamed here; the complete schema-bound native entity remains
// the facts value for a consuming Evidence Source to project.
fn lookup_native_entity(exchange) {
    let entity = exchange.body;
    let expected = exchange.properties.dhis2EvidenceRecordReference;
    if entity.trackedEntity == () {
        throw "tracked entity carries no UID";
    }
    if entity.trackedEntity != expected {
        throw "tracked entity identity does not match the authorized input";
    }
    #{lookup: "matched", facts: entity}
}
