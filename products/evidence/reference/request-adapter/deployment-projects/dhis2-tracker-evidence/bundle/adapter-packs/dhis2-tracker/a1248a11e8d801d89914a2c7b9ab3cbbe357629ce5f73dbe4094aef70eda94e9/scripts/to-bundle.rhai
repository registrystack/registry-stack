// The validated facade record, mapped to a DHIS2 tracker import bundle.
//
// The engine evaluates the send's `body` expression on the exchange
// (CONCEPT 8.11.3); for this write operation the exchange body is the
// validated facade request record (CONCEPT 8.11.1). The script returns
// the POST /api/tracker payload: one tracked entity keyed by the
// validated recordId header for both create and update, so a redelivered
// import with the same UID
// updates the same object instead of creating a second one; the capture
// answers such a repeat with status OK and stats.updated 1, provided the
// deployment's account reaches a program of the entity's type (a repeat
// without one is refused with E1323; the pack header carries the
// precondition). The documentation's E1002 create-strategy refusal fires
// only under importStrategy=CREATE, which this pack never sends and the
// capture never observed. `trackedEntityType` is a required tracker
// property (the capture refuses the omission with E1121), and on a real
// server it is the tracked-entity-type UID, so the record's
// tracked_entity_type carries that UID; the script maps it from the
// record and throws when the record carries none. The facade derives the
// recordId header from the authored request envelope and validates it against
// the update path when present. A missing recordId header or org unit would
// create an upstream-assigned UID or an importable object without a home: the
// script throws instead. The `attribute_fields` route parameter is held in the
// `dhis2AttributeMap` property as record field to DHIS2 attribute UID. Only
// mapped fields that the validated record carries become attribute rows;
// every other record field is excluded. The default empty map preserves the
// earlier no-attribute payload. Pure and deterministic; no I/O.
fn to_bundle(exchange) {
    let record = exchange.body;
    let record_id = exchange.headers.recordid;
    if record_id == () || record_id == "" {
        throw "exchange carries no recordId header";
    }
    if record.org_unit == () {
        throw "record carries no org_unit";
    }
    if record.tracked_entity_type == () {
        throw "record carries no tracked_entity_type";
    }
    let attributes = [];
    let map = exchange.properties.dhis2AttributeMap;
    if map != () {
        for field in map.keys() {
            let value = record[field];
            if value != () {
                attributes.push(#{attribute: map[field], value: value});
            }
        }
    }
    #{
        trackedEntities: [
            #{
                trackedEntity: record_id,
                trackedEntityType: record.tracked_entity_type,
                orgUnit: record.org_unit,
                attributes: attributes
            }
        ]
    }
}
