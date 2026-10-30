// The validated facade record, mapped to a DHIS2 tracker import bundle.
//
// The engine evaluates the send's `body` expression on the exchange
// (CONCEPT 8.11.3); for this write operation the exchange body is the
// validated facade request record (CONCEPT 8.11.1). The script returns
// the POST /api/tracker payload: one tracked entity keyed by the
// record's own identifier, so a redelivered import with the same UID
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
// record and throws when the record carries none. A record without a
// recordIdentifier, or an org unit, would create an upstream-assigned
// UID or an importable object without a home: the script throws
// instead. Pure and deterministic; no I/O.
fn to_bundle(exchange) {
    let record = exchange.body;
    if record.recordIdentifier == () {
        throw "record carries no recordIdentifier";
    }
    if record.domainData.org_unit == () {
        throw "record carries no org_unit";
    }
    if record.domainData.tracked_entity_type == () {
        throw "record carries no tracked_entity_type";
    }
    #{
        trackedEntities: [
            #{
                trackedEntity: record.recordIdentifier,
                trackedEntityType: record.domainData.tracked_entity_type,
                orgUnit: record.domainData.org_unit,
                // No attributes: DHIS2 reads an empty attribute list as no
                // attribute change, so an import through this pack updates
                // an existing entity's stamps only and never alters an
                // attribute value (captured update with an empty list).
                attributes: []
            }
        ]
    }
}
