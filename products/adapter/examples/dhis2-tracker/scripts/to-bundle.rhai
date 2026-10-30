// The validated facade record, mapped to a DHIS2 tracker import bundle.
//
// The engine evaluates the send's `body` expression on the exchange
// (CONCEPT 8.11.3); for this write operation the exchange body is the
// validated facade request record (CONCEPT 8.11.1). The script returns
// the POST /api/tracker payload: one tracked entity keyed by the
// record's own identifier, so a redelivered import with the same UID
// updates the same object instead of creating a second one (DHIS2
// treats a payload UID that already exists as an update under the
// default CREATE_AND_UPDATE strategy; error E1002, the create-strategy
// collision refusal, fires only under importStrategy=CREATE, which this
// pack never sends). `trackedEntityType` is a required tracker property
// (error E1121 without it), so the script maps it from the record and
// throws when the record carries none. A record without a
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
                attributes: []
            }
        ]
    }
}
