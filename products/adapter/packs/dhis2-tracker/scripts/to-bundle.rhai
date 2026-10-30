// The validated facade record, mapped to a DHIS2 tracker import bundle.
//
// The engine evaluates the send's `body` expression on the exchange
// (CONCEPT 8.11.3); for this write operation the exchange body is the
// validated facade request record (CONCEPT 8.11.1). The script returns
// the POST /api/tracker payload: one tracked entity keyed by the
// record's own identifier, so a redelivered import with the same UID
// updates the same object instead of creating a second one (DHIS2 treats
// a payload UID that already exists as an update; see the tracker
// documentation's duplicate-handling rules and error E1002). A record
// without a recordIdentifier, or an org unit, would create an
// upstream-assigned UID or an importable object without a home: the
// script throws instead. Pure and deterministic; no I/O.
fn to_bundle(exchange) {
    let record = exchange.body;
    if record.recordIdentifier == () {
        throw "record carries no recordIdentifier";
    }
    if record.domainData.org_unit == () {
        throw "record carries no org_unit";
    }
    #{
        trackedEntities: [
            #{
                trackedEntity: record.recordIdentifier,
                orgUnit: record.domainData.org_unit,
                attributes: []
            }
        ]
    }
}
