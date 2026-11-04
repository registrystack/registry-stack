// Exact native reads must not accept a source object under another identity.
// These predicates contain no domain policy and expose no values.
fn source_identity_mismatch(exchange) {
    exchange.body.trackedEntity == ()
        || exchange.body.trackedEntity != exchange.properties.dhis2SourceRecordId
}

fn evidence_identity_mismatch(exchange) {
    exchange.body.trackedEntity == ()
        || exchange.body.trackedEntity != exchange.properties.dhis2EvidenceRecordReference
}
