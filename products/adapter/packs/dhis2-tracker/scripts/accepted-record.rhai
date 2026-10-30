// The accepted record, echoed back to the facade envelope.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). An import that passed the `import_failed`
// check accepted exactly the submitted payload, and the record's own
// identifier is the DHIS2 UID, so the accepted record is the submitted
// record. The send replaces the body with the import summary, so the
// route keeps the submitted record in the `dhis2SubmittedRecord`
// property before the send (the exchange body captured through a
// jsonpath expression), and this script returns it. Pure and
// deterministic; no I/O.
fn accepted_record(exchange) {
    exchange.properties.dhis2SubmittedRecord
}
