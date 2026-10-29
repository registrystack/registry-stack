// The accepted record, echoed back to the facade envelope.
//
// The engine calls `accepted_record` with the write exchange's map,
// which carries the validated record under `record`. An import that
// passed the `import_failed` check accepted exactly the submitted
// payload, and the record's own identifier is the DHIS2 UID, so the
// accepted record is the submitted record. Pure and deterministic; no
// I/O.
fn accepted_record(exchange) {
    exchange.record
}
