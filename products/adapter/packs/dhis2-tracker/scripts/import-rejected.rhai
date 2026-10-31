// Whether an upstream HTTP failure is a refused tracker import.
//
// A failed synchronous import answers HTTP 409 with the import report as
// the body, whose status is ERROR and whose validationReport member
// carries the error reports (captured from DHIS2 2.43.2.1). The engine
// evaluates this clause's `onWhen` predicate on the exchange
// (CONCEPT 8.11.3), whose body is that error body, so only the report
// shape maps to the facade's refused-write problem. A WebMessage error,
// which also carries status ERROR, carries no validationReport member
// and falls through unmatched, as does any body that is absent. Pure and
// deterministic; no I/O.
fn import_rejected(exchange) {
    let body = exchange.body;
    if body == () {
        return false;
    }
    body.status == "ERROR" && body.validationReport != ()
}
