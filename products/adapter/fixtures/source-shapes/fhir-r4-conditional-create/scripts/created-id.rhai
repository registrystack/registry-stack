// The logical id of the created or matched Patient, from the
// transaction-response Bundle.
//
// A transaction-response carries one entry per request entry, with
// `response.status` ("201 Created" or "200 OK") and `response.location`
// ("Patient/<id>/_history/<vid>")
// (https://hl7.org/fhir/R4/bundle-definitions.html#Bundle.entry.response).
// The engine calls `created_id` with the exchange map; the response body is
// the transaction-response Bundle.
// Pure and deterministic; no I/O.
fn created_id(exchange) {
    let bundle = exchange.body;
    if bundle.type != "transaction-response" || bundle.entry == () || bundle.entry.len() != 1 {
        throw "the reply is not a one-entry transaction-response";
    }
    let response = bundle.entry[0].response;
    let status = response.status;
    if !(status.starts_with("200") || status.starts_with("201")) {
        throw "the conditional create did not land";
    }
    let parts = response.location.split("/");
    if parts.len() < 2 || parts[0] != "Patient" {
        throw "the location names no Patient";
    }
    parts[1]
}
