// The FHIR token search value for the facade's national_id filter.
//
// FHIR R4 token search (https://hl7.org/fhir/R4/search.html#token) takes
// `identifier=[system]|[code]`. The engine is assumed to call
// `identifier_token` with the exchange map: `headers.national_id` holds the
// facade filter value and `properties.fhirIdentifierSystem` the template's
// identifier system. That input view is an assumption: no document names
// what a `rhai` expression receives (see the experiment README). Pure and
// deterministic; no I/O.
fn identifier_token(exchange) {
    let value = exchange.headers.national_id;
    if value == () {
        throw "the search carries no national_id filter";
    }
    exchange.properties.fhirIdentifierSystem + "|" + value
}
