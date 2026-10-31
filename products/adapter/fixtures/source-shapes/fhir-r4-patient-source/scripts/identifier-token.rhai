// The FHIR token search value for the facade's national_id filter.
//
// FHIR R4 token search (https://hl7.org/fhir/R4/search.html#token) takes
// `identifier=[system]|[code]`. The engine is assumed to call
// `identifier_token` with the exchange map: `properties.AdapterFilters`
// holds the facade filters and `properties.fhirIdentifierSystem` the
// template's identifier system. Pure and deterministic; no I/O.
fn identifier_token(exchange) {
    let filters = exchange.properties.AdapterFilters;
    let value = if filters == () { () } else { filters.national_id };
    if value == () {
        throw "the search carries no national_id filter";
    }
    exchange.properties.fhirIdentifierSystem + "|" + value
}
