// Whether the Patient search loop fetches another page.
//
// FHIR R4 paging (https://hl7.org/fhir/R4/http.html#paging): a searchset
// Bundle carries `link` entries; the one whose `relation` is `next` names
// the next page. The fetchSearchPage route stores that link's URL in the
// `fhirNextUrl` property, or nothing on the last page. The engine is
// assumed to call `has_next_link` with the exchange map. Pure and
// deterministic; no I/O.
fn has_next_link(exchange) {
    let next = exchange.properties.fhirNextUrl;
    next != () && next != ""
}
