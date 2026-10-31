// Whether the Patient search loop fetches another page.
//
// FHIR R4 paging (https://hl7.org/fhir/R4/http.html#paging): a searchset
// Bundle carries `link` entries; the one whose `relation` is `next` names
// the next page. The aggregation strategy carries the Bundle's link array
// under `fhirNextUrl`; the fetched marker distinguishes the pre-tested first
// iteration from a fetched page with no next link. Pure and deterministic;
// no I/O.
fn has_next_link(exchange) {
    if exchange.properties.fhirPageFetched == () {
        return true;
    }
    let next = next_url(exchange);
    next != () && next != ""
}

fn next_url(exchange) {
    let next = exchange.properties.fhirNextUrl;
    if next == () || type_of(next) != "array" {
        return next;
    }
    let url = ();
    for link in next {
        if link.relation == "next" {
            if url != () {
                throw "the searchset carries more than one next link";
            }
            url = link.url;
        }
    }
    url
}
