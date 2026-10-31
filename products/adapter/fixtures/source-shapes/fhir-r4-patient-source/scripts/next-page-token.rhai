// The continuation token from a FHIR next link, HAPI FHIR's spelling.
//
// FHIR R4 says paging links are opaque to the client
// (https://hl7.org/fhir/R4/http.html#paging). The http component takes a
// fixed path template and fixed query keys, so it cannot follow an opaque
// absolute URL. This script is the workaround the grammar forces: it
// assumes the server is HAPI FHIR, whose next link reads
// `<base>?_getpages=<id>&_getpagesoffset=<n>&_count=<n>&_bundletype=searchset`,
// and extracts the `_getpages` value. Any other server (or a HAPI version
// that changes its spelling) breaks it. The script also cannot check that
// the link's origin is the bound base URL, since the base URL never
// enters the exchange. Pure and deterministic; no I/O.
fn next_page_token(exchange) {
    query_value(next_url(exchange), "_getpages")
}

fn next_page_offset(exchange) {
    query_value(next_url(exchange), "_getpagesoffset")
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
    if url == () {
        throw "the searchset carries no next link";
    }
    url
}

fn query_value(url, name) {
    let start = url.index_of("?");
    if start < 0 {
        throw "the next link carries no query";
    }
    let query = url.sub_string(start + 1);
    for pair in query.split("&") {
        let parts = pair.split("=");
        if parts.len() == 2 && parts[0] == name {
            return parts[1];
        }
    }
    throw "the next link carries no " + name;
}
