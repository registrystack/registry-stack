// The protected read returns a page of matching items and a pagination
// envelope that says whether further pages exist. It carries no total count,
// so uniqueness is decided from the page itself: how many items came back,
// and whether the provider claims more. The prepared request asks for a page
// of two against an exact reference filter, which is the smallest page that
// can still distinguish one match from several.

fn extract(source_response, context) {
    let parameters = context["parameters"];
    let items = source_response["items"];
    let has_more = !is_missing(source_response["pageInfo"]["nextCursor"]);

    if items.len == 0 {
        // An empty page that still claims further pages contradicts itself.
        // Reading it as no match would turn a broken provider into a clean
        // negative answer.
        if has_more {
            throw("source_protocol_error");
        }
        return #{outcome: "no_match"};
    }
    if items.len > 1 || has_more {
        return #{outcome: "ambiguous"};
    }

    let record = items[0]["domainData"];
    // The shape cannot require this of every record, because an ambiguous page
    // is decided before any record is read. A single matched record with no
    // reference of its own is a source this adapter does not understand.
    if is_missing(record["recordReference"]) {
        throw("source_protocol_error");
    }

    let facts = #{record_reference: record["recordReference"]};
    // A record that carries no region is a record this requirement cannot
    // answer from. The fact schema refuses it, which leaves the requirement
    // unresolved rather than letting derivation invent a region.
    if !is_missing(record["region"]) {
        facts["official_residence_code"] = record["region"];
    }

    #{outcome: "match", facts: facts}
}
