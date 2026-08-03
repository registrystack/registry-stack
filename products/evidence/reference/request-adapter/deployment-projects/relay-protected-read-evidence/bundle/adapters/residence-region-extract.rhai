// The protected read returns a page of matching records and a pagination
// envelope that says whether further pages exist. It carries no total count,
// so uniqueness is decided from the page itself: how many records came back,
// and whether the provider claims more. The prepared request asks for a page
// of two against an exact reference filter, which is the smallest page that
// can still distinguish one match from several.

fn extract(source_response, parameters) {
    let records = source_response["data"];
    let has_more = source_response["pagination"]["has_more"];

    if records.len == 0 {
        // An empty page that still claims further pages contradicts itself.
        // Reading it as no match would turn a broken provider into a clean
        // negative answer.
        if has_more {
            throw("source_protocol_error");
        }
        return #{outcome: "no_match"};
    }
    if records.len > 1 || has_more {
        return #{outcome: "ambiguous"};
    }

    let record = records[0];
    // The shape cannot require this of every record, because an ambiguous page
    // is decided before any record is read. A single matched record with no
    // reference of its own is a source this adapter does not understand.
    if is_missing(record["id"]) {
        throw("source_protocol_error");
    }

    let facts = #{record_reference: record["id"]};
    // A record that carries no region is a record this requirement cannot
    // answer from. The fact schema refuses it, which leaves the requirement
    // unresolved rather than letting derivation invent a region.
    if !is_missing(record["region"]) {
        facts["official_residence_code"] = record["region"];
    }

    #{outcome: "match", facts: facts}
}
