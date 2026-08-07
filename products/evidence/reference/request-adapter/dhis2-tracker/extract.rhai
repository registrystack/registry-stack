// Extraction runs with fresh state and receives no selectors or request parts.
// The response schema has already refused any envelope outside the declared
// pager and record shape, so what remains is the part a shape cannot state:
// the page count agreeing with the total, and the one attribute this
// requirement names.

fn extract(source_response, context) {
    let parameters = context["parameters"];
    let pager = source_response["pager"];
    let records = source_response["trackedEntities"];

    let expected_page_count =
        (pager["total"] + pager["pageSize"] - 1) / pager["pageSize"];
    if pager["pageCount"] != expected_page_count {
        throw("source_protocol_error");
    }

    if pager["total"] == 0 {
        if records.len != 0 {
            throw("source_protocol_error");
        }
        return #{outcome: "no_match"};
    }

    if pager["total"] > 1 {
        if records.len != 2 {
            throw("source_protocol_error");
        }
        return #{outcome: "ambiguous"};
    }

    if records.len != 1 {
        throw("source_protocol_error");
    }

    let record = records[0];
    let found_status = false;
    let status_code = ();
    for attribute in record["attributes"] {
        if attribute["attribute"] == parameters["statusAttribute"] {
            if found_status {
                throw("source_protocol_error");
            }
            found_status = true;
            status_code = attribute["value"];
        }
    }

    if !found_status {
        throw("source_protocol_error");
    }

    #{outcome: "match", facts: #{status_code: status_code}}
}
