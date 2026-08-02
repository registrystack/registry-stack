// Extraction runs with fresh state and receives no selectors or request parts.

fn extract(source_response, parameters) {
    if len(source_response) != 2 ||
       !source_response.contains("pager") ||
       !source_response.contains("trackedEntities") {
        throw("source_protocol_error");
    }

    let pager = source_response["pager"];
    let records = source_response["trackedEntities"];
    if len(pager) != 4 ||
       !pager.contains("page") ||
       !pager.contains("pageSize") ||
       !pager.contains("total") ||
       !pager.contains("pageCount") ||
       type_of(pager["page"]) != "i64" ||
       type_of(pager["pageSize"]) != "i64" ||
       type_of(pager["total"]) != "i64" ||
       type_of(pager["pageCount"]) != "i64" ||
       pager["page"] != 1 ||
       pager["pageSize"] != 2 ||
       pager["total"] < 0 ||
       pager["pageCount"] < 0 ||
       records.len > 2 {
        throw("source_protocol_error");
    }

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

    if pager["total"] != 1 || records.len != 1 {
        throw("source_protocol_error");
    }

    let record = records[0];
    if len(record) != 2 ||
       !record.contains("trackedEntity") ||
       !record.contains("attributes") {
        throw("source_protocol_error");
    }

    let found_status = false;
    let status_code = ();
    for attribute in record["attributes"] {
        if len(attribute) != 2 ||
           !attribute.contains("attribute") ||
           !attribute.contains("value") {
            throw("source_protocol_error");
        }
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
