fn extract(source_response, parameters) {
    if !source_response.contains("pager") ||
       !source_response.contains("trackedEntities") ||
       source_response.len() != 2 {
        throw("source_protocol_error");
    }

    let pager = source_response.pager;
    let records = source_response.trackedEntities;
    if !pager.contains("page") ||
       !pager.contains("pageSize") ||
       !pager.contains("total") ||
       !pager.contains("pageCount") ||
       pager.len() != 4 ||
       type_of(pager.page) != "i64" ||
       type_of(pager.pageSize) != "i64" ||
       type_of(pager.total) != "i64" ||
       type_of(pager.pageCount) != "i64" ||
       pager.page != 1 ||
       pager.pageSize != 2 ||
       pager.total < 0 ||
       pager.total > 2 ||
       pager.total != records.len ||
       (pager.total == 0 && pager.pageCount != 0) ||
       (pager.total > 0 && pager.pageCount != 1) {
        throw("source_protocol_error");
    }

    if records.len == 0 {
        return #{ outcome: "no_match" };
    }
    if records.len > 1 {
        return #{ outcome: "ambiguous" };
    }
    let status_code = ();
    let found_status = false;
    if records[0].len() != 1 ||
       !records[0].contains("attributes") ||
       type_of(records[0].attributes) != "array" {
        throw("source_protocol_error");
    }
    for attribute in records[0].attributes {
        if attribute.len() != 2 ||
           !attribute.contains("attribute") ||
           !attribute.contains("value") ||
           type_of(attribute.attribute) != "string" ||
           type_of(attribute.value) != "string" {
            throw("source_protocol_error");
        }
        if attribute.attribute == parameters["statusAttribute"] {
            if found_status {
                throw("source_protocol_error");
            }
            found_status = true;
            status_code = attribute.value;
        }
    }
    #{
        outcome: "match",
        facts: #{ official_residence_code: status_code }
    }
}
