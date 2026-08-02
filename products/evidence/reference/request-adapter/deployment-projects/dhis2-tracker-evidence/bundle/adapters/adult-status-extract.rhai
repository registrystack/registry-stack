// The provider reports the full pager only because the prepared request asks
// for it. Requiring every declared pager field, and requiring the page count
// to agree with the total, keeps a truncated or inconsistent envelope from
// being read as an authoritative no-match or unique match.
fn extract(source_response, parameters) {
    if !source_response.contains("pager") ||
       !source_response.contains("trackedEntities") ||
       type_of(source_response["pager"]) != "map" ||
       type_of(source_response["trackedEntities"]) != "array" {
        throw("source_protocol_error");
    }

    let pager = source_response["pager"];
    let records = source_response["trackedEntities"];
    if pager.len() != 4 ||
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
       records.len > 2 {
        throw("source_protocol_error");
    }

    let total = pager["total"];
    if pager["pageCount"] != (total + pager["pageSize"] - 1) / pager["pageSize"] {
        throw("source_protocol_error");
    }

    if total == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if records.len != 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if records.len != 1 { throw("source_protocol_error"); }

    let record = records[0];
    if !record.contains("trackedEntity") ||
       type_of(record["trackedEntity"]) != "string" ||
       !record.contains("attributes") ||
       type_of(record["attributes"]) != "array" {
        throw("source_protocol_error");
    }

    let date_of_birth = ();
    let matches = 0;
    for attribute in record["attributes"] {
        if type_of(attribute) != "map" ||
           !attribute.contains("attribute") ||
           !attribute.contains("value") {
            throw("source_protocol_error");
        }
        if attribute["attribute"] == parameters["dateOfBirthAttribute"] {
            if type_of(attribute["value"]) != "string" {
                throw("source_protocol_error");
            }
            date_of_birth = attribute["value"];
            matches += 1;
        }
    }
    if matches > 1 { throw("source_protocol_error"); }

    let facts = #{record_reference: record["trackedEntity"]};
    if matches == 1 {
        facts["date_of_birth"] = date_of_birth;
    }

    #{outcome: "match", facts: facts}
}
