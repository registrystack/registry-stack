fn extract(source_response, parameters) {
    if !source_response.contains("pager") ||
       !source_response.contains("trackedEntities") ||
       type_of(source_response["pager"]) != "map" ||
       type_of(source_response["trackedEntities"]) != "array" ||
       !source_response["pager"].contains("total") ||
       type_of(source_response["pager"]["total"]) != "i64" ||
       source_response["pager"]["total"] < 0 ||
       source_response["trackedEntities"].len > 2 {
        throw("source_protocol_error");
    }

    let total = source_response["pager"]["total"];
    let records = source_response["trackedEntities"];
    if total == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if records.len < 2 { throw("source_protocol_error"); }
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
