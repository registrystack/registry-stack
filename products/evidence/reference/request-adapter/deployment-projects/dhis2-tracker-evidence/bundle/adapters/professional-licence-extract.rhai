// The licence register nests the governing state one level deeper than the
// population register: the tracked entity carries the licence validity dates,
// its enrollment in the licence programme carries the licence state, and that
// enrollment's events carry any recorded practice restriction. Extraction reads
// exactly that nesting and nothing else.

fn licence_enrollments(record, parameters) {
    let selected = [];
    if !record.contains("enrollments") {
        return selected;
    }
    if type_of(record["enrollments"]) != "array" {
        throw("source_protocol_error");
    }
    for enrollment in record["enrollments"] {
        if type_of(enrollment) != "map" ||
           !enrollment.contains("program") ||
           type_of(enrollment["program"]) != "string" {
            throw("source_protocol_error");
        }
        if enrollment["program"] == parameters["program"] {
            selected.push(enrollment);
        }
    }
    selected
}

// An enrollment recording no restriction event at all is read as unrestricted
// only because the deployment declares that reading. A deployment whose
// programme does not record restrictions positively sets the declaration to
// false, and the absent fact leaves the requirement unresolved instead of
// silently asserting an unrestricted licence.
fn unrecorded_restriction(parameters) {
    if parameters["absentRestrictionEventMeansUnrestricted"] {
        return false;
    }
    ()
}

fn restriction_recorded(enrollment, parameters) {
    if !enrollment.contains("events") {
        return unrecorded_restriction(parameters);
    }
    if type_of(enrollment["events"]) != "array" {
        throw("source_protocol_error");
    }
    let stage_present = false;
    for event in enrollment["events"] {
        if type_of(event) != "map" ||
           !event.contains("programStage") ||
           !event.contains("status") ||
           type_of(event["programStage"]) != "string" ||
           type_of(event["status"]) != "string" {
            throw("source_protocol_error");
        }
        if event["programStage"] == parameters["restrictionStage"] {
            if event["status"] == parameters["completedEventStatus"] {
                return true;
            }
            stage_present = true;
        }
    }
    if stage_present {
        return false;
    }
    unrecorded_restriction(parameters)
}

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

    let valid_from = ();
    let valid_until = ();
    let from_matches = 0;
    let until_matches = 0;
    for attribute in record["attributes"] {
        if type_of(attribute) != "map" ||
           !attribute.contains("attribute") ||
           !attribute.contains("value") {
            throw("source_protocol_error");
        }
        if attribute["attribute"] == parameters["validFromAttribute"] {
            if type_of(attribute["value"]) != "string" {
                throw("source_protocol_error");
            }
            valid_from = attribute["value"];
            from_matches += 1;
        }
        if attribute["attribute"] == parameters["validUntilAttribute"] {
            if type_of(attribute["value"]) != "string" {
                throw("source_protocol_error");
            }
            valid_until = attribute["value"];
            until_matches += 1;
        }
    }
    if from_matches > 1 || until_matches > 1 {
        throw("source_protocol_error");
    }

    let facts = #{record_reference: record["trackedEntity"]};
    if from_matches == 1 { facts["valid_from"] = valid_from; }
    if until_matches == 1 { facts["valid_until"] = valid_until; }

    // Two enrollments in one programme leave no reviewed rule for which one
    // governs the licence, so the record is not read at all.
    let enrollments = licence_enrollments(record, parameters);
    if enrollments.len > 1 {
        throw("source_protocol_error");
    }
    if enrollments.len == 1 {
        let enrollment = enrollments[0];
        if !enrollment.contains("status") ||
           type_of(enrollment["status"]) != "string" {
            throw("source_protocol_error");
        }
        facts["licence_state"] = enrollment["status"];
        let restricted = restriction_recorded(enrollment, parameters);
        if type_of(restricted) == "bool" {
            facts["restriction_recorded"] = restricted;
        }
    }

    #{outcome: "match", facts: facts}
}
