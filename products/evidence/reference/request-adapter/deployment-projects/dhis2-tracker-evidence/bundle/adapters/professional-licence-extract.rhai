// The licence register nests the governing state one level deeper than the
// population register: the tracked entity carries the licence validity dates,
// its enrollment in the licence programme carries the licence state, and that
// enrollment's events carry any recorded practice restriction. The response
// schema states that nesting, so this script reads it without re-checking it,
// and keeps only the readings a shape cannot express.

fn licence_enrollments(record, parameters) {
    let selected = [];
    // A tracked entity with no enrollment at all is a record carrying no
    // licence state, not a malformed response, so absence is read as an empty
    // selection.
    let enrollments = get_path(record, "/enrollments");
    if is_missing(enrollments) {
        return selected;
    }
    for enrollment in enrollments {
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
    let events = get_path(enrollment, "/events");
    if is_missing(events) {
        return unrecorded_restriction(parameters);
    }
    let stage_present = false;
    for event in events {
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
    let pager = source_response["pager"];
    let records = source_response["trackedEntities"];
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
    // The validity attributes are named by adapter parameters, and a register
    // that reports one of them twice has no single value to read, so this loop
    // stays.
    let valid_from = ();
    let valid_until = ();
    let from_matches = 0;
    let until_matches = 0;
    for attribute in record["attributes"] {
        if attribute["attribute"] == parameters["validFromAttribute"] {
            valid_from = attribute["value"];
            from_matches += 1;
        }
        if attribute["attribute"] == parameters["validUntilAttribute"] {
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
        facts["licence_state"] = enrollment["status"];
        let restricted = restriction_recorded(enrollment, parameters);
        if type_of(restricted) == "bool" {
            facts["restriction_recorded"] = restricted;
        }
    }

    #{outcome: "match", facts: facts}
}
