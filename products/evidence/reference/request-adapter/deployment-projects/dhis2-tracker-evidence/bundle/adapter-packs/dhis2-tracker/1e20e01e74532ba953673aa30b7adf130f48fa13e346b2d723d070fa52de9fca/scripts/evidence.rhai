// Evidence routes keep the DHIS2 provider request in the maintained pack and
// expose only the reviewed pager, record, attribute, enrollment, and event
// members to schema validation and lookup classification.
fn selected_members(value, names) {
    if value.type_of() != "map" { return value; }
    let selected = #{};
    for name in names {
        if value.contains(name) { selected[name] = value[name]; }
    }
    selected
}

fn selected_attributes(value) {
    if value.type_of() != "array" { return value; }
    let selected = [];
    for attribute in value {
        selected.push(selected_members(attribute, ["attribute", "value"]));
    }
    selected
}

fn selected_events(value) {
    if value.type_of() != "array" { return value; }
    let selected = [];
    for event in value {
        selected.push(selected_members(event, ["programStage", "status"]));
    }
    selected
}

fn selected_enrollments(value) {
    if value.type_of() != "array" { return value; }
    let selected = [];
    for enrollment in value {
        if enrollment.type_of() != "map" {
            selected.push(enrollment);
            continue;
        }
        let projected = selected_members(enrollment, ["program", "status"]);
        if enrollment.contains("events") {
            projected.events = selected_events(enrollment.events);
        }
        selected.push(projected);
    }
    selected
}

fn project_tracker(exchange, include_enrollments) {
    let raw = exchange.body;
    if raw.type_of() != "map" { return raw; }
    let projected = #{};
    if raw.contains("pager") {
        projected.pager = selected_members(
            raw.pager,
            ["page", "pageSize", "total", "pageCount"]
        );
    }
    if raw.contains("trackedEntities") {
        if raw.trackedEntities.type_of() != "array" {
            projected.trackedEntities = raw.trackedEntities;
        } else {
            let records = [];
            for record in raw.trackedEntities {
                if record.type_of() != "map" {
                    records.push(record);
                    continue;
                }
                let selected = selected_members(record, ["trackedEntity"]);
                if record.contains("attributes") {
                    selected.attributes = selected_attributes(record.attributes);
                }
                if include_enrollments && record.contains("enrollments") {
                    selected.enrollments = selected_enrollments(record.enrollments);
                }
                records.push(selected);
            }
            projected.trackedEntities = records;
        }
    }
    projected
}

fn project_adult(exchange) { project_tracker(exchange, false) }
fn project_professional_licence(exchange) { project_tracker(exchange, true) }

fn unique_record(response) {
    let pager = response.pager;
    let records = response.trackedEntities;
    let total = pager.total;
    if pager.pageCount != (total + pager.pageSize - 1) / pager.pageSize {
        throw "inconsistent-page-count";
    }
    if total == 0 {
        if records.len() != 0 { throw "inconsistent-empty-page"; }
        return #{lookup: "no-match"};
    }
    if total > 1 {
        if records.len() != 2 { throw "inconsistent-ambiguous-page"; }
        return #{lookup: "ambiguous"};
    }
    if records.len() != 1 { throw "inconsistent-unique-page"; }
    let record = records[0];
    if !record.contains("trackedEntity") { throw "missing-tracked-entity"; }
    #{lookup: "matched", facts: record}
}

fn attribute_value(record, attribute_id) {
    let value = ();
    let matches = 0;
    if record.contains("attributes") {
        for attribute in record.attributes {
            if attribute.attribute == attribute_id {
                value = attribute.value;
                matches += 1;
            }
        }
    }
    if matches > 1 { throw "duplicate-attribute"; }
    if matches == 1 { return value; }
    ()
}

fn lookup_adult(exchange) {
    let result = unique_record(exchange.body);
    if result.lookup != "matched" { return result; }
    let record = result.facts;
    let facts = #{record_reference: record.trackedEntity};
    let date_of_birth = attribute_value(record, "Dob00000001");
    if date_of_birth.type_of() == "()" { return #{lookup: "unresolved"}; }
    facts.date_of_birth = date_of_birth;
    #{lookup: "matched", facts: facts}
}

fn restriction_recorded(enrollment) {
    if !enrollment.contains("events") { return false; }
    for event in enrollment.events {
        if event.programStage == "Rst00000001" && event.status == "COMPLETED" {
            return true;
        }
    }
    false
}

fn lookup_professional_licence(exchange) {
    let result = unique_record(exchange.body);
    if result.lookup != "matched" { return result; }
    let record = result.facts;
    let facts = #{record_reference: record.trackedEntity};
    let valid_from = attribute_value(record, "Vfr00000001");
    let valid_until = attribute_value(record, "Vun00000001");
    if valid_from.type_of() != "()" { facts.valid_from = valid_from; }
    if valid_until.type_of() != "()" { facts.valid_until = valid_until; }

    let selected = [];
    if record.contains("enrollments") {
        for enrollment in record.enrollments {
            if enrollment.program == "Prg00000002" { selected.push(enrollment); }
        }
    }
    if selected.len() > 1 { throw "duplicate-licence-enrollment"; }
    if selected.len() == 0 { return #{lookup: "unresolved"}; }
    if valid_from.type_of() == "()" || valid_until.type_of() == "()" {
        return #{lookup: "unresolved"};
    }
    facts.licence_state = selected[0].status;
    facts.restriction_recorded = restriction_recorded(selected[0]);
    #{lookup: "matched", facts: facts}
}
