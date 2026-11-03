fn request_search(exchange) {
    let input = exchange.body;
    #{
        lookup: #{
            family_name: input.family_name,
            given_name: input.given_name,
            date_of_birth: input.date_of_birth
        },
        fields: ["civil_record_reference", "reference_namespace"],
        limit: 2
    }
}

fn project_search(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" || !raw.contains("total") || !raw.contains("records") {
        throw "invalid-civil-search";
    }
    let records = [];
    for record in raw.records {
        let projected = #{};
        if record.contains("civil_record_reference") {
            projected.civil_record_reference = record.civil_record_reference;
        }
        if record.contains("reference_namespace") {
            projected.reference_namespace = record.reference_namespace;
        }
        records.push(projected);
    }
    #{total: raw.total, records: records}
}

fn search_lookup(exchange) {
    let response = exchange.body;
    if response.records.len > 2 { throw "civil-search-over-limit"; }
    if response.total == 0 {
        if response.records.len != 0 { throw "inconsistent-civil-absence"; }
        return #{lookup: "no-match"};
    }
    if response.total > 1 {
        if response.records.len < 2 { throw "inconsistent-civil-ambiguity"; }
        return #{lookup: "ambiguous"};
    }
    if response.total != 1 || response.records.len != 1 {
        throw "inconsistent-civil-match";
    }
    let record = response.records[0];
    if !record.contains("civil_record_reference") ||
       record.reference_namespace != "urn:example:fixture:civil-record" {
        throw "invalid-civil-reference";
    }
    #{lookup: "matched", facts: #{
        civil_record_reference: record.civil_record_reference,
        reference_namespace: record.reference_namespace
    }}
}

fn is_match(exchange) { exchange.body.lookup == "matched" }
fn search_facts(exchange) { exchange.body.facts }
fn civil_reference(exchange) { exchange.body.facts.civil_record_reference }

fn project_union(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" || !raw.contains("record_found") {
        throw "invalid-union-response";
    }
    let projected = #{record_found: raw.record_found};
    if raw.contains("union_events") {
        let events = [];
        for event in raw.union_events {
            let item = #{};
            if event.contains("union_start_date") { item.union_start_date = event.union_start_date; }
            if event.contains("union_end_reason") { item.union_end_reason = event.union_end_reason; }
            if event.contains("union_recognized") { item.union_recognized = event.union_recognized; }
            events.push(item);
        }
        projected.union_events = events;
    }
    if raw.contains("union_set_contract") { projected.union_set_contract = raw.union_set_contract; }
    if raw.contains("union_set_complete") { projected.union_set_complete = raw.union_set_complete; }
    projected
}

fn union_facts(exchange) {
    let response = exchange.body;
    if response.record_found != true ||
       !response.contains("union_events") ||
       !response.contains("union_set_contract") ||
       !response.contains("union_set_complete") ||
       response.union_events.len > 8 ||
       response.union_set_contract != "urn:example:fixture:union-set:v1" {
        throw "unresolved-union-register";
    }
    for event in response.union_events {
        if !event.contains("union_start_date") ||
           !event.contains("union_end_reason") ||
           !event.contains("union_recognized") {
            return #{lookup: "unresolved"};
        }
        let reason = event.union_end_reason;
        if reason != "death-of-other-party" &&
           reason != "dissolution" &&
           reason != "annulment" &&
           reason != "ongoing" {
            return #{lookup: "unresolved"};
        }
    }
    #{
        union_events: response.union_events,
        union_set_contract: response.union_set_contract,
        union_set_complete: response.union_set_complete
    }
}

fn union_facts_resolved(exchange) { !exchange.body.contains("lookup") }

fn request_death(exchange) {
    #{subject_reference: exchange.properties.civilReference}
}

fn project_death(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" || !raw.contains("record_found") {
        throw "invalid-death-response";
    }
    let projected = #{record_found: raw.record_found};
    if raw.contains("death_subject_reference") { projected.death_subject_reference = raw.death_subject_reference; }
    if raw.contains("death_recorded") { projected.death_recorded = raw.death_recorded; }
    if raw.contains("death_record_contract") { projected.death_record_contract = raw.death_record_contract; }
    if raw.contains("death_record_complete") { projected.death_record_complete = raw.death_record_complete; }
    projected
}

fn death_facts(exchange) {
    let response = exchange.body;
    if response.record_found != true ||
       !response.contains("death_subject_reference") ||
       !response.contains("death_recorded") ||
       !response.contains("death_record_contract") ||
       !response.contains("death_record_complete") ||
       response.death_record_contract != "urn:example:fixture:death-register:v1" {
        throw "unresolved-death-register";
    }
    #{
        death_subject_reference: response.death_subject_reference,
        death_recorded: response.death_recorded,
        death_record_contract: response.death_record_contract,
        death_record_complete: response.death_record_complete
    }
}

fn combined_lookup(exchange) {
    let search = exchange.properties.searchFacts;
    let union = exchange.properties.unionFacts;
    let death = exchange.body;
    #{lookup: "matched", facts: #{
        civil_record_reference: search.civil_record_reference,
        reference_namespace: search.reference_namespace,
        union_events: union.union_events,
        union_set_contract: union.union_set_contract,
        union_set_complete: union.union_set_complete,
        death_subject_reference: death.death_subject_reference,
        death_recorded: death.death_recorded,
        death_record_contract: death.death_record_contract,
        death_record_complete: death.death_record_complete
    }}
}
