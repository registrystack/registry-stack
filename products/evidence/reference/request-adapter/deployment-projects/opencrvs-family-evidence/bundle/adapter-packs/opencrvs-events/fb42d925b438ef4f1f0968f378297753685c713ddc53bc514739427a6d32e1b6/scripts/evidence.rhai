// Evidence routes share the provider's registered-event request with the facade.
// Only the declared event members survive into schema validation and facts.
fn project_records(exchange, parents) {
    let raw = exchange.body;
    if raw.type_of() != "map" || !raw.contains("total") || !raw.contains("results") || raw.results.type_of() != "array" {
        throw "invalid-event-page";
    }
    let records = [];
    for event in raw.results {
        if event.type_of() != "map" { throw "invalid-event"; }
        let record = #{};
        for field in ["type", "status", "trackingId"] {
            if event.contains(field) { record[field] = event[field]; }
        }
        if parents {
            if !event.contains("declaration") || event.declaration.type_of() != "map" {
                throw "invalid-declaration";
            }
            let declaration = #{};
            for field in ["mother.personReference", "father.personReference"] {
                if event.declaration.contains(field) { declaration[field] = event.declaration[field]; }
            }
            record.declaration = declaration;
        } else if event.contains("dateOfEvent") {
            record.dateOfEvent = event.dateOfEvent;
        }
        records.push(record);
    }
    #{total: raw.total, results: records}
}

fn project_date(exchange) { project_records(exchange, false) }
fn project_parents(exchange) { project_records(exchange, true) }

// A page has one closed lookup outcome. Matched record identity remains a
// private fact checked against the authorized selector by assertion derivation.
fn lookup_record(response) {
    if response.total == 0 {
        if response.results.len() != 0 { throw "inconsistent-empty-page"; }
        return #{lookup: "no-match"};
    }
    if response.total > 1 {
        if response.results.len() < 2 { throw "inconsistent-ambiguous-page"; }
        return #{lookup: "ambiguous"};
    }
    if response.results.len() != 1 { throw "inconsistent-unique-page"; }
    let record = response.results[0];
    if record["type"] != "birth" || record.status != "REGISTERED" || !record.contains("trackingId") {
        throw "invalid-registered-event";
    }
    #{lookup: "matched", facts: record}
}

fn lookup_date(exchange) {
    let result = lookup_record(exchange.body);
    if result.lookup != "matched" { return result; }
    let record = result.facts;
    if !record.contains("dateOfEvent") { throw "missing-birth-date"; }
    #{lookup: "matched", facts: #{record_tracking_id: record.trackingId, date_of_birth: record.dateOfEvent}}
}

fn lookup_parents(exchange) {
    let result = lookup_record(exchange.body);
    if result.lookup != "matched" { return result; }
    let record = result.facts;
    let references = [];
    for field in ["mother.personReference", "father.personReference"] {
        if record.declaration.contains(field) {
            let reference = record.declaration[field];
            if references.contains(reference) { throw "duplicate-parent-reference"; }
            references.push(reference);
        }
    }
    if references.len() < 1 || references.len() > 2 { throw "incomplete-parent-set"; }
    #{lookup: "matched", facts: #{
        record_tracking_id: record.trackingId,
        parent_references: references,
        reference_namespace: "urn:gov:example:opencrvs:person",
        relationship_set_contract: "urn:gov:example:opencrvs:registered-parent-set:v1",
        relationship_set_complete: true
    }}
}
