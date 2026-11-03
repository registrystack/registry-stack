// The pack route prepares the fixed read-only event search, projects only the
// reviewed provider members, and checks exact returned identity before facts.
fn prepare_query(exchange) {
    let tracking_id = exchange.properties.requestedTrackingId;
    #{
        query: #{
            type: "and",
            clauses: [#{
                eventType: "birth",
                status: #{type: "exact", term: "REGISTERED"},
                trackingId: #{type: "exact", term: tracking_id}
            }]
        },
        limit: 2,
        offset: 0
    }
}

fn project_response(exchange) {
    let raw = exchange.body;
    if raw.type_of() != "map" { return raw; }
    let projected = #{};
    if raw.contains("total") { projected.total = raw.total; }
    if raw.contains("results") {
        if raw.results.type_of() != "array" {
            projected.results = raw.results;
        } else {
            let results = [];
            for event in raw.results {
                if event.type_of() != "map" {
                    results.push(event);
                    continue;
                }
                let selected = #{};
                for field in ["type", "status", "trackingId"] {
                    if event.contains(field) { selected[field] = event[field]; }
                }
                if event.contains("declaration") {
                    if event.declaration.type_of() != "map" {
                        selected.declaration = event.declaration;
                    } else {
                        let declaration = #{};
                        for field in ["mother.personReference", "father.personReference"] {
                            if event.declaration.contains(field) { declaration[field] = event.declaration[field]; }
                        }
                        selected.declaration = declaration;
                    }
                }
                results.push(selected);
            }
            projected.results = results;
        }
    }
    projected
}

fn lookup(exchange) {
    let response = exchange.body;
    if response.results.len() > 2 { throw "too-many-results"; }
    if response.total == 0 {
        if response.results.len() != 0 { throw "inconsistent-empty-page"; }
        return #{lookup: "no-match"};
    }
    if response.total > 1 {
        if response.results.len() < 2 { throw "inconsistent-ambiguous-page"; }
        return #{lookup: "ambiguous"};
    }
    if response.results.len() != 1 { throw "inconsistent-unique-page"; }

    let result = response.results[0];
    if !result.contains("type") || result.type != "birth" ||
       !result.contains("status") || result.status != "REGISTERED" ||
       !result.contains("trackingId") {
        throw "invalid-registered-event";
    }
    let returned_tracking_id = result.trackingId;
    let expected_tracking_id = exchange.properties.requestedTrackingId;
    if returned_tracking_id.type_of() != expected_tracking_id.type_of() || returned_tracking_id != expected_tracking_id {
        throw "returned-identity-mismatch";
    }
    if !result.contains("declaration") { throw "missing-declaration"; }
    let parent_references = [];
    for field in ["mother.personReference", "father.personReference"] {
        if result.declaration.contains(field) {
            let reference = result.declaration[field];
            if parent_references.contains(reference) { throw "duplicate-parent-reference"; }
            parent_references.push(reference);
        }
    }
    if parent_references.len() < 1 || parent_references.len() > 2 {
        throw "incomplete-parent-set";
    }
    #{lookup: "matched", facts: #{
        record_tracking_id: returned_tracking_id,
        parent_references: parent_references,
        reference_namespace: "urn:gov:example:opencrvs:person",
        relationship_set_contract: "urn:gov:example:opencrvs:registered-parent-set:v1",
        relationship_set_complete: true
    }}
}
