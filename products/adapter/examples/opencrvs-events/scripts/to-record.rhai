// One OpenCRVS event index entry, mapped to the record slot object the
// facade's response envelope wraps.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3), whose body is the search reply the route has
// already proven to hold exactly one matching registered event
// (scripts/get-outcome.rhai). The record maps `recordIdentifier` from the
// tracking ID and `domainData` from the event index members the bound
// project declares: event_id, tracking_id, status, event_type, and
// date_of_event. The reply carries no revision stamp, so the record
// carries no `revisionIdentifier`.
//
// Declarations are configured per OpenCRVS deployment, so which declaration
// leaves a record exposes is the project's decision: the
// `declaration_fields` route parameter, held in the `opencrvsDeclarationMap`
// property, is a comma-separated list of `declaration.key=record_field`
// pairs. Only a listed key that the event carries is copied, under the
// record field name the project declares; nothing else in the declaration
// passes through. The event index entries are never copied whole. Scripts
// are per-file units, so this file carries the per-event mapping itself;
// it mirrors scripts/shape-records.rhai and the two change together. Pure
// and deterministic; no I/O.
fn to_record(exchange) {
    let event = exchange.body.results[0];
    let data = #{
        event_id: event.id,
        tracking_id: event.trackingId,
        status: event.status,
        event_type: event["type"]
    };
    if event.dateOfEvent != () {
        data.date_of_event = event.dateOfEvent;
    }
    let declaration = event.declaration;
    let map = exchange.properties.opencrvsDeclarationMap;
    if declaration != () && map != () && map != "" {
        for pair in map.split(",") {
            let parts = pair.split("=");
            if parts.len() != 2 {
                throw "declaration_fields holds a pair that is not key=field";
            }
            let key = parts[0].trim();
            let field = parts[1].trim();
            if declaration[key] != () {
                data[field] = declaration[key];
            }
        }
    }
    #{
        recordIdentifier: event.trackingId,
        domainData: data
    }
}
