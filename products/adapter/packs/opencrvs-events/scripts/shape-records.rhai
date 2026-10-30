// The fetched event-search page, mapped record by record.
//
// The engine evaluates the route's final setBody expression on the
// exchange (CONCEPT 8.11.3). The search route answers one facade page from
// one upstream page (CONCEPT 8.11.2), so the body carries exactly the
// results of the fetched page, which the route has already proven sound
// (scripts/page-sound.rhai). Scripts are per-file units, so this file
// carries the per-event mapping itself; it mirrors the `to_record` mapping
// in scripts/to-record.rhai, including the declaration_fields rule, and
// the two change together. Pure and deterministic; no I/O.
fn shape_records(exchange) {
    let map = exchange.properties.opencrvsDeclarationMap;
    let records = [];
    for event in exchange.body.results {
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
        if declaration != () && map != () {
            for field in map.keys() {
                let key = map[field];
                if declaration[key] != () {
                    data[field] = declaration[key];
                }
            }
        }
        records.push(#{
            recordIdentifier: event.trackingId,
            domainData: data
        });
    }
    records
}
