// The event-search body for one registered event, by tracking ID.
//
// The engine evaluates the send's `body` expression on the exchange
// (CONCEPT 8.11.3). The facade entrypoint reads its host-owned `recordId`
// input from the lowercased header; the Evidence entrypoint reads the
// minimized Source input directly from the body. Both call the same pure
// helper, so neither host has to impersonate the other's input channel.
// The body is the `and` query of the reviewed Evidence reference
// (products/evidence/reference/request-adapter/opencrvs-event-search/
// prepare.rhai): exact event type, exact status REGISTERED, exact tracking
// ID. The limit is 2 on purpose: a second result is how an ambiguous
// tracking ID becomes visible (scripts/get-outcome.rhai), and a limit of 1
// would hide it. The offset is 0. Pure and deterministic; no I/O.
fn registered_event_query(event_type, tracking_id) {
    if tracking_id == () {
        throw "request carries no record identifier";
    }
    #{
        query: #{
            type: "and",
            clauses: [#{
                eventType: event_type,
                status: #{ type: "exact", term: "REGISTERED" },
                trackingId: #{ type: "exact", term: tracking_id }
            }]
        },
        limit: 2,
        offset: 0
    }
}

fn get_query(exchange) {
    registered_event_query(exchange.properties.opencrvsEventType, exchange.headers.recordid)
}

fn source_query(exchange) {
    registered_event_query(exchange.properties.opencrvsEventType, exchange.body.trackingId)
}
