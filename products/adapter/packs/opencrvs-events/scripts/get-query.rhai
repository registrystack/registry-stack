// The event-search body for one registered event, by tracking ID.
//
// The engine evaluates the send's `body` expression on the exchange
// (CONCEPT 8.11.3); the facade's `recordId` input (CONCEPT 8.11.1) is the
// tracking ID, read from the lowercased `recordid` header. The body is the
// `and` query of the reviewed Evidence reference
// (products/evidence/reference/request-adapter/opencrvs-event-search/
// prepare.rhai): exact event type, exact status REGISTERED, exact tracking
// ID. The limit is 2 on purpose: a second result is how an ambiguous
// tracking ID becomes visible (scripts/get-outcome.rhai), and a limit of 1
// would hide it. The offset is 0. Pure and deterministic; no I/O.
fn get_query(exchange) {
    let tracking_id = exchange.headers.recordid;
    if tracking_id == () {
        throw "request carries no record identifier";
    }
    #{
        query: #{
            type: "and",
            clauses: [#{
                eventType: exchange.properties.opencrvsEventType,
                status: #{ type: "exact", term: "REGISTERED" },
                trackingId: #{ type: "exact", term: tracking_id }
            }]
        },
        limit: 2,
        offset: 0
    }
}
