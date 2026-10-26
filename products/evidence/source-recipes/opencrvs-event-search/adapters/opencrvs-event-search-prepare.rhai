// Fixed OpenCRVS event-search request preparation. It receives no credential,
// connection origin, or network capability.
fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let child = selectors["child"];
    if child["profile"] != "opencrvs-tracking-id-v1" {
        throw("adapter_input_error");
    }
    #{
        query: [],
        body: #{
            query: #{
                type: "and",
                clauses: [#{
                    eventType: parameters["eventType"],
                    status: #{type: "exact", term: parameters["registeredStatus"]},
                    trackingId: #{type: "exact", term: child["values"]["tracking_id"]}
                }]
            },
            limit: parameters["resultLimit"],
            offset: parameters["resultOffset"]
        }
    }
}
