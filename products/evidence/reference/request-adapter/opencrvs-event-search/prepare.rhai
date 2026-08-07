// Exploratory exact OpenCRVS child-event request preparation. It has no
// credentials, transport authority, or network access.

fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let child = selectors["child"];
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
