fn prepare(selectors, parameters) {
    let subject = selectors[parameters["selectorRole"]];
    #{
        query: [],
        body: #{
            query: #{
                type: "and",
                clauses: [#{
                    eventType: parameters["eventType"],
                    status: #{type: "exact", term: parameters["registeredStatus"]},
                    trackingId: #{type: "exact", term: subject["values"]["tracking_id"]}
                }]
            },
            limit: parameters["resultLimit"],
            offset: parameters["resultOffset"]
        }
    }
}
