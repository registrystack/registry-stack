fn prepare(selectors, parameters) {
    let subject = selectors["subject"]["values"];
    #{
        query: [],
        body: #{
            selector: #{
                opaque_alpha: subject["alpha"],
                opaque_delta: subject["delta"],
                opaque_kappa: subject["kappa"]
            },
            requested_fields: parameters["requestedFields"]
        }
    }
}
