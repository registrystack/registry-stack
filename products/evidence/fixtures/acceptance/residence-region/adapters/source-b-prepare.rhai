fn prepare(selectors, parameters) {
    let subject = selectors["subject"];
    #{
        query: [],
        body: #{
            lookup: #{record_reference: subject["values"]["record_reference"]},
            fields: parameters["requestedFields"],
            limit: parameters["resultLimit"]
        }
    }
}
