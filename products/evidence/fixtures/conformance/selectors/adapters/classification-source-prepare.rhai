fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"]["values"];
    #{
        query: [],
        body: #{
            selector: #{request_record_reference: subject["record_reference"]},
            requested_fields: parameters["requestedFields"]
        }
    }
}
