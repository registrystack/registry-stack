fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"]["values"];
    #{
        query: [],
        body: #{
            selector: #{
                grant_given_name: subject["given_name"],
                grant_family_name: subject["family_name"],
                grant_birth_date: subject["birth_date"],
                grant_event_reference: subject["event_reference"]
            },
            requested_fields: parameters["requestedFields"]
        }
    }
}
