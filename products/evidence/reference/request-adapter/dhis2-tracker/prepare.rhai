// Exploratory trusted request preparation. Rust supplies only authorized
// selectors and non-secret parameters from the immutable bundle.

fn dhis2_filter_value(value) {
    // DHIS2 uses slash escaping inside filter expressions. Rust performs URL
    // encoding on the complete raw query value after preparation.
    let escaped = value;
    escaped.replace("/", "//");
    escaped.replace(":", "/:");
    escaped.replace(",", "/,");
    escaped
}

fn exact_filter(attribute, value) {
    attribute + ":EQ:" + dhis2_filter_value(value)
}

fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    let query = [
        #{name: "program", value: parameters["program"]},
        #{name: "orgUnits", value: parameters["organisationUnit"]},
        #{name: "fields", value: parameters["projection"]},
        #{name: "pageSize", value: parameters["pageSize"]},
        #{name: "page", value: parameters["page"]},
        #{name: "totalPages", value: parameters["totalPages"]}
    ];

    let values = subject["values"];
    if subject["profile"] == "tracked-entity-id-v1" {
        query.push(#{name: "trackedEntities", value: values["record_reference"]});
    } else if subject["profile"] == "person-demographics-v1" {
        query.push(#{
            name: "filter",
            value: exact_filter(
                parameters["attributes"]["given_name"],
                values["given_name"]
            )
        });
        query.push(#{
            name: "filter",
            value: exact_filter(
                parameters["attributes"]["family_name"],
                values["family_name"]
            )
        });
        query.push(#{
            name: "filter",
            value: exact_filter(
                parameters["attributes"]["birth_date"],
                values["birth_date"]
            )
        });
    } else {
        throw("adapter_input_error");
    }

    #{query: query, body: ()}
}
