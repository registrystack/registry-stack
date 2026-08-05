fn prepare(selectors, parameters) {
    let subject = selectors["subject"];
    let values = subject["values"];
    let selector = #{};

    if subject["profile"] == "opaque-record-v1" {
        selector["record_reference"] = values["record_reference"];
    } else if subject["profile"] == "opaque-coordinates-v1" {
        selector["alpha"] = values["alpha"];
        selector["delta"] = values["delta"];
    } else {
        throw("adapter_input_error");
    }

    #{
        query: [],
        body: #{
            selector: selector,
            fields: [parameters["requestedField"]],
            limit: parameters["resultLimit"]
        }
    }
}
