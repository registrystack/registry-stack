// Fixed DHIS2 Tracker request preparation. Rust performs URL encoding after
// this Function returns ordered query pairs.
fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    if subject["profile"] != "dhis2-tracked-entity-id-v1" {
        throw("adapter_input_error");
    }
    #{
        query: [
            #{name: "program", value: parameters["program"]},
            #{name: "orgUnits", value: parameters["organisationUnit"]},
            #{name: "trackedEntities", value: subject["values"]["record_reference"]},
            #{name: "fields", value: parameters["projection"]},
            #{name: "pageSize", value: parameters["pageSize"]},
            #{name: "page", value: parameters["page"]},
            #{name: "totalPages", value: parameters["totalPages"]}
        ],
        body: ()
    }
}
