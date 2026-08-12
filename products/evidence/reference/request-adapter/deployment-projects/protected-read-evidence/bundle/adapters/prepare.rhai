fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{
        query: [
            #{name: "recordReference", value: subject["values"]["record_reference"]},
            #{name: "fields", value: parameters["providerFields"]},
            #{name: "pageSize", value: parameters["pageSize"]}
        ],
        body: ()
    }
}
