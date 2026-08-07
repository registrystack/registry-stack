fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{
        query: [
            #{name: "id", value: subject["values"]["record_reference"]},
            #{name: "fields", value: parameters["providerFields"]},
            #{name: "limit", value: parameters["resultLimit"]}
        ],
        body: ()
    }
}
