fn handle(ctx) {
    let prefix = ctx.inputs["farmer-prefix"];
    let number = ctx.inputs["farmer-number"];
    prefix.trim();
    number.trim();
    if prefix == "" || number == "" {
        return #{refusal: #{
            code: "invalid-farmer-number",
            field: "farmer-number"
        }};
    }

    let farmer_number = prefix + "-" + number;
    let subjects = #{farmer: #{"farmer-number": farmer_number}};
    let status = evidence::resolve("farmer-status", subjects);
    if !status.active {
        return #{refusal: #{code: "farmer-inactive"}};
    }

    let fields = #{
        "farmer-number": farmer_number,
        "parcel-code": ctx.inputs["parcel-code"]
    };
    if ctx.inputs["include-category"] {
        let category = evidence::resolve("farmer-category", subjects);
        fields["farmer-category"] = category.category;
    }

    #{effects: [#{id: "landholding", set: fields}]}
}
