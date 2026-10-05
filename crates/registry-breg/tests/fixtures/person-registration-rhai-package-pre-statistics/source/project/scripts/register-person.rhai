fn handle(ctx) {
    let given = if "given-name" in ctx.inputs && ctx.inputs["given-name"] != () {
        ctx.inputs["given-name"]
    } else { "" };
    given.trim();
    let family = if "family-name" in ctx.inputs && ctx.inputs["family-name"] != () {
        ctx.inputs["family-name"]
    } else { "" };
    family.trim();

    if given == "" && family == "" {
        return #{refusal: #{code: "blank-name", field: "given-name"}};
    }
    let display_name = given;
    if display_name == "" {
        display_name = family;
    } else if family != "" {
        display_name += " " + family;
    }

    #{effects: [#{
        id: "person",
        set: #{identifier: ctx.inputs.identifier, "display-name": display_name}
    }]}
}
