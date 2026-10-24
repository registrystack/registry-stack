fn plan(ctx) {
    let label = ctx.inputs.label;
    label.trim();
    if label == "" {
        return #{refusal: #{code: "blank-label", field: "label"}};
    }
    #{effects: [#{id: "entry", set: #{label: label}}]}
}
