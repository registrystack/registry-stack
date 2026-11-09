fn plan(ctx) {
    let effective_on = today();
    #{effects: [#{
        id: "entry",
        set: #{
            label: ctx.inputs.label,
            "effective-on": effective_on,
            "expires-on": add_days(effective_on, 30),
            "renewal-on": add_months(effective_on, 1),
        },
    }]}
}
