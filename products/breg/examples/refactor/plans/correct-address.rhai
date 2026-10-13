fn plan(ctx) {
    if ctx.input["postal-code"].trim().is_empty() {
        return #{
            refusal: #{
                code: "invalid-postal-code",
                field: "postal-code"
            }
        };
    }

    #{
        effects: [
            #{
                id: "facility-address",
                set: #{
                    "address-line": ctx.input["address-line"],
                    "city": ctx.input["city"],
                    "postal-code": ctx.input["postal-code"]
                }
            }
        ]
    }
}
