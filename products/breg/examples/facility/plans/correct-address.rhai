fn plan(ctx) {
    let postal_code = ctx.inputs["postal-code"];
    postal_code.trim();
    if postal_code == "" {
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
                    "address-line": ctx.inputs["address-line"],
                    "city": ctx.inputs["city"],
                    "postal-code": ctx.inputs["postal-code"]
                }
            }
        ]
    }
}
