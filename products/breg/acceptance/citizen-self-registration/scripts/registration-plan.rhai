// The planner receives only the frozen application fields and emits effects
// within the YAML-declared write ceiling. The account principal comes only
// from the owner field already pinned to the verified `sub` claim.
fn plan(ctx) {
    #{effects: [
        #{
            id: "person",
            target: #{entity: "person"},
            operation: "create",
            set: #{
                "given-name": ctx.request["given-name"],
                "family-name": ctx.request["family-name"],
                "date-of-birth": ctx.request["date-of-birth"]
            }
        },
        #{
            id: "enrollment",
            target: #{entity: "program-enrollment"},
            operation: "create",
            set: #{
                person: #{fromEffect: "person"},
                "program-code": ctx.request["program-code"]
            }
        },
        #{
            id: "account-link",
            target: #{entity: "self-service-link"},
            operation: "create",
            set: #{
                person: #{fromEffect: "person"},
                principal: ctx.request.owner,
                active: true
            }
        }
    ]}
}
