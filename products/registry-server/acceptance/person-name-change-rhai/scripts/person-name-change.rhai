// The runtime receives only ctx.request and emits the closed planner ABI.
// It cannot read people, credentials, files, time, or process state.
fn plan(ctx) {
    let given = ctx.request["given-name"];
    given.trim();
    let family = ctx.request["family-name"];
    family.trim();
    let display_name = given + " " + family;
    let effect = #{
        target: #{fromField: "person"},
        operation: "patch",
        set: #{"display-name": display_name}
    };

    if ctx.request["handling"] == "routine" {
        return #{effects: [effect], disposition: "apply"};
    }

    #{
        effects: [effect],
        disposition: "queue",
        reasonCode: "assisted-review"
    }
}
