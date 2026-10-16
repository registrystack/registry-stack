fn plan(ctx) {
    let reason = ctx.inputs.reason;
    reason.trim();
    if reason == "" {
        return #{refusal: #{code: "invalid-reason", field: "reason"}};
    }
    #{effects: [#{id: "application", set: #{"information-requested": true, reason: reason}}]}
}
