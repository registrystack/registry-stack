// An explicitly granted procedure check records no eligibility claim.
fn plan(ctx) { #{effects: [#{id: "procedure-check", set: #{checked: true}}]} }
