// An explicitly granted procedure check records no eligibility claim.
fn handle(ctx) { #{effects: [#{id: "procedure-check", set: #{checked: true}}]} }
