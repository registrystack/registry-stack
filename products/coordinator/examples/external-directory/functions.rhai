// The logical connection owns the configured origin, allowed path/query names,
// response schema and optional credentials. This mapping performs no I/O.
fn lookup_request(input) {
    #{ path: "offices", query: #{ district: input.district } }
}

fn office_route(reply) {
    if reply.status == 404 { return "missing"; }
    if reply.status != 200 { return "unavailable"; }
    if reply.body.items.len == 0 { return "missing"; }
    "found"
}

fn office_result(reply) {
    #{ officeId: reply.body.items[0].id }
}
