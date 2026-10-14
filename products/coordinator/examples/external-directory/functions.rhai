// The logical connection owns the configured origin, allowed path/query names,
// response schema and optional credentials. This mapping performs no I/O.
fn lookup_request(args) {
    let input = args["input"];

    #{ path: "offices", query: #{ district: input.district } }
}

fn office_route(args) {
    let reply = args["reply"];

    if reply.status == 404 { return "missing"; }
    if reply.status != 200 { return "unavailable"; }
    if reply.body.items.len == 0 { return "missing"; }
    "found"
}
