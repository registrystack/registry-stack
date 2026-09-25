// Read one verified JSON delivery report.
fn receipt(request) {
    let report = request.json;
    if type_of(report) != "map" || type_of(report.id) != "string" {
        throw "not a delivery report";
    }
    let state = switch report.status {
        "sent" => "sent",
        "delivered" => "delivered",
        "failed" => "undelivered",
        _ => ()
    };
    if type_of(state) != "string" {
        return ();
    }
    if type_of(report.code) == "string" {
        return #{ providerReference: report.id, report: state, code: report.code };
    }
    #{ providerReference: report.id, report: state }
}
