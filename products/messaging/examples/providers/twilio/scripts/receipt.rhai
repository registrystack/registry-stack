// Read one verified status callback. Intermediate states (queued, sending,
// accepted) report nothing this runtime records.
fn receipt(request) {
    let form = request.form;
    let sid = form.MessageSid;
    let status = form.MessageStatus;
    if type_of(sid) != "string" || type_of(status) != "string" {
        throw "not a message status callback";
    }
    let report = switch status {
        "sent" => "sent",
        "delivered" => "delivered",
        "undelivered" | "failed" => "undelivered",
        _ => ()
    };
    if type_of(report) != "string" {
        return ();
    }
    let code = form.ErrorCode;
    if type_of(code) == "string" && code != "" {
        return #{ providerReference: sid, report: report, code: "twilio." + code };
    }
    #{ providerReference: sid, report: report }
}
