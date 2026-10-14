// Pure Function ABI: one typed object of named inputs, one typed output.
// The host validates schemas and enforces script limits around both functions.
fn job_request(args) {
    #{path: "jobs/status", query: #{id: args.request.jobId}}
}

fn job_observation(args) {
    // Compare with the saved original read, never a newly selected job.
    if args.response.body.jobId != args.command.query.id {
        throw "job-correlation-mismatch";
    }
    let state = args.response.body.state;
    if state == "queued" || state == "running" {
        return #{state: "pending"};
    }
    if state == "failed" {
        return #{state: "refused", code: "external-job-failed"};
    }
    if state == "succeeded" {
        return #{state: "complete", result: #{jobId: args.response.body.jobId}};
    }
    throw "job-response-invalid";
}
