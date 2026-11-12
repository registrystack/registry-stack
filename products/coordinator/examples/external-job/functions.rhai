// Pure Function ABI: one typed object of named inputs, one typed output.
// The host validates schemas and enforces script limits around every function.
fn job_command(args) {
    #{reference: args.request.reference}
}

// Only a durable receipt or a declared no-effect application refusal settles
// admission. Every other answer keeps Coordinator on same-command recovery.
fn job_admission(args) {
    let status = args.response.status;
    let body = args.response.body;
    if (status == 200 || status == 201) && "jobId" in body {
        return #{state: "accepted", result: #{jobId: body.jobId}};
    }
    if status == 422 && "reason" in body && body.reason == "invalid-job" {
        return #{state: "refused", code: "invalid-job"};
    }
    // A key conflict proves an earlier job exists. It cannot claim no effect
    // for this command, so the catch-all keeps the run uncertain.
    #{state: "uncertain"}
}

fn job_request(args) {
    #{path: "jobs/status", query: #{id: args.receipt.jobId}}
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
