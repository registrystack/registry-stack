// Replace these exact owner exports before deploying this synthetic project.
// The native runner binds the BReg context contract and Casework policy from
// their owning compilers before it computes the Coordinator Review binding.
fn assessment_input(args) {
    #{actionId: "correct-amount", subject: args.request.subject,
      contract: #{id: "urn:registry:breg:review-context:coordinator-source:correct-amount:application-amount-context",
                  revision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  schemaDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
}

fn assessment_route(args) {
    let fields = args.assessment.fields;
    if !fields.recordActive {
        "refused"
    } else if fields.proposedAmount >= fields.currentAmount
        && fields.proposedAmount <= fields.currentAmount + 50 {
        "automatic"
    } else {
        "human"
    }
}

fn human_input(args) {
    let request = args.request;
    // Optional exact-pin variant. An ID-only selector uses the provider's current policy.
    // Replace these synthetic pin values with the compiled Casework PolicyBinding.
    let handoff = #{
        policy: #{id: "external-review", version: "1", digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        subject: request.subject,
        requesterReference: request.requesterReference,
        context: request.context
    };
    if request.contains("initiator") { handoff.initiator = request.initiator; }
    handoff
}

fn human_route(args) {
    args.result.status
}
