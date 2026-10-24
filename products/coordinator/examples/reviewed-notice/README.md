# Reviewed notice project

Use this example when an application in the Base Registry Engine (BReg) needs
human approval in Registry Casework before Registry Messaging accepts a notice.
The workflow checks the authoritative application both before review and after
approval. It never accepts an email address in its input.

From the repository root, check the project and its deterministic scenarios:

~~~sh
coordinatorctl check --project products/coordinator/examples/reviewed-notice --explain
coordinatorctl test --project products/coordinator/examples/reviewed-notice
~~~

## Use packaged tools and clients

The session helper accepts `--bin-dir` with verified native binaries and
`--released-clients` to use an installed unified Python client instead of the
Rust input helper. `--messaging-image` accepts an exact published
`ghcr.io/registrystack/messaging@sha256:...` digest and runs its runtime and tool
with Docker host networking and only the owned fixture directory mounted.
This supports hosts without a native Messaging distribution. The verified local
combination is v0.44.0 candidate native tools and unified wheel, the reviewed C1
source Git archive, and published Messaging v0.43.0 at digest
`sha256:695b6a6dc2f72ab2f2341510f171d683cc87a19c7d37c253b545198557bd8a2c`.
It was executed on macOS arm64 with the Linux amd64 image under OrbStack.
This does not establish an actual Linux amd64 host run or a fully published
Coordinator distribution. Future release users must select the exact tested
combination documented for their release; arbitrary version mixing is not
covered. v0.43.0 does not publish Coordinator. The binary platform roster and
publication work remain required.

See the [tutorial](https://docs.registrystack.org/dev/tutorials/review-an-application-and-send-a-notice/)
for the complete sequence, restart, and cleanup. The Python projection uses
pinned RFC 8785 canonicalization over the same three reviewed fields; refusal
messages contain no field values.

## Prepare trusted input from a contributor build

The reviewed-notice-input Rust example reads the application through the
maintained BReg client. It writes a new owner-only input file containing the
real application identifier and revision. Its digest covers only the submitted
review projection: applicantName, benefitProgram and requestedAmount.
The helper uses registry_review_protocol::canonical_bytes and
ContentDigest::for_bytes, the same bounded canonical JSON contract used by the
review protocol.

Build the helper with the same source and lockfile as Coordinator:

~~~sh
cargo build --locked -p registry-coordinator --example reviewed-notice-input
~~~

Give it an owner-only token file for a BReg profile that may read the
application. A bregctl dev token header file is accepted directly:

~~~sh
target/debug/examples/reviewed-notice-input \
  --breg-url http://127.0.0.1:8100 \
  --record-id 00000000-0000-4000-8000-000000000001 \
  --token-file ./private/application-reader.headers \
  --output ./private/reviewed-notice-input.json
~~~

The command refuses an existing output path. Its JSON report names the output
file without printing its application data or credential. Start the run with
that file through coordinatorctl start.

## Workflow decisions

The run has a thirty-day deadline and follows these checks:

1. read-for-review reads the application from BReg. If its identifier or
   revision differs from the trusted input, the run finishes
   application-changed without creating a review.
2. submit-review sends the expected exact PolicyBinding and bounded facts to Casework under review policy
   application-review. Casework owns reviewer eligibility, policy and the
   decision.
3. await-review waits up to fourteen days. A Casework completion event wakes
   the run, but the Coordinator still reads the result through the producer
   connection before continuing.
4. A rejection finishes review-rejected. Other terminal results that are not
   approval finish review-not-approved.
5. After approval, read-for-notice reads BReg again. Revoked noticeAllowed
   finishes notice-permission-gone. Any other revision change finishes
   application-changed.
6. Only an unchanged reviewed revision with current notice permission reaches
   notify. The recipient email comes from this second BReg read. A successful
   Messaging receipt finishes notice-accepted.

The workflow therefore sends no notice for a rejection, an application change
or revoked notice permission. Messaging can still refuse an otherwise eligible
notice under its own current policy; that product refusal stops the run without
claiming an accepted notice.

## Withdrawal and late decisions

When fourteen days pass without a result, withdraw-timeout cancels the review.
An operator cancelling a run parked at the review wait takes the separate
withdraw-operator route. Casework receives a distinct recorded reason and the
run finishes review-timeout-withdrawn or review-operator-withdrawn.

A reviewer may decide immediately before either cancellation reaches Casework.
In that race the cancellation reports already-terminal; both routes finish
decided-late with Casework's status and result identifier. They do not send a
notice. Only a cancelled response proves that Casework closed the open review.

## Deployment prerequisites

The institution supplies these independent authorities:

- BReg exposes applications to the configured follow-up-reader service profile,
  including the reviewed facts, email and noticeAllowed.
- Casework declares review policy application-review version 1 with submitted context.
  Its display schema accepts applicantName, benefitProgram and requestedAmount.
- Casework admits trusted producer coordinator through profile coordinator-producer,
  and its completion destination uses the same bearer secret and recipient
  binding as the Coordinator connection.
- Messaging permits sender profile transactional, template
  application-approved version 1 and locale en for its own service caller.
- The token endpoint registers separate BReg reader, Casework producer,
  Messaging sender and Coordinator caller identities. Starting a run grants
  none of those product permissions.

Before packaging for your deployment, replace the synthetic offline PolicyBinding in
`functions.rhai` with the exact ID, version, and digest in the owning Casework project's
`caseworkctl check` report under `policyBindings`. Keep the Workflow and scenarios consistent with
that reviewed policy. The local tutorial helper binds a private copy to the actual compiled policy;
it does not deploy the offline placeholder digest.

The runtime template contains HTTPS reference endpoints and secret references.
Copy it outside the package and adapt its endpoints, database identity, client
registrations, completion secret and package digest. Follow the
[deployment runbook](../../DEPLOYMENT.md) for packaging, activation and
recovery.

The review wait names `completion: {step: submit-review, name: result}`. Casework remains the
review authority. This example does not submit or apply a BReg Proposal; the applicant drives a
Proposal in BReg, and a Workflow follows it through the
[Product events](../product-events/README.md) path. Completion wake-ups
respect the durable observation floor and do not provide a result the workflow can trust directly.
