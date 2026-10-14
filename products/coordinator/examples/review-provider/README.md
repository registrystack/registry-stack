# Coordinator as a Review provider

This project accepts the shared Review protocol and runs one ordinary pinned
Workflow per request. Its Review policy is the project ID and version plus the
computed Workflow revision. Changing a Function, graph, terminal mapping or
result availability changes that revision.

This provider returns a fixed status and optional authored outcome code. It
declares no structured result payload and refuses supplied `resultConstraints`;
omit that member when submitting a request.

The example reads a frozen BReg Proposal's exact exported context through a
separately admitted service assessment profile. The minimal projection contains
the proposed amount, current amount, application identifier and active flag.
An active record and an increase of at most 50 units take the authored automatic
approval route. Other active corrections go to Casework;
inactive records are rejected. These are example policy choices, with no
application semantics built into Coordinator.

Casework receives its own producer identity, policy and submission digest. Its
human display still uses the reviewer's current BReg permissions. Coordinator
maps a validated terminal Casework result back to the original upstream Review
binding. Unavailable context, unknown effects and mismatched bindings cannot
produce approval. Cancellation seals the upstream result while the normal Run
takes its authored downstream withdrawal route.

BReg independently authorizes application and checks current commit guards.
Approval of an exact frozen Proposal does not override a later target revision,
renew result availability or authorize the assessment credential to apply.

## Check the authored routes

```sh
coordinatorctl check --project products/coordinator/examples/review-provider
coordinatorctl test --project products/coordinator/examples/review-provider
```

The nine offline scenarios cover automatic approval, inactive-record refusal,
human approval, rejection, answer, requested changes and supersession, human
timeout withdrawal, and assessment authority refusal. The checked-in context and
Casework pins are synthetic fixture values.
Before deploying, import exact owner exports. A producer normally selects the
Review policy by ID; the provider binds its current version and revision on
first acceptance and preserves that concrete policy for recovery and results.
Include both version and digest only when the producer requires an exact pin.
`runtime.yaml` illustrates
separate producer, operator, read-only assessment and Casework credentials.

## Run the real product journey

Prepare native executables with the maintained helper or use an existing build:

```sh
python3 products/coordinator/scripts/test-real-services.py --prepare /absolute/private/native-build
COORDINATOR_TEST_DATABASE_URL=<owned-loopback-postgres-database> \
  python3 products/coordinator/scripts/test-review-provider.py \
  --bin-dir /absolute/private/native-build/bin \
  --build-manifest /absolute/private/native-build/build-manifest.json \
  --work-dir /absolute/private/review-provider-proof
```

Provide PostgreSQL 17+, matching `psql`, Docker, OpenSSL and Python 3. The six
service/operator executables are BReg, Casework and Coordinator. Dev tooling
starts isolated BReg, Casework and issuer containers. Coordinator uses a unique
schema and split runtime role in the named disposable database. Successful runs
remove owned resources and retain synthetic proof and logs in the private work
directory; a failure retains diagnostic dev state for inspection.

The runner obtains the context schemas and Casework policy bindings from their
owning compilers, then instantiates this project with those exact context and
downstream policy pins. The automatic source Action selects Coordinator's policy
by ID and verifies the accepted concrete binding; the manual and expiry Actions
exercise explicit version and digest pins. It
proves automatic BReg application, independent service apply refusal, human
review through Casework, lost-response recovery under original keys, and a
Coordinator process restart with an unknown command and a durable wait.

An active human-route Proposal is also cancelled through BReg's authorized
transition. The upstream cancelled result stays identical across a Coordinator
restart, the authored withdrawal settles the distinct Casework request, and
the source applies no change.

For deterministic stale-condition recovery it uses a separately instantiated
manual BReg Action. After approval, another authorized Proposal changes the
assessed active flag to false. Apply fails with the old approval. Rebase and
resubmission create a new frozen subject and a rejected Review request while
the record is inactive. A separate authorized change restores the active flag;
only a fresh rebase, resubmission and approval can apply. A short-retention
instance also proves that expired
result reads and cancellation return 410 and cannot authorize application.
The human-result observation floor is advanced only in the disposable fixture;
its relative deadlines and observation budget remain intact.
