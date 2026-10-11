# Bounded poll project

Use this synthetic example when a run must check a source record a few times
until the source decides, then hand control back to the caller. It reads one
Base Registry Engine (BReg) application at three fixed times and finishes with
the decision, or with `still-pending` after the third read. The workflow, pure
functions, deterministic scenarios and runtime template form one complete
project.

From the repository root, run the offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/bounded-poll --explain
coordinatorctl test --project products/coordinator/examples/bounded-poll
```

The workflow graph is finite and acyclic, so the poll is unrolled into three
rounds. Each round is a `wait-until` step, a `read-record` call and a `choose`
step:

1. `wait-1` waits until the input's `firstCheckAt`, `read-1` reads the
   application and `check-1` calls `review_state` on the record.
2. `wait-2` waits until one day after `firstCheckAt`, computed by `check_time`
   with `add_seconds`, then `read-2` and `check-2` repeat the read and choice.
3. `wait-3` waits until two days after `firstCheckAt`, then `read-3` and
   `check-3` read and choose a last time.

When the record's `domainData.reviewState` is `approved` or `rejected`, the run
finishes with outcome `decided` and that value as `decision`. After three
pending reads it finishes with outcome `still-pending` and no output. Each check
happens at its time whether or not the record changed; BReg sends the run no
signal. While the run waits, `coordinatorctl status` reports the next check
time as `nextDueAt`. Once it finishes, the caller reads `outcome` and `output`
from the same status and decides whether to start a new run later, with a new
idempotency key.

The scenarios cover a decision at the first read, a decision at the third read,
three pending reads, a refused read that stops the run, and a late
`firstCheckAt`. The run has a `deadlineSeconds` of seven days from admission,
so the last check, two days after `firstCheckAt`, must fall inside it. When a
wait ends at or after the deadline, the run expires instead of reading again;
the
`late-first-check-reaches-the-deadline` scenario shows that case.

To change the number of checks or their spacing, add or remove a round, give its
wait a later `check_time` argument, and keep the last wait inside
`deadlineSeconds`. Each round is a separate read step, so `inspect` lists every
read the run reached.

For a deployment, the institution must supply these prerequisites:

- BReg exposes a reviewed `review-reader` profile that reads the `applications`
  collection, and its application records carry `reviewState` in
  `domainData`.
- The token endpoint registers the `application-reader` client for resource
  `urn:example:applications` with scope `applications:read`, and BReg admits
  that client to the `review-reader` profile.
- Callers hold a Coordinator access token for the `bounded-poll` flow, and an
  explicit operator policy grants inspection and recovery separately.

The runtime template uses loopback endpoints and secret references only. Copy
it outside the package and adapt its endpoints, PostgreSQL identity and roles,
client and package pin. Follow [the deployment runbook](../../DEPLOYMENT.md)
for installation and apply.
