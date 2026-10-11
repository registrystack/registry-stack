# Approved record check project

Use this synthetic example when a run must read one Base Registry Engine (BReg)
record under a Casework approval instead of a standing service identity. The
run waits until the input's `notBefore`, reads the record with the approved
grant, and finishes with the record identifier. The workflow, deterministic
scenarios and runtime template form one complete project. `functions.rhai`
declares no functions, because every mapping is a reference in
`workflow.yaml`.

From the repository root, run the offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/approved-record-check --explain
coordinatorctl test --project products/coordinator/examples/approved-record-check
```

The start input carries `collection`, `recordId`, `notBefore` and a `grant`
with the approval's `id` and its original `expiresAt` Unix timestamp. Copy those
two grant values from the Casework approval unchanged; the input carries no
assertion or token. The `read` step passes the grant to `read-record`.

The `source` connection declares `authorization.taskAuthority`, so it accepts
only grant-bound reads. A read without `grant` is refused with
`invalid-command`, and so is a grant sent to a BReg connection without
`taskAuthority`. For each read attempt, including one after a restart, the
Coordinator acquires authority afresh:

1. The registered client `task-agent` obtains a token for the
   `bootstrapResource` `urn:example:casework` with scope
   `casework:grants:assert`.
2. It asks Casework at `taskAuthority.baseUrl` for an assertion about the
   grant. Casework must report the same grant deadline as `expiresAt`.
3. It exchanges that assertion at the token endpoint for a BReg token for
   resource `urn:example:applications` with scope `records:get`, bound to the
   configured `issuer`, `subject` and `exchangeAudience`.

No bearer is kept between attempts, and there is no fallback to standing
service authority. A revoked grant, a changed deadline or a passed `expiresAt`
refuses the read with `credential-refused` before BReg is contacted. The run's
`deadlineSeconds` of one day is a run cutoff; it never extends the shorter
Casework approval.

The scenarios cover a read after the virtual wait, an expired approval refused
with `credential-refused`, a record the profile no longer shows
(`product-not-found`), and an unavailable credential service
(`credential-unavailable`). In the service, the Coordinator retries
`credential-unavailable` on its own within the deadline, as
[Recover safely](../../DEPLOYMENT.md#recover-safely) describes; the scenario
stops at the first such answer. The scenarios use synthetic replies only, so
they do not prove Casework approval, task-grant exchange or BReg access policy.

For a deployment, the institution must supply these prerequisites:

- BReg exposes a reviewed `approved-reader` profile that reads the collections
  callers name in `collection`, and admits the token the exchange issues.
- The token endpoint registers the `task-agent` client. It issues that client a
  token for `urn:example:casework` with scope `casework:grants:assert`, and
  exchanges a Casework task assertion for a token for
  `urn:example:applications` with scope `records:get`.
- Casework, at `taskAuthority.baseUrl`, holds the approved grant for the
  registered agent subject `registered-agent-subject` and issues its task
  assertions as `https://casework.local.example`.
- Callers hold a Coordinator access token for the `approved-record-check` flow,
  and an explicit operator policy grants inspection and recovery separately.

The runtime template uses loopback endpoints and secret references only, and
sets `clientAssertionAudience`, the audience of the client's signed assertion;
without it, the token endpoint URL is used. Copy it outside the package and
adapt its endpoints, PostgreSQL identity and roles, client, task authority and
package pin. Follow [the deployment runbook](../../DEPLOYMENT.md) for
installation and apply.
