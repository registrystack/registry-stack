# Delayed follow-up project

Use this synthetic example when a run must wait until a set time, read the
current Base Registry Engine (BReg) record, and send one notice through Registry
Messaging only when the record still permits it. It is the starter that
`coordinatorctl init` writes: the same four files, with the project id and the
file secret root replaced. The workflow, pure functions, deterministic
scenarios and runtime template form one complete project.

From the repository root, run the offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/delayed-follow-up --explain
coordinatorctl test --project products/coordinator/examples/delayed-follow-up
```

The `due` step waits until the input's `sendAfter`. Then:

1. `read-application` reads the application named by `applicationId` from the
   `applications` collection.
2. `permission` calls `notice_route` on the record. When
   `domainData.noticeAllowed` is true the run continues to `notify`; otherwise
   it finishes with outcome `no-current-permission` and no output.
3. `notify` submits one message built by `notice_request`: sender profile
   `transactional`, template `application-follow-up` version `1`, locale `en`,
   the record's `domainData.email` as the destination, and the application
   identifier as template data.
4. `accepted` finishes with outcome `message-accepted` and the Messaging
   `messageId`.

The record is read after the wait, so the permission and contact details are
the ones BReg holds at send time, not at admission. `message-accepted` means
Messaging accepted the submission; provider delivery is a separate Messaging
observation. The run's `deadlineSeconds` is 30 days from admission.

The scenarios cover a notice accepted after the virtual wait, a permission
withdrawn before the read, and four lost or unproven Messaging answers. After a
lost response, `retry-same` resends the saved command and key, and `reconcile`
reads the Messaging receipt for the original key; both cases finish with the
accepted message. An expired receipt, or a refusal after a lost response,
leaves the run `uncertain`, because neither proves that Messaging did not
accept the first submission.

For a deployment, the institution must supply these prerequisites:

- BReg exposes a reviewed `follow-up-reader` profile that reads the
  `applications` collection, including `noticeAllowed` and `email` in
  `domainData`.
- The token endpoint registers the `application-reader` client for resource
  `urn:example:applications` with scope `applications:read`, and the
  `case-system` client for resource `urn:example:messaging` with scope
  `messaging:send`. BReg admits `application-reader` to the `follow-up-reader`
  profile.
- Messaging permits sender profile `transactional`, template
  `application-follow-up` version `1` and locale `en` for the `case-system`
  caller.
- Callers hold a Coordinator access token for the `delayed-follow-up` workflow,
  and an explicit operator policy grants inspection and recovery separately.

The runtime template uses loopback endpoints and secret references only. Copy
it outside the package and adapt its endpoints, PostgreSQL identity and roles,
clients and package pin. Follow [the deployment runbook](../../DEPLOYMENT.md)
for installation and apply.
