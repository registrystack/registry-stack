# Deferred appointment project

Use this reviewed example for one current eligibility read, a durable wait, one
approved appointment and a separate accepted notice. The workflow, pure
functions, deterministic scenarios and runtime template form one complete
project. Configure the owning product policies before sending real work.

```sh
coordinatorctl --runtime-config /absolute/path/runtime.yaml \
  check --project products/coordinator/examples/deferred-appointment --explain
coordinatorctl test --project products/coordinator/examples/deferred-appointment
```

The runtime template uses HTTPS reference endpoints and secret references only.
Copy it outside the package and adapt its absolute paths, PostgreSQL identity and
roles, OIDC issuer/audience, exact clients/scopes, task authority and package pin.
Follow [the deployment runbook](../../DEPLOYMENT.md) for installation and apply.
The institution must supply these prerequisites:

- BReg exposes the reviewed `follow-up-reader` profile and fields that the
  functions inspect for current eligibility and contact details.
- Scheduling publishes offering `application-review` at the approved location and anchored
  windows. A catalogue identity reads metadata and availability. A separate
  booking agent consumes an approved Casework deferred grant for the exact
  service, location, actions and original deadline.
- Casework exposes that approved grant to the registered booking agent and issues
  fresh task assertions. Revocation, expiry, changed bounds or source invalidation
  refuses booking; the workflow never falls back to standing service authority.
- The booking agent's required `observationAuthorization` has the same token endpoint,
  registered client and resource. Scheduling's original-key receipt API authorizes
  its exact verified issuer/subject and returns only authoritative observation.
  The observation scope grants no authority to create a new appointment.
  Receipt recovery uses ordinary read credentials even after grant expiry or
  revocation; it never requests another Casework assertion or task-token exchange.
- Messaging permits sender profile `transactional`, template `appointment-confirmed`
  version `1`, and locale `en` for the reviewed sender identity. Acceptance
  and provider delivery remain distinct product observations.
- Institutional producers hold an audience-bound Coordinator access token for
  the `deferred-appointment` flow. An explicit operator policy grants inspection
  and recovery separately.

Input contains `applicationId`, `bookAfter`, `searchStart`, `searchEnd` and an
approved `grant` with its `id` and original `expiresAt` Unix timestamp. Keep the
search interval and booking time inside the grant's original bounds. Input carries
no credentials. The functions derive the product requests; they do not decide
which scopes or identities the operator registered.

Package the project and retain its start key through response loss. Reconciliation
uses the original booking or message key and owner. It cannot infer non-existence
from an expired receipt or unavailable receiver. Runtime key rotation preserves
registered identities; workflow edits cannot alter an admitted run's snapshot.
