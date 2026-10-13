# Governed action follow-up project

Use this synthetic example when a run must read a Base Registry Engine (BReg)
record, invoke one governed BReg action when the record needs it, and then send
a separate notice through Registry Messaging. The workflow, pure functions,
deterministic scenarios and runtime template form one complete project.

From the repository root, run the offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/governed-action-follow-up --explain
coordinatorctl test --project products/coordinator/examples/governed-action-follow-up
```

The run starts at once and has a `deadlineSeconds` of 300:

1. `read-application` reads the application named by `applicationId` from the
   `applications` collection.
2. `needs-information` calls `information_route` on the record. When
   `domainData.complete` is true the run finishes with outcome
   `no-information-request-needed` and no output; otherwise it continues.
3. `request-information` calls `invoke-breg-action` with action
   `request-information` and two inputs: `applicationId`, and a `reason` built
   from the record's `domainData.missingField`. A package-declared business
   refusal takes `onDeclaredRefusal` to `action-refused`, which finishes with
   `information-request-refused` and the validated `refusalCode`.
4. `notify` submits one message with sender profile `transactional`, template
   `information-requested` version `1` and locale `en` to the record's
   `domainData.email`, carrying the application identifier the action returned.
5. `accepted` finishes with outcome `action-and-notice-accepted`, the action's
   `actionApplicationId` and the Messaging `messageId`.

BReg decides whether the action runs. It checks its action metadata, the
`workflow-actions` profile, the action's conditions and current authority; the
action name in `functions.rhai` grants nothing. `invoke-breg-action` uses the
connection's standing service identity and accepts no Casework grant, so this
connection has no `taskAuthority`. Only a package-declared, no-effect action
refusal takes the authored refusal edge. Authentication, authorization,
transport, protocol and preparation refusals stop the run and expose no raw
problem document to the workflow.

After a lost action response the run is `uncertain`. `retry-same` resends the
saved prepared command with its original key. A later declared refusal cannot
settle whether the original command ran, so that run remains `uncertain` and
does not take the refusal edge. Reconciliation is refused for this step: BReg
has no read-only action receipt, and a record read does not prove that the
action succeeded. When Messaging refuses the notice after BReg accepted the
action, the run ends `refused` and the action stays accepted; cancellation does
not roll it back.

The scenarios cover an accepted action and notice, a complete application that
needs no action, an authority refusal, a routed declared refusal, a declared
refusal after an uncertain attempt, a lost action response left unresolved, a
lost action response recovered with `retry-same`, and a notice refused after an
accepted action. They use synthetic replies only, so they do not prove BReg
action policy, target preconditions, remote acceptance or provider delivery.

For a deployment, the institution must supply these prerequisites:

- BReg exposes a reviewed `workflow-actions` profile that reads the
  `applications` collection, including `complete`, `missingField` and `email`
  in `domainData`, and permits the immediate `request-information` action with
  `applicationId` and `reason` inputs. Its package declares the business
  refusal codes the workflow may receive.
- The token endpoint registers the `application-agent` client for resource
  `urn:example:applications` with scopes `applications:read` and
  `applications:act`, and the `case-system` client for resource
  `urn:example:messaging` with scope `messaging:send`. BReg admits
  `application-agent` to the `workflow-actions` profile.
- Messaging permits sender profile `transactional`, template
  `information-requested` version `1` and locale `en` for the `case-system`
  caller.
- Callers hold a Coordinator access token for the `governed-action-follow-up`
  flow, and an explicit operator policy grants inspection and recovery
  separately.

The runtime template uses loopback endpoints and secret references only. Copy
it outside the package and adapt its endpoints, PostgreSQL identity and roles,
clients and package pin. Follow [the deployment runbook](../../DEPLOYMENT.md)
for installation and apply.
