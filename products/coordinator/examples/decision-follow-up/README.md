# Typed decision followed by a governed action

Use this synthetic example to test a decision, an explicit business threshold,
and a separate Base Registry Engine (BReg) action. The model sees only the
application summary. BReg receives the application identifier and still checks
its own action metadata, profile, conditions, and current authority.

From the repository root, run the existing offline authoring commands:

```sh
coordinatorctl check --project products/coordinator/examples/decision-follow-up --explain
coordinatorctl test --project products/coordinator/examples/decision-follow-up
```

The check validates the graph, script, scenarios, and runtime configuration without
resolving the referenced keys or contacting a model. The tests cover a governed
action, no action, low confidence, model refusal, product refusal, lost or
malformed model replies, and a credential failure. The model-refusal case uses
an OpenAI normalized reply
to demonstrate the same authored policy with that binding. System One HTTP
refusal instead stops the call; it cannot produce this per-question answer.
A nonzero exit identifies the failed check or scenario; repair that case before
packaging or activation.

The example uses an illustrative confidence threshold of 0.8. Validate thresholds
with labeled cases for your selected model and use case before enabling actions.
Native confidence is a provider statistic, not a guarantee of correctness or an
interchangeable measure between models. `needs-review` is a terminal return to
the caller; it does not create a Casework task or acquire human approval.

For a deployment, provide your BReg endpoint and an explicitly authorized
`coordinator-actions` profile exposing a `request-information` action with
`applicationId` and `reason` inputs. The action is a project declaration, not a
built-in Coordinator operation. Configure the shared secret references and
choose an available reviewed model. Inspect provider data retention and minimize
the summary before activating a remote binding. This fixture's endpoints and
identities do not configure a working institutional deployment.

To use OpenAI Decisions, change the same logical binding to `openai-decisions`,
its service root, and an available model name. The authored questions do not
change. To use a System One compatible local service such as Ollama, select
`system-one`, its numeric loopback root, an installed decision model, and
explicit `authorization: {local: {}}`. Protocol fixtures prove the request and
response shapes, not an actual installed model or service account.

A successful answer is saved before branching. A later retry or restart reuses
it. An uncertain evaluation has no proven receipt or safe replay contract:
`retry-same` and reconciliation are refused. You can cancel and make a separately
authorized new start, accepting possible additional model cost and a different
answer. Neither cancellation nor a new start retracts provider processing.
Cancellation remains visible as `cancelRequested: true` alongside the unknown
outcome. After a restore, use the [recovery procedure](../../DEPLOYMENT.md#backup-and-restore)
to abandon that cancelled evaluation without blocking unrelated work or replaying it.

General JSON generation, images, asynchronous jobs, training, and model tool
execution are not supported. No live provider call is part of the offline check.
