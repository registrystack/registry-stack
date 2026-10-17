# Current-source development

A standalone review needs only a Casework project and its local teaching clients. Run `caseworkctl init ./casework`, `caseworkctl check ./casework`, `caseworkctl test ./casework`, and `caseworkctl dev start ./casework` for the first submitted-context journey. The session starts Casework, its database, and a local issuer. `caseworkctl dev token staff ./casework` writes a fresh owner-only header for an admitted teaching client.

A current-source review adds one read-only context provider. The [canonical review example](examples/canonical-review/README.md) contains a submitted-context policy and a BReg Proposal policy. Its vendored schema and `context.contract` pin the exact native `correct-address` review-context export. The compiled policy checks the schema offline; an open review never silently adopts a later producer contract.

1. Build and check the matching BReg package using the BReg runbook. Pair its native export with the authored Casework provider:

   ```sh
   caseworkctl provider pair products/casework/examples/canonical-review \
     --provider-id facility-proposal-context \
     --breg-package /absolute/path/to/breg-package \
     --action-id correct-address --apply
   caseworkctl check products/casework/examples/canonical-review \
     --against-breg-package /absolute/path/to/breg-package
   ```

   Pairing writes the provider export under `context-providers/` and records its path in `casework.yaml`. It changes no BReg package, runtime permissions, or lifecycle hooks. The agreement check verifies the native package and compares its exact source, action, context contract, and schema bytes with the imported export. Unrelated registry package changes do not invalidate that agreement. Regenerate and re-pair if the producer contract changes.

2. Bind the provider's `deploymentRef` in `runtime.yaml`. The [canonical runtime example](examples/canonical-review/runtime.example.yaml) shows `contextProviders.facility-registry`: BReg URL, token endpoint, `statusProfile`, and secret references for a purpose-specific status reader. The status profile must equal `serviceProfiles.service-status` in `casework.yaml`, and BReg must grant that service client `get-review-status` for the action. It need not grant generic Proposal `get`. Configure the exact issuer audience, resource, and scope that BReg accepts. Use `caseworkctl check PROJECT --runtime-config FILE` before packaging and applying.

3. For a local session with the same issuer as BReg, add an explicit `integrations` block to Casework's `dev-clients.yaml`. Declare `integrations.resource`, `integrations.contextProviders` keyed by `deploymentRef`, and a `serviceClients` entry for the status reader. Each provider binding has the same fields as the runtime example. A generated local service client's references are `secret:file/service-CLIENT-id` and `secret:file/service-CLIENT-key`; imported owner-only files go through `integrations.secretFiles`. Start the already configured BReg dev session separately. Use `caseworkctl dev start ./casework --issuer-project ./breg-project` only when that ready BReg owner has pre-registered the Casework clients, their exact scopes, claims and resource. Casework does not start BReg or modify its access profiles.

The reviewer sends the current human bearer and selects an authorized BReg source profile with `Registry-Source-Profile` for open Casework work, source context, lists, decisions, and new notes. BReg must trust that issuer and audience, authorize the selected profile and subject, and grant `get-review-context` with the intended field disclosure. Casework never substitutes its service credential for a human display read. It selects the action and purpose from current caller-visible metadata, then checks the observed Proposal binding and exact context contract at visibility and decision boundaries. Context meaning, field semantics, and schema bytes stay pinned while profile and row disclosure remain current. A concealed, changed, or non-reviewable Proposal is refused or omitted from the visible task list. Retained decided-task and settled-history reads use current Casework authority and expose no source projection. The service credential reads status only.

The trusted BReg producer creates or recovers the ReviewRequest and later fetches the immutable ReviewResult. An apply principal authorized by BReg independently rechecks and applies the Proposal. Casework neither synchronizes source records nor executes a source action. Use submitted context when the producer is authorized to give Casework a stable minimized snapshot and source availability or revocable disclosure is unnecessary.
