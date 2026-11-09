# Stage-specific review outcomes

This submitted-context policy keeps one review history across two levels. The
local review can approve, reject, or request changes. The final review can only
approve or reject.

Run the offline authoring checks from the repository root:

```sh
caseworkctl check products/casework/examples/stage-outcomes
caseworkctl explain products/casework/examples/stage-outcomes
caseworkctl test products/casework/examples/stage-outcomes
```

`explain` reports the effective outcomes offered by each stage. `test` checks
the synthetic submitted context and the local stage's queue and outcome
vocabulary. These offline commands do not exercise a deployed review or prove
runtime decision transitions.
