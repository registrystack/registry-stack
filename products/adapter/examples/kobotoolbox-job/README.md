# KoboToolbox ingestion job examples

Use these examples to prepare one controlled KoboToolbox ingestion pilot.
The maintained pack is based on synthetic fixtures, published KoboToolbox
documentation, and one controlled direct-destination proof with pinned
KoboToolbox 2.026.37c. That proof carried an authentic source submission into
a direct BReg Proposal, through a distinct human Casework approval, and into
one applied record. An unchanged repeat skipped, while an edit that reused the
same source identity was held and did not create a second registration. This
evidence covers the direct job only; the Coordinator flow has not completed an
equivalent controlled drill.

All three jobs reuse the same pinned `kobotoolbox` provider pack and its
`kobo-submissions` source route.
Choose exactly one job and runtime pair for each form:

- `job.yaml` maps the declared projection through the job-owned,
  digest-pinned `mappings/register-household.rhai`, then starts and submits a
  Base Registry Engine (BReg) Proposal directly. Its operator bindings are in
  `job-runtime.example.yaml`.
- `job.coordinator.yaml` signs the same projection for a named Coordinator
  workflow. Its operator bindings are in `job-runtime.coordinator.example.yaml`.
- `job.hook.yaml` runs the direct job from the same interval and may also be
  woken early by a Basic-authenticated Kobo webhook. Its operator bindings are
  in `job-runtime.hook.example.yaml`; [HOOKS.md](HOOKS.md) owns the ingress and
  TLS-proxy instructions.

Do not run more than one job against one form.
A destination refusal never falls back to the other job.
Use the direct job only when each submission maps to one BReg operation
without lookup or choice.
Use the Coordinator job when the workflow must resolve a target, choose an
operation, wait, or reach a person.

The direct mapping is deliberately example-specific. Programme Action inputs
do not belong in the reusable Kobo provider pack, and changing the mapping
requires updating its digest in `job.yaml`.
Review the mapping, Action, access profile, projection, and destination
binding before a pilot.

The projection presents selected dotted paths as literal dotted keys, so the
direct mapping reads `household.household_size` by that exact key. It converts
numeric or string submission IDs to the BReg string field, preserving opaque
string IDs, and converts Kobo's integer-string household-size answer to the
BReg `int64` field. Unsupported types and invalid integer strings refuse.

`adapter-job check` compiles each job from its authored file, the unchanged
provider pack, the local profile and project, and the matching runtime config.
It performs the source endpoint's credential preflight, using synthetic values
in the maintained contract check, but does not contact an endpoint or activate
either destination credential.

Follow the [KoboToolbox ingestion job operations runbook](OPERATIONS.md) to
initialize the store, preview one source page, run bounded passes, and inspect
outcomes.
