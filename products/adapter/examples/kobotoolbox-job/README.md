# KoboToolbox ingestion job examples

Use these examples to prepare one controlled KoboToolbox ingestion pilot.
The maintained pack is based on synthetic fixtures and published KoboToolbox
documentation. The maintainers also ran the direct job with synthetic data on a
real KoboToolbox 2.026.37c server: a submission reached a direct BReg Proposal,
a distinct human Casework approval, and one applied record. An unchanged repeat
skipped, while an edit that reused the same source identity was held and did not
create a second registration. No run record is committed, so treat this as
unverified until your own pilot repeats it. It covers the direct job only; the
Coordinator flow has not completed an equivalent run.

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

Use the Coordinator job for any form whose submissions are edited after they
are sent. The direct job holds every correction: an edit changes the
submission's revision, the Adapter holds the item with its earlier Proposal
reference, and nothing releases it, so BReg keeps the uncorrected value and the
held count grows. If supervisors routinely correct submissions in Kobo, choose
`job.coordinator.yaml` and let its workflow resolve the earlier record. Use the
direct job for forms that are submitted once and not edited.

The direct mapping is deliberately example-specific. Programme Action inputs
do not belong in the reusable Kobo provider pack, and changing the mapping
requires updating its digest in `job.yaml`.
Review the mapping, Action, access profile, projection, and destination
binding before a pilot. The BReg half of the direct journey (the `household`
record type, the `register-household` Action, the `ingestion` access profile
and the review policy) is the project in
[`../kobotoolbox-breg/`](../kobotoolbox-breg/README.md).

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
