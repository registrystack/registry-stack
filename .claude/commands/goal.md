---
description: Execute the next step of the Notary retirement and Evidence onboarding plan
argument-hint: [DoD item id, e.g. B5, or a workstream letter; empty picks the next item]
---

Work the tracked plan at `plans/notary-retirement-and-evidence-onboarding.md`.

1. Read the plan in full: decisions, constraints, DoD checklist, dependency
   order, status log. The decisions are settled; do not relitigate them.
2. Select work. If `$ARGUMENTS` names a DoD item or workstream, target it.
   Otherwise pick the first unchecked item whose dependencies are satisfied,
   preferring workstream B (onboarding is the standing priority).
3. Announce the selected item and its intended shape in one short message,
   then execute. Only stop for input when the item is security-sensitive,
   requires a decision the plan reserves for Jeremi (A1's Mint-for-Relay
   branch, G4 re-approval), or turns out to conflict with a constraint.
4. For code: TDD, failing test first. The frozen Evidence V1 rules in
   `AGENTS.md` and `products/evidence/AGENTS.md` apply; composition work
   must not touch Evidence production code.
5. Verify with the gates listed in the plan's Verification section for every
   area touched. All must pass; paste the evidence in the report.
6. Update the plan file in the same commit as the work: tick the DoD
   checkbox, append a dated status log line (absolute dates).
7. Commit with `git commit -s` and a conventional prefix. Stage only files
   belonging to this item; never sweep unrelated worktree changes.
8. Report: what changed, verification evidence, and the next unblocked item.

Never: modify frozen Evidence V1 contracts, hand-edit generated artifacts,
scrub Notary from history pages, or log secrets.
