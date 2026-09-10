# Registry Casework changelog

## Unreleased

- Add directory-scoped absence cover, explicit assignment and delegation for
  hosted or source-backed work, and bounded review-then-apply caseload moves
  with per-item visibility, eligibility, attempt, and revision results. Add
  Administrator-managed team membership and served-queue replacement with
  immediate authority changes and bounded ineligible-holding release.
- Add bounded, source-validated routing projections and ordered queue rules,
  plus named subject and working-day activity clock policies with revisioned
  external holiday-set inputs, immutable Administrator-published holiday
  revisions, bounded occurrence reads, and reviewed atomic deadline
  recomputation.
- Add source-free hosted decisions with declared bounded display schemas and
  outcomes, Requester-owned create/read/notes/cancel/terminal polling, human
  decisions under a configured profile, pinned kind policy, opaque actor references,
  audited Supervisor accountability resolution, separate terminal and
  accountability retention, payload-free idempotency tombstones for
  expired-response recovery, and the `standalone-decision` starter.
- Add the first checkpoint runtime and `caseworkctl` authoring and local operator
  commands, with separate PostgreSQL storage for team membership, work items,
  private drafts, attempts, history and durable events.
- Connect one governed BReg request source through the maintained client.
  Signed event hints and periodic readback discover current work and repair
  missed events. Decisions retain the acting human's token and source profile.
- Add caller-visible inbox views, claim and release, officer-private drafts,
  correction requests, approval and separate application, supervisor holdings,
  per-item accountability and a passive elapsed queue target.
- Preserve original attempts through uncertain source responses and expose
  distinct refusal and recovery codes to the maintained Rust and Node clients.
- Require an explicit trusted-issuer human identity assertion in addition to
  token verification, selected profile scopes and current directory membership.
- Publish per-operation OpenAPI responses from the maintained Rust problem
  contract, including bounded framework rejections, request tracing, recovery
  headers, and current DTO shapes.
- Require an explicit local-development or upstream-TLS mode, reject public
  listeners, and document the private server-to-server, no-CORS boundary.
- Add a reproducible combined demo with Registry App Kit and the existing-kit
  comparison. This checkpoint does not include timers, routing rules, reminders,
  bulk decisions, consultation or automatic outcomes.

These changes are unreleased. The workspace version alone does not identify a
published client package containing Casework; the demo builds a matching local
candidate from the selected source trees.
