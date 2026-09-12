# Registry Casework changelog

## Unreleased

## v0.30.0 - 2026-09-12

- Document the secret reference grammar, the owner-only file rules, and the
  requirement that every resolved secret value be non-empty NUL-free text of at
  most 64 KiB, with a command that generates the audit journal secret.
- Document the static `authentication.oidc.jwksSource` alternative to issuer
  discovery, when to prefer it, and that it performs no rotation of its own.
- Name `GET /v1/work-items/{itemId}/hosted-history` as the staff hosted
  lifecycle history read, and say that `GET /v1/work-items/{itemId}/history` is
  the source-scoped variant that requires a `Registry-Source-Profile` header.
- Name the failing secret reference and the rule it broke when the database
  connection, the audit journal, or a static OIDC JWKS document cannot resolve
  its secret at startup, and name the source whose binding was refused. The
  refusal never carries the resolved secret value.
- Version the runtime configuration as `casework-runtime/v1alpha1`, select the
  fixed `casework.yaml` through an absolute `package.root`, move listener fields
  under `listener` with port 8100, require explicit secret providers, adopt
  `audit.hashKeyRef`, and generate its JSON Schema from the owning Rust types.
- Remove the unused runtime OIDC `principalClaim` and direct operators to the
  enforced `accessProfiles[].principalClaim`; add field paths for invalid
  routing, queue, clock, and hosted-kind references.
- Add an explicit source-owned display reference for exact, case-sensitive
  inbox lookup, current-caller disclosure rechecks, and `due`, `age`, or `type`
  inbox ordering with cursor context bound to the selected lookup and sort.
- Return `/v1/work-items/next` as a bounded `WorkItemPage`, including empty
  successful pages and a continuation when caller-visible scanning exhausts
  its per-request budget.
- Persist source-reconciliation progress across bounded passes and apply the
  configured concurrency limit to caller-scoped source reads while preserving
  deterministic response order.
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
- Add `caseworkctl attempt settle`, a preview-by-default operator command that
  settles an uncertain source attempt whose execution lease has expired as
  applied or not applied, and records the outcome, reason, and decider as an
  `attempt_settled` history event in the same transaction as the state change.
- Require an explicit trusted-issuer human identity assertion in addition to
  token verification, selected profile scopes and current directory membership.
- Publish per-operation OpenAPI responses from the maintained Rust problem
  contract, including bounded framework rejections, request tracing, recovery
  headers, and current DTO shapes.
- Require an explicit local-development or upstream-TLS mode, reject public
  listeners, and document the private server-to-server, no-CORS boundary.
- Add a reproducible combined demo with Registry App Kit and the existing-kit
  comparison.

This checkpoint does not include bulk decisions, consultation, automatic
outcomes, or outbound delivery. Clock policies compute due reminder and
escalation occurrences. When one falls due, the runtime confirms the item with a
fresh source read, then records the reminder in the item's history or, for a
due step, releases the holder and moves the item to the queue the step names,
under the `system:clock` actor. A clock decides no outcome, changes nothing at
the source, and sends nothing outward; an Administrator applies a reviewed
recompute after a policy change.

The unified Registry Stack Node.js and Python client packages include Casework
in this release. The demo builds a matching local candidate from the selected
source trees.
