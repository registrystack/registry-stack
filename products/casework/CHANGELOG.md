# Registry Casework changelog

## Unreleased

- BREAKING: replace hosted decisions with unified reviews. Remove `hosted.rs`
  and its routes: `POST /v1/hosted-items` and the paired
  `GET /v1/hosted-items/terminal`, `GET /v1/hosted-items/{itemId}`,
  `GET`/`POST /v1/hosted-items/{itemId}/notes`,
  `POST /v1/hosted-items/{itemId}/cancel`,
  `GET /v1/hosted-accountability/{eventId}`,
  `POST /v1/work-items/{itemId}/hosted-decisions`, and
  `GET /v1/work-items/{itemId}/hosted-history`. Add `review.rs` and its routes:
  `POST /v1/review-requests`, `GET /v1/review-kinds` and
  `/v1/review-kinds/{kindId}`, `GET /v1/review-results`,
  `GET /v1/review-tasks` and `/v1/review-tasks/{taskId}` with `context`,
  `claim`, `assign`, `delegate`, `release`, `draft`, and `decisions`,
  `GET /v1/review-requests/{requestId}` with `result`, `cancel`, `history`,
  `clocks`, and `notes`, and `GET /v1/review-accountability/{eventId}`.
  Casework now owns approval for BReg change requests through the
  source-neutral producer contract (`registry-review-protocol`,
  `registry-review-client`) instead of BReg holding review state itself. A
  single `0015_unified_reviews.sql` migration creates the review schema and
  drops the experimental `casework_hosted_*` tables; no hosted data is carried
  over.
- Review decisions can carry a structured result. A review kind declares an optional closed
  `resultSchema` beside its display schema, and an outcome may set `resultRequired`. A Requester may
  narrow declared top-level fields per request with `resultConstraints` at create time; the constraints
  are stored verbatim, count in the create idempotency hash, and are refused unless every value they
  admit is already inside the kind schema. The deciding person submits a `result` with the outcome,
  which Casework validates against the schema and then the constraints, and the Requester reads it
  back on the terminal request. Results and their constraints erase with the display payload at
  `terminalDays`; the accountability record keeps only a sha256 digest of the result until its own
  `accountabilityDays` closes.
- Allow governed Casework task templates to approve exact Scheduling service,
  location, and commitment-action bounds. The existing generic ThunderID
  exchange carries them to Scheduling without a product crate dependency.
- The inbox, the next-item result, holdings, the item view, history, and clocks
  stay readable while a subject's source binding has moved within its source
  generation but reconciliation has not applied it yet. The retained occurrence
  is returned without actions. One such item no longer refuses the caller's
  inbox, next item, or holdings. Operations that act on the item or its tasks,
  including claims, drafts, decisions, assignment, and caseload moves, still
  refuse with `work-item.proposal-changed`, and a caseload move preview that
  reads such an item still refuses as a whole.
- The BReg source adapter logs the cause of a source reader failure, such as
  the refusal status and problem code or the token request failure, when it
  first appears or changes, and logs when a reader request next succeeds. A
  missing record is not logged. Caller-facing problem codes are unchanged.

## v0.32.0 - 2026-09-15

- Pair each Casework client with the assertion issuers it may present through
  `assertionIssuers`. A token exchanged through any other assertion authority
  is refused; without the setting no pairing rule applies.
- The Rust Casework client adds `CaseworkTaskAssertionSource` for
  task-grant-bound token exchange. The Node.js client exposes
  `taskAssertionEndpoint()` and the Python client `task_assertion_endpoint()`.
- Borrowed local development sessions admit only the clients they declare.
  `caseworkctl` no longer admits every client of a shared issuer when a session
  declares none.

## v0.31.0 - 2026-09-13

- Add institutional task grants. An officer approves a governed task template,
  and an agent exchanges a short-lived Casework assertion for access bounded to
  the approved client, resource, purpose, subjects, permissions, and deadline.
- Sign explicit requester context for Evidence reads and retain the approved
  source and deadline across restart and token re-exchange. Evidence and BReg
  continue to enforce their own local policy and current grant status.
- Expose task approval, exchange, status, and Evidence context through the
  maintained Rust, Node.js, and Python clients and local development commands.
- Add a source-backed development journey that reviews BReg changes through
  Casework, and preflight every configured source credential before starting a
  multi-source local project.
- BREAKING: remove `taskAuthority.id` and the
  `registry_grant_authority` claim. Task-grant source identity now comes from
  the verified assertion issuer. Reset local development databases containing
  pre-v0.31.0 task grants or drafts, then rebuild source configuration and
  generated clients.

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
