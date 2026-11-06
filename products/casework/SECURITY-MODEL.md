# Registry Casework security model

This page states what Casework's security boundaries hold, what they do not,
and what an operator must do. The row-per-invariant contract is
[`contracts/security-invariant-matrix.yaml`](contracts/security-invariant-matrix.yaml),
and its executable counterpart is
[`contracts/security-test-traceability.yaml`](contracts/security-test-traceability.yaml).
Deployment behavior is in the [README](README.md),
[`RUNTIME-CONFIG.md`](RUNTIME-CONFIG.md) and [`TASK_GRANTS.md`](TASK_GRANTS.md).

## 1. Scope and trust boundaries

- **Token verification and the issuer.** Every authenticated request carries an
  RFC 9068 access token verified for the configured issuer, audience, `at+jwt`
  type, allowed clients and signature from the configured key source. The
  deployment trusts one issuer. A declared issuer or JWKS address may be a
  private address, and the operator who writes the file is trusted to name it;
  cloud metadata and link-local addresses stay refused. With
  `allowInsecureHttp: true`, an attacker on the network path to the issuer can
  substitute keys (CASEWORK-RES-08). A key listed in `revokedKeyIds` is refused
  locally and revoked nowhere else (CASEWORK-RES-09).
- **Producer versus reviewer.** A producer submits review requests and reads
  results; it cannot record human decisions. A reviewer decides under a human
  assertion and a single selected profile; profile scopes are never unioned
  (CASEWORK-SEC-01, CASEWORK-SEC-02).
- **Private reason versus public reason.** Every decision names an outcome
  declared by the pinned policy. The reviewer's private reason stays in the
  accountability record. Only the outcome and an optional `publicReason`
  (at most 2000 UTF-8 bytes) reach the producer result, and the audit journal
  records only that a public reason was given (CASEWORK-SEC-31).
- **Source concealment.** Lists, counts, ordering and exact request selection
  evaluate the caller's live source visibility before releasing anything. An
  unknown, out-of-team, concealed or expired request returns the neutral empty
  result. Retained decision receipts go only to their recorded author
  (CASEWORK-SEC-03, CASEWORK-SEC-12, CASEWORK-SEC-32).
- **Supervisory reads.** Supervisory discovery omits holder identities and due
  dates and grants no reviewer content access. The audited accountability read
  is released only after its audit entry is accepted (CASEWORK-SEC-21).
- **Task grants.** A grant is bounded: 900 seconds for an immediate grant, at
  most 604800 seconds (seven days) for a `deferred` one. Responsibility
  changes, release, a changed subject, template deactivation and revocation
  end a grant, and it cannot be revived by reassigning back. Deferred grants
  cannot carry Evidence bounds (CASEWORK-SEC-18, CASEWORK-SEC-27).
- **Completion signals.** The completion wake-up carries no result and no
  destination authority. The authenticated result fetch and result feed are
  the source of truth (CASEWORK-SEC-08).
- **Activation.** All database writes of a package activation run in
  `caseworkctl apply` and are recorded in an activation ledger. The runtime
  refuses to start on a weakened role boundary until apply records it
  (CASEWORK-SEC-23, CASEWORK-SEC-24, CASEWORK-SEC-25).
- **Local tooling.** `caseworkctl api PATH --client CLIENT` binds the selected
  client's bearer and profile into the request and adds no authority; Casework
  still authenticates and authorizes every route. Remote connections follow the
  [`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary).

## 2. Operator obligations

1. Use a fresh Casework database on PostgreSQL 17 or newer. Casework does not
   upgrade a retired schema in place, and its activation boundary refuses an
   older server.
2. Run split roles: a distinct migration role for `caseworkctl apply` and a
   runtime role for the service. In single-role mode the runtime logs that the
   ledger check catches a wrong package but not someone holding the credential.
3. Hold the migration credential as the authority to activate packages. Pin
   `package.expectedDigest` and keep operator references for each apply.
4. Protect the runtime credential as write access to Casework state (see
   CASEWORK-RES-02 and CASEWORK-RES-03).
5. When an officer's source access is withdrawn, revoke their live task grants
   or remove their Casework eligibility. Keep deferred lifetimes no longer than
   the work needs.
6. Make completion receivers idempotent on the `Idempotency-Key` header (the
   `eventId`), and fall back to `GET /v1/review-results` when a wake-up is
   missed. See [`COMPLETION-RECEIVERS.md`](COMPLETION-RECEIVERS.md).
7. Treat reviewer-written public reasons as released text (CASEWORK-RES-06).
8. Use an HTTPS issuer and leave `authentication.oidc.allowInsecureHttp` unset.
   Declare only issuer and JWKS addresses you intend Casework to reach
   (CASEWORK-RES-08).
9. When a signing key is compromised or retiring, list its `kid` in
   `authentication.oidc.revokedKeyIds`, and list the `kid` of any republished
   copy of that key too. Restart every instance, because the list is read at
   startup. Revoke the key at the issuer and at every other relying party
   (CASEWORK-RES-09).

## 3. Accepted residuals

### CASEWORK-RES-01: activation is not signed

- **Condition:** a package activation carries no signature.
- **Consequence:** anyone holding the migration credential can activate any
  package that verifies; the ledger and audit trail record it afterward.
- **Mitigation:** restrict and rotate the migration credential; pin the
  expected package digest; review the ledger with `caseworkctl status`.
- **Related:** CASEWORK-SEC-23, CASEWORK-SEC-24.

### CASEWORK-RES-02: single-role mode does not protect the ledger

- **Condition:** one database role serves both apply and runtime.
- **Consequence:** the runtime credential can rewrite the activation ledger.
- **Mitigation:** use split roles (obligation 2).
- **Related:** CASEWORK-SEC-23.

### CASEWORK-RES-03: task-template state is writable by the runtime role

- **Condition:** in split mode the runtime role keeps
  `SELECT, INSERT, UPDATE, DELETE` on `casework_task_templates`; only the two
  ledgers are read-only to it.
- **Consequence:** a runtime credential holder can activate or retire a task
  template without `caseworkctl apply`, a ledger row or an activation audit
  entry. Split mode protects the ledgers and the schema, not that state.
- **Mitigation:** treat the runtime credential as privileged; compare stored
  templates with the package at each plan.
- **Related:** CASEWORK-SEC-23, CASEWORK-SEC-18, CASEWORK-SEC-27.

### CASEWORK-RES-04: deferred grants rely on approval-time source access

- **Condition:** the approver's own source access is observed only at
  approval, with that officer's ephemeral credential. Later observations read
  the source through the service reader and recheck Casework eligibility,
  proposal identity and subject facts.
- **Consequence:** a source-side withdrawal of the officer's access alone does
  not end a grant before its deadline, which is at most seven days for a
  deferred grant (900 seconds for an immediate one). Repeating the read would
  need Casework to retain a credential it must not keep.
- **Mitigation:** revoke the grant or remove Casework eligibility (obligation
  5); keep deferred lifetimes short.
- **Related:** CASEWORK-SEC-18, CASEWORK-SEC-27, CASEWORK-SEC-33.

### CASEWORK-RES-05: no transaction spans grant status and resource commit

- **Condition:** scheduling observes grant status, then the resource server
  commits its own mutation; there is no distributed transaction between them.
- **Consequence:** a temporary status or source failure refuses the current
  attempt, and review membership is checked only when observed. A withdrawal
  that is reversed before the next observation is not seen.
- **Mitigation:** revoke explicitly when a withdrawal must stay effective
  after eligibility is restored. Resource servers keep their own duplicate and
  business limits.
- **Related:** CASEWORK-SEC-18.

### CASEWORK-RES-06: public reasons are free text

- **Condition:** `publicReason` is reviewer-written text released to the
  producer. Casework bounds its size and rejects blank or control-character
  text but cannot judge content.
- **Consequence:** approvers who agree on an outcome may write different
  public reasons; only the one from the approval meeting the stage threshold
  is released. The producer decides how long it retains the text.
- **Mitigation:** train reviewers on what a public reason may contain; choose
  `none` for outcomes that need no explanation.
- **Related:** CASEWORK-SEC-31.

### CASEWORK-RES-07: completion delivery is at-least-once

- **Condition:** a send whose response is lost is retried under the same
  `Idempotency-Key`; an attempt interrupted by a crash or restart counts as a
  failed attempt, so an interrupted final attempt ends `dead-lettered` and is
  not retried. One worker serves each runtime process with a one-second idle
  poll.
- **Consequence:** a producer that ignores the key may see a wake-up twice,
  and a dead-lettered wake-up is never delivered. A settled review's wake-up
  can wait up to the poll interval after its retry time.
- **Mitigation:** deduplicate on the key and recover through the result feed
  (obligation 6).
- **Related:** CASEWORK-SEC-08.

### CASEWORK-RES-08: declared issuer and key endpoints are trusted

- **Condition:** the runtime file names an issuer or a JWKS URI, or sets
  `authentication.oidc.allowInsecureHttp: true`.
- **Consequence:** a declared issuer or JWKS URI may name any private address
  that is not cloud metadata or link-local; the operator who writes the file is
  trusted to name it. A discovered key endpoint on another origin stays under
  the strict public-network policy and must use HTTPS, and redirects are
  disabled. Under `allowInsecureHttp: true`, an attacker on the network path to
  the issuer can substitute keys and so mint tokens Casework accepts. Startup
  logs a fixed warning when the setting is on.
- **Mitigation:** use an HTTPS issuer; leave `allowInsecureHttp` unset; or pin
  keys with a static `jwksSource`.
- **Related:** CASEWORK-SEC-01.

### CASEWORK-RES-09: key refusal is by `kid`, locally, at startup

- **Condition:** `authentication.oidc.revokedKeyIds` lists a compromised or
  retiring key, or `maximumTokenLifetimeSeconds` is set.
- **Consequence:** refusal matches the `kid` the issuer assigns, so a
  compromised key republished under another `kid` is accepted until that `kid`
  is listed too. The list refuses keys in Casework only and revokes nothing at
  the issuer, so every other relying party must be changed separately. The list
  is runtime configuration read at startup, so a running process keeps
  authorizing a listed key until it restarts. The lifetime bound compares the
  token's own `exp` and `iat`, so it limits the lifetime the issuer declared,
  not how long ago the token was minted.
- **Mitigation:** obligation 9: list every `kid`, restart, and revoke at the
  issuer.
- **Related:** CASEWORK-SEC-01.

### CASEWORK-RES-10: an empty inbox without a source profile discloses one bit

- **Condition:** a caller lists review tasks without the
  `Registry-Source-Profile` header, and the page would be empty with no
  continuation because at least one candidate was skipped only for the missing
  header.
- **Consequence:** the caller receives `source-profile.required` instead of an
  empty page, which tells it that its queues hold at least one source-backed
  candidate. The problem body names no task, request, subject, count, queue or
  source. A page that lists anything, or an empty page cut short by its
  source-read budget, candidate scan or deadline, is unchanged.
- **Mitigation:** none needed; the candidates are already limited to the
  caller's current membership and served queues.
- **Related:** CASEWORK-SEC-03.

## 4. Reporting

Report suspected vulnerabilities as described in [`SECURITY.md`](../../SECURITY.md).
