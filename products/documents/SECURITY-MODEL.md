# Registry Document Store security model

What the Document Store guarantees, what it does not, and what an operator
must do for the guarantees to hold. The enforced invariants, with threats,
enforcement points and test names, are in
[`contracts/security-invariant-matrix.yaml`](contracts/security-invariant-matrix.yaml)
(`DOCUMENTS-SEC-NN`); this page does not repeat them. Configuration is in
[`RUNTIME-CONFIG.md`](RUNTIME-CONFIG.md); the restore drill is in
[`README.md`](README.md).

## 1. Scope and trust boundaries

- **Unauthenticated surface.** Only `GET /health` and `GET /ready`. Readiness
  answers `200` or `503` with no cause; the cause goes to the operational log.
- **Issuer.** Every document route verifies the bearer token (issuer,
  audience, `at+jwt`, allowed clients, signature from the configured key set)
  and resolves exactly one access profile before it reads a body or the store.
  An unreachable key set answers 503, never 401. The deployment trusts one
  issuer; `allowedClients: unrestricted` is refused. A declared issuer or key
  address is trusted on the operator's word, and with `allowInsecureHttp: true`
  an attacker on the network path to the issuer can substitute keys
  (`DOCUMENTS-RES-17`).
- **Custodian.** Alone removes a document and issues, lists and revokes its
  grants. Under citizen delivery the citizen is the custodian and the
  reserving system keeps metadata and status only. Under institutional custody
  the institution stays custodian and a named person is only the represented
  principal, with no standing until granted.
- **Grant holder.** A grant names one exact version and one recipient by
  issuer, subject and actor kind. Release reads the stored grant row only. A
  caller with no standing gets the same 404 as for an unknown identifier.
- **Content verifier.** A version is released only after a verifier approved
  those exact bytes under the binding currently recorded for it. An
  unavailable verifier never releases.
- **Migration credential holder.** Holds authority over the schema.
  `documentsctl apply` is the only path that changes it or records an
  activation; the serving process never does. Package authority is checked
  against the activation ledger on every authenticated request.
- **Runtime credential holder.** Serves requests and, through `documentsctl`,
  lists and replays dead-lettered jobs.
- **Database superuser and object storage.** Trusted completely. The storage
  binding is pinned at the first write; a start under another backend, bucket
  or scope is refused.
- **Hook observers.** Untrusted. They receive closed, content-free events for
  the policies a hook names, at destinations the operator binds, and cannot
  change a document, version or grant.
- **Host users who can write audit files.** Trusted; the journal is only as
  strong as the storage it is written to.

Weakened configuration (plaintext database transport, a disabled verifier or
`http` verifier or hook URL outside `development-loopback`, environment
expressions in secret references, undeclared secret providers) is refused
before anything binds. Findings name the member and rule, never the value.

## 2. Operator obligations

1. **Treat a database restore as a security event.** Restore the audit file
   written since the backup with the database, re-apply every revocation and
   repeat every erasure request it records (`DOCUMENTS-RES-01`,
   `DOCUMENTS-RES-02`). Follow the restore drill: serving stopped,
   `cleanup.erasure: paused`, compare restored state with the audit file.
2. **Keep the migration credential off the serving host** and use split roles
   in production. With one role for both, the runtime keeps schema authority.
3. **Collect both journals.** `documentsctl` apply and replay write to a
   companion journal on the host where they run. Ship it and the runtime
   journal to append-only storage.
4. **Finish a verifier change by restarting every instance**
   (`DOCUMENTS-RES-05`).
5. **Drain before activating a changed package.** Apply waits at most five
   seconds for the activation lock; busy old workers may need draining.
6. **Replay dead letters deliberately.** A dead-lettered verification leaves
   the version pending and unservable; a dead-lettered erasure leaves it
   pending; the sweep re-arms neither. Use `documentsctl verification list`
   and `replay`, and `documentsctl erasure status`, `list` and `replay`.
7. **Alarm on `storage-integrity` audit entries** (digest or length mismatch,
   503, no byte sent). Outages write `storage-unavailable` instead.
8. **Bind hook destinations only for observers entitled to the timing** of
   document and grant events (`DOCUMENTS-RES-12`).
9. **Provision memory for the transfer budget** shared by uploads, downloads
   and verification; `RUNTIME-CONFIG.md` states the figure.
10. **Resume erasure after a pause.** `cleanup.erasure: paused` stops the
    erasure worker, arming and the orphan sweep; serving, removal requests
    and upload expiry continue.
11. **Render labels as untrusted text** (`DOCUMENTS-RES-08`).
12. **Do not reuse a subject for another person** at the issuer
    (`DOCUMENTS-RES-07`).
13. **Use an HTTPS issuer and leave `allowInsecureHttp` unset.** Declare only
    issuer and JWKS addresses you intend the Store to reach
    (`DOCUMENTS-RES-17`).

## 3. Accepted residuals

Related rows are the neighbouring enforced behaviour, not the residual itself.

### DOCUMENTS-RES-01 Restoring a backup resurrects revoked grants

- **Condition:** a backup older than a grant revocation is restored.
- **Consequence:** the revoked grant is active again unless the audit journal
  written since the backup is restored and its revocations are re-applied.
- **Mitigation:** obligation 1.
- **Related:** DOCUMENTS-SEC-24 to DOCUMENTS-SEC-26.

### DOCUMENTS-RES-02 Restoring a backup loses newer erasures

- **Condition:** a backup older than an erasure request or erasure is restored.
- **Consequence:** the version is servable again and its bytes are back.
- **Mitigation:** obligation 1; repeat the requests from the audit file.
- **Related:** DOCUMENTS-SEC-37 to DOCUMENTS-SEC-46.

### DOCUMENTS-RES-03 "Erased" bytes persist in PostgreSQL pages, WAL and backups

- **Condition:** erasure of content held in PostgreSQL or S3.
- **Consequence:** "erased" means the Store can no longer serve the bytes.
  Vacuum only marks space reusable, so bytes stay on their pages until
  overwritten or `VACUUM FULL` rewrites the table. Backups, WAL archives,
  replicas, and S3 versioning or replication outside the Store's key keep them
  as long as those copies are retained.
- **Mitigation:** match backup, WAL and bucket-version retention to the
  erasure promise made to custodians; run `VACUUM FULL` where on-disk removal
  is required.
- **Related:** DOCUMENTS-SEC-37 to DOCUMENTS-SEC-46.

### DOCUMENTS-RES-04 An admitted transfer finishes after revocation or removal

- **Condition:** a download is admitted, then its grant is revoked or removal
  is requested.
- **Consequence:** the download is not interrupted; it finishes within its
  transfer deadline. No release that starts after the commit serves the
  version.
- **Mitigation:** size `transfers.minimumDeadlineSeconds` and
  `transfers.mebibyteAllowanceSeconds` to bound the window.
- **Related:** DOCUMENTS-SEC-28, DOCUMENTS-SEC-37 to DOCUMENTS-SEC-46.

### DOCUMENTS-RES-05 A verifier rollout leaves an older instance releasing

- **Condition:** instances run different verifier bindings during a rollout.
- **Consequence:** an older instance can finalize a version after a newer one
  swept, and release it under the older binding until the next restart sweeps
  it. A worker under the newer binding only retries its job.
- **Mitigation:** obligation 4.
- **Related:** DOCUMENTS-SEC-14 to DOCUMENTS-SEC-20.

### DOCUMENTS-RES-06 The runtime credential can replay dead-lettered jobs

- **Condition:** a holder of the runtime credential runs `documentsctl`.
- **Consequence:** a verification replay only re-queues verification and
  releases nothing (verifier load, no disclosure). An erasure replay re-queues
  an erasure already armed by a custodian or a rejection; it cannot choose
  what is erased. No HTTP route lists or replays a job.
- **Mitigation:** keep the runtime credential on the serving host.
- **Related:** DOCUMENTS-SEC-34 to DOCUMENTS-SEC-36.

### DOCUMENTS-RES-07 A grant follows the subject

- **Condition:** the issuer reuses a subject for another person.
- **Consequence:** the new holder receives what the grant releases. A grant
  names its recipient only by issuer, subject and actor kind; the recipient
  resolver and display names are out of scope.
- **Mitigation:** obligation 12.
- **Related:** DOCUMENTS-SEC-24, DOCUMENTS-SEC-54.

### DOCUMENTS-RES-08 The label is caller text

- **Condition:** a client renders the label as markup or trusts it to describe
  the bytes.
- **Consequence:** the client can mislead its user. The Store returns the label
  as written and makes no claim about it.
- **Mitigation:** obligation 11.
- **Related:** DOCUMENTS-SEC-21 to DOCUMENTS-SEC-33.

### DOCUMENTS-RES-09 A document whose policy is no longer declared is inaccessible

- **Condition:** the deployed package no longer declares a document's policy.
- **Consequence:** the document is shown to nobody, custodian included, each
  access logs a warning, and the custodian cannot remove it. It stays in
  custody until the policy is declared again.
- **Mitigation:** do not drop policies that still have documents in custody.
- **Related:** DOCUMENTS-SEC-21 to DOCUMENTS-SEC-33.

### DOCUMENTS-RES-10 Lists can return short pages

- **Condition:** a caller lists documents under standing rules.
- **Consequence:** the list filters each fetched row, so a page can be shorter
  than its limit while a next cursor remains. The received-grants list selects
  only redeemable grants before its limit and is not affected.
- **Mitigation:** clients follow the cursor until it is absent.
- **Related:** DOCUMENTS-SEC-21 to DOCUMENTS-SEC-33.

### DOCUMENTS-RES-11 Grants after rejection and removal

- **Condition:** a version is rejected, or removal follows a rejection.
- **Consequence:** a rejection alone revokes no grant; a grant on a rejected
  version releases nothing and stays listed as active until it expires or is
  revoked. A removal after a rejection is a first removal: it revokes every
  active grant on the document, and the version keeps the rejection's due
  time. Only a repeat of a recorded removal changes nothing.
- **Mitigation:** none needed for release.
- **Related:** DOCUMENTS-SEC-37 to DOCUMENTS-SEC-46.

### DOCUMENTS-RES-12 Observers learn timing

- **Condition:** a hook destination is bound for a policy.
- **Consequence:** the observer learns that a document exists, when it became
  ready or was rejected, and when grants on it change, keyed by stable ids. No
  event carries content, label, media type, name or subject.
- **Mitigation:** obligation 8.
- **Related:** DOCUMENTS-SEC-48 to DOCUMENTS-SEC-53.

### DOCUMENTS-RES-13 Grant expiry emits no event

- **Condition:** a grant reaches its expiry.
- **Consequence:** expiry is not a recorded transition. A receiver that forgets
  the `expiresAt` an `issued` event carried treats an expired grant as live
  until it is revoked. Release checks expiry and is unaffected.
- **Mitigation:** receivers keep `expiresAt` from the `issued` event.
- **Related:** DOCUMENTS-SEC-49.

### DOCUMENTS-RES-14 Terminal delivery payloads are not yet pruned

- **Condition:** a hook delivery reaches a terminal state.
- **Consequence:** a captured payload stops being sent after
  `retention.hookPayloadRetentionDays`, but the delivery row and payload stay
  in the database; the Store does not yet call the shared pruning. Payloads
  hold ids and timing, no content.
- **Mitigation:** include the delivery tables in database retention planning.
- **Related:** DOCUMENTS-SEC-48 to DOCUMENTS-SEC-53.

### DOCUMENTS-RES-15 A paused deployment keeps due bytes

- **Condition:** `cleanup.erasure: paused`.
- **Consequence:** due bytes remain while paused, and orphan S3 objects
  accumulate.
- **Mitigation:** obligation 10.
- **Related:** DOCUMENTS-SEC-37 to DOCUMENTS-SEC-46.

### DOCUMENTS-RES-17 Declared issuer and key endpoints are trusted

- **Condition:** the runtime file names an issuer or JWKS URI, or sets
  `authentication.oidc.allowInsecureHttp: true`.
- **Consequence:** a declared issuer or JWKS URI may name any private address
  that is not cloud metadata or link-local; the operator who writes the file is
  trusted to name it. A discovered key endpoint on another origin stays under
  the strict public-network policy and must use HTTPS, and redirects are
  disabled. Under `allowInsecureHttp: true`, an attacker on the network path to
  the issuer can substitute keys and so mint tokens the Store accepts. Startup
  logs a fixed warning when the setting is on.
- **Mitigation:** obligation 13; or pin keys with a static `jwksSource`.
- **Related:** DOCUMENTS-SEC-10.

## 4. Development tooling

- `development-loopback` is the only listener setting that permits a disabled
  verifier or an `http` hook URL, and the hook URL must also be a loopback
  address. Do not set it in production.
- `documentsctl plan`, `status` and `check` write nothing.
- **DOCUMENTS-RES-16:** `documentsctl init` refuses an existing path, stages
  the starter and publishes it with one rename. An empty directory another
  local process creates at that path before the rename is replaced by the
  starter. The window needs write access to the parent directory and loses no
  content.

## 5. Reporting

Report vulnerabilities as described in [`../../SECURITY.md`](../../SECURITY.md).
