# Registry Coordinator changelog

## Unreleased

- Verify BReg runtime issuer and audience against fixture tokens in the shared-issuer journeys.

- Clean up managed project data through `rstack dev` after fixture runs.

- The Node and Python clients accept development peers by default and offer a configuration option to reject them.

- `coordinatorctl serve` passes the resolved posture explicitly to the runtime.

- BREAKING: Rust client configurations take a peer policy in `CoordinatorClientConfig::new`. Migration: pass `PeerPolicy::AcceptDevelopmentPeer` in application code and the runtime's policy in runtimes.

- Coordinator accepts responses from development downstream product peers when the runtime declares development.

- Under `database.transport: loopback-plaintext` or `private-network-plaintext`, the database connection goes to the numeric addresses its host check accepted at startup. A host name such as `localhost` is no longer looked up again for each connection, so a later, different answer cannot send the connection to an address that was not checked.
- Under `database.transport: loopback-plaintext` or `private-network-plaintext`, a keyword connection string host written as an IP address in brackets, such as `host=[::1]` or `host=[127.0.0.1]`, is skipped when the transport otherwise permits it and the driver would dial it, as the driver itself fails that entry and tries the next. When no other host is left, the connection is refused when it is configured, with `platform.database.bracketed-host` naming the address. Write `host=::1`. When a keyword host has an authored `hostaddr`, the connection still uses that `hostaddr`. A bracketed IPv6 address in a URL, such as `postgresql://app@[::1]/registry`, still works.
- The library's public `Store::open` runs the same `loopback-plaintext` check on a plaintext connection, after its local-host check, and dials only the loopback addresses it accepted. A `hostaddr` that is not loopback, `localhost` answering a non-loopback address, or a list whose dialled hosts are all bracketed keyword addresses is refused with the shared code.

- Signed deliveries have the same form in both postures.

- Typed remote mutations require an unauthenticated doctor response with HTTP 401 or 200 and a valid posture header if present. Probe refusals point to `--url`, with `coordinator.command.probe-posture-invalid` for malformed or repeated headers.

- Start a local development run from the starter with `rstack dev start`.
- Typed remote mutations probe the Coordinator API through an unauthenticated `GET /v1/doctor`. Production commands refuse a development or malformed posture mark before sending the mutation.
- BREAKING: Configure OIDC issuer entries under `deployment.authentication.issuers` and keep the client policies under `deployment.authentication.policies`.
  Migration: Move `issuer`, `audience`, `jwksSource`, `allowInsecureHttp`, `assertionIssuers`, and `scopeClaim` to a named entry and set its `allowedClients` to `from-policies` or list the clients explicitly.
- BREAKING: An issuer entry reads scopes from `scope` by default.
  Migration: Write `scopeClaim: registry_scopes` in an entry if its issuer uses that claim.
- BREAKING: An entry that states `accessTokenType: JWT` refuses tokens carrying ID-token markers.
  Migration: Present an access token addressed to the Coordinator.
- BREAKING: Tokens without a caller kind and without a scope beyond OpenID Connect identity scopes are refused.
  Migration: Have the issuer grant the scope the Coordinator policy requires or declare the caller kind for the appropriate issuer or client.
- `coordinatorctl generate identity-facts` writes the clients and access profiles of one configured issuer.
- Development refusal bodies include `failedCheck`, the check that refused the request.

- BREAKING: An undeclared posture is production.
  Migration: Set REGISTRY_STACK_POSTURE=development for laptop and test runs; rstack dev sets it for you.

- BREAKING: `check` reports development settings as errors under the production default.
  Migration: Pass --posture development, or set REGISTRY_STACK_POSTURE, when checking a laptop file.

- BREAKING: Use `loopback-plaintext` for loopback listener placement.
  Migration: Set `tlsTermination` to `loopback-plaintext` for a listener behind a TLS proxy on the same host.

- BREAKING: Issuer `allowInsecureHttp: true` requires development.
  Migration: Delete allowInsecureHttp where the issuer is on loopback: no setting is needed in any posture.

- Development deployments can now set `database.transport` to `private-network-plaintext` for PostgreSQL on the private network.

- Loopback HTTP issuer URLs are accepted in either posture. A non-loopback HTTP issuer requires an explicit development opt-in.

- Production responses keep HSTS behind a TLS proxy on the same host. Development responses omit HSTS when the listener uses a loopback mode.

- BREAKING: Activation records the declared posture. Startup, plan and apply refuse a different posture. Status reports a finding. Existing rows read production.
  Migration: Recreate development databases: a fresh apply is the way.

- BREAKING: `/ready` returns a JSON object with `posture` and `developmentSettings`.
  Migration: No change for probes that read the status code.

- BREAKING: Audit lines carry `posture`.
  Migration: Audit readers with a closed line parser accept the posture member.

- Mutating typed `coordinatorctl` commands probe `/health` without credentials before sending the mutation. A production command refuses a development Coordinator at the probe.
- Development responses carry `Registry-Posture: development`. The Coordinator Rust client refuses that mark, and every typed `coordinatorctl` command refuses it when it runs as production. The refusal code is `coordinator.command.development-peer`. `coordinatorctl api` passes the response through unchecked.

- `/v1/doctor` carries a required `findings` member. It holds the `platform.activation.posture-mismatch` entry when the activation ledger records the other posture.

- BREAKING: Local plaintext PostgreSQL needs `database.transport`. This replaces the local plaintext database behavior selected by the former listener mode.
  Migration: Set `database.transport: loopback-plaintext` for PostgreSQL on the same host, in either posture.

- BREAKING: The shared `platform.database.*` codes report transport configuration refusals.
  Migration: Update scripts that match the old codes.

- BREAKING: protected state schema version 7 records a posture with each
  activation. Version 6 namespaces are refused. Settle their Runs with the
  matching binary, then apply this version to a fresh namespace and database
  identity.

- Coordinator counts every refused caller by the check that refused it, in
  `coordinator_request_refusals_total{check}` on the metrics listener, and
  writes one `request refused` line with `failed_check` and the request's
  trace id, at most five lines per check per minute. A policy denial after
  authentication and a refused signed event delivery are now counted and
  logged too. A scope refusal's line also names the scope claim the
  deployment configured and the scope the caller's policy requires, as
  `scope_claim` and `required_scope`, and nothing from the token. Refusal
  statuses and bodies are unchanged, and
  `coordinator_authentication_refusals_total{reason}` stays.
- Wherever Coordinator and `coordinatorctl` allow plaintext to a loopback
  host, an IPv4-mapped loopback literal such as `[::ffff:127.0.0.1]` counts as
  loopback, the same as `127.0.0.1`. A database host of `localhost` is matched
  in any letter case. Host names other than `localhost` stay refused.
- **BREAKING**. Coordinator verifies event and review completion deliveries
  with Standard Webhooks. The signature is `v1,<base64>` over `webhook-id`,
  `webhook-timestamp` and the exact body bytes. A delivery must be within 300
  seconds of the Coordinator clock in either direction. A refused delivery
  answers 401 with
  `WWW-Authenticate: Registry-Signature scheme="standard-webhooks", version="v1"`.
  A completion also carries `Registry-Recipient-Binding`, which selects the
  connection's key. A completion no longer reads `Idempotency-Key` or
  `Authorization`, and its `eventId` must equal `webhook-id`. An event route
  no longer answers `503 event.source-unavailable`.
- **BREAKING**. Configure one key per event trigger under
  `eventSources.<alias>.triggers.<workflow>.<trigger>.hmacSha256KeyRef`, in
  place of `eventSources.<alias>.signingKeyRef`. Configure
  `connections.<id>.completion.hmacSha256KeyRef` in place of
  `completion.bearerTokenRef`, with the same file in the Casework destination.
  Startup refuses the removed keys with the replacement. It also refuses a
  deployed trigger without a key entry, a key entry without a deployed
  trigger, and a key that is unavailable, shorter than 32 bytes, longer than
  64 bytes or starts with `whsec_`. It refuses the same key bytes in two
  triggers or completion connections, including previous keys, and names both
  paths. A refusal never names a key byte.
- To rotate, keep `hmacSha256KeyRef` fixed, put the new bytes behind it, and
  set `previousHmacSha256KeyRef` to the old bytes on the trigger or the
  completion. Coordinator accepts either key. Restart to load the new files.
- A static key set that startup refuses now names the rule it broke, and the
  key's position for a rule about one key, in the `access.configuration`
  message instead of pointing at the issuer and policy configuration.
- `coordinatorctl provision` creates the database, the migration and runtime
  roles and the grants `apply` expects, from the two database URLs in the
  runtime file, as a PostgreSQL administrator. `--print-sql` prints the plan
  and connects to nothing. When the runtime file has a `deployment` block, a
  runtime URL whose user is not `deployment.runtimeRole` is refused before any
  connection with `coordinator.runtime-config.runtime-role-mismatch`, and a
  runtime URL that names no user gets its own message under the same code.
  `coordinatorctl --runtime-config FILE provision` is accepted, as for every
  other `coordinatorctl` command.

- `GET /health` and `GET /ready` carry the `status` member the other
  services answer: `{"live":true,"status":"ok"}` and
  `{"ready":true,"status":"ready"}`. The `live` and `ready` members stay, and
  the 503 body is unchanged.

- Add native Adapter payment collection operations: request a collection from
  an authoritative bill id and version, read its typed state, and record a
  verified receipt under a separate idempotent command. Collection requests
  support read-only original-key reconciliation. The host-owned `collection`
  completion keeps accepted, pending, and unknown states waiting, correlates
  every read to the accepted bill and binding, and settles the collection
  attempt only on confirmed or failed state. Only Adapter-verified confirmed
  state can produce a registry receipt.
- Add native G2P disbursement operations: submit one approved immutable
  instruction, observe its typed provider state, and report a verified
  provider confirmation under a separate same-command key. An uncertain
  submission stays held and permits only read-only original-command
  reconciliation, never a fresh provider send. The host-owned `disbursement`
  completion keeps accepted, pending, and unknown states waiting, correlates
  every read to the accepted instruction and binding, and settles only on
  provider-confirmed or failed state.

## 0.47.0 - 2026-11-21

- BREAKING: a `CoordinatorProject`'s human `label` and `description` move from
  the top level into the shared `project` block, as `project.label` and
  `project.description` (pre-1.0 cleanup, so every product accepts them in the
  same place). A top-level `label` or `description` is refused with
  `config.removed-key` and the fix "Move label to project.label." Neither
  changes the workflow's stable identity or behavior revision, and the
  compiled presentation is unchanged.

- BREAKING: in the runtime configuration, `database.trustedRootCertificateRef`
  -> `database.caBundleRef`, as a pre-1.0 cleanup, to match the `caBundleRef`
  the other TLS blocks use. The old key is refused as an unknown key. The value
  is unchanged: a secret reference to the PEM CA bundle the connection trusts.
- Report held and stuck work as metrics: `coordinator_runs_attention` by
  reason, `coordinator_runs_restore_review_required`, `coordinator_hold_active`
  for the restore and admissions holds, and `coordinator_oldest_due_age_seconds`
  for the oldest pending step a worker can claim. The counts cover every run,
  not the capped list in `coordinatorctl doctor`.
- The metrics listener accepts `metricsListener.networkExposure`. Set
  `metricsListener.networkExposure: container-private` to also allow the
  unspecified address (for example `0.0.0.0`), for a container whose network
  is private to the deployment. The default, `private-address`, keeps the
  loopback-or-private rule.
- Every database-sampled gauge is read under one 5 second scrape deadline,
  with a server-side statement timeout set to the time left, so the server
  cancels a slow read. Failed reads are logged by error class. A failed read
  is counted in `coordinator_metrics_sample_failures_total`, and its gauge is
  left out.
- Promise Registry Coordinator at Registry Stack 1.0, as the sixth promised product, instead of
  an experimental surface. The promise covers the `workflow.yaml`, `runtime.yaml` and
  `scenarios.yaml` formats, the HTTP API, and the `coordinator` client namespace. The operations
  that call Registry Scheduling or Registry Messaging stay experimental with those products. The
  state baseline and the `v1alpha1` version strings are unchanged.
- Add `stepLabel` to every run status: start, status, list, cancel and the
  `run` member of an inspection. It is the authored label of the current
  step, read from the workflow definition the run was admitted on, so a later
  package that only relabels the step does not change it. It is `null` when
  the step has no label, and after retention erases the run's stored payload.
  The protected state schema does not change.
- BREAKING: upgrade the Coordinator clients with the server, once. The Rust,
  Python and Node clients from before this release refuse response members
  they do not recognise, so they refuse every run status that carries
  `stepLabel`, even when it is `null`. From this release the clients ignore
  response members they do not recognise, as the API stability rules require,
  so a later minor release can add members without another client upgrade.
  They also accept a server that omits `stepLabel`. Rust callers that build
  the client `RunStatus` as a struct literal must set `step_label`.

- BREAKING: `coordinatorctl api --client` is removed. Pass `--url URL --header @FILE`
  with a bearer header file, or use a saved `--connection`.
- BREAKING: protected state schema version 6 adds the durable calendar cursor,
  which records each trigger's cron and timezone, and the optional
  service-deadline instant on each Run. Version 5 namespaces are refused;
  settle their Runs with the matching binary, then apply this version to a
  fresh namespace and database identity. The fresh namespace seeds each
  calendar cursor at the first check, so a calendar occurrence that falls due
  while Coordinator is drained for this reset is not run after it.
- Add reviewed monthly calendar starts using `MIN HOUR 1 * *` or
  `MIN HOUR L * *` in a named IANA timezone. Admission supplies only
  `scheduledAt`, catches up with the latest due occurrence, records the exact
  skipped count, and uses the ordinary fenced Run admission transaction. A new
  Workflow revision keeps an occurrence already due unless the trigger's cron
  or timezone changed; a changed schedule runs nothing the previous one left
  due, and logs and audits (`calendar-reschedule`) how many it skipped. Each
  admission is audited before it is written, and replicas skip a cursor
  another replica is checking. A trigger that leaves the served set loses
  its cursor, so adding it back starts from its first check.
- Add an optional service deadline, `workflow.serviceDeadlineSeconds`, with a
  disjoint `onDeadline` path. It counts from durable Run admission, caps wait
  wake-ups, and takes `onDeadline` once for a still-pending wait, including
  after restart. A shorter wait keeps its own timeout route, and an operator
  cancel ends the service deadline.
- Add optional `onFailure` to read and evaluation call steps. It routes only
  after the ordinary retry limit is exhausted by a definite availability
  category, or when the next retry would not fit before the run deadline,
  records that bounded category on the run, and provides no call output on
  the failure edge. Mutations, authorization and configuration refusals,
  preparation failures, invalid protocol answers and uncertain outcomes
  remain operational failures. In a scenario, one `retryable` reply with such
  a category takes the edge, as the runtime does once retries are exhausted.
- BREAKING: every connection `authorization` and `observationAuthorization`
  in `runtime.yaml` requires `clientAssertionAudience`, with no default. The
  client assertion carries it as its only audience and has the header
  `typ: client-authentication+jwt` (RFC 10070 section 4). A configuration
  without it fails to load with `config.missing-key` naming the member, and an
  `observationAuthorization` states the same audience as its primary
  `authorization`. The audience is part of each connection's binding, so a
  Run admitted without it no longer matches: finish live Runs on the earlier
  release before upgrading. `coordinatorctl deployment-status` with the
  upgraded configuration reports `live-binding-conflict` while one remains,
  and `coordinator --recovery-only` inspects it with admissions and dispatch
  disabled. Migration: set the audience member to the authorization server's
  issuer identifier, exactly as its metadata publishes it.

## 0.46.0 - 2026-11-08

- BREAKING: This release does not read workflow snapshots sealed by 0.45.0 or earlier: a snapshot whose project presentation, function or operation holds `title` is refused with `definition.snapshot`. A step `title` in the free-form `presentation.steps` map still restores and is shown as written. Finish open runs on the earlier release before upgrading.

- BREAKING: The authored `title` of a project, function, operation and step is
  renamed `label`, and `presentation.title` in `check --explain` is
  `presentation.label`, so one word names a display label across the products.
  The duplicate-title diagnostics are now
  `coordinator.project.duplicate-function-label`,
  `coordinator.project.duplicate-operation-label` and
  `coordinator.project.duplicate-step-label`. Migration: write `label: TEXT`
  where a file wrote `title: TEXT` at those four positions; the old key is
  refused with `config.removed-key` naming `label`. A script that reads
  `presentation.title` or matches a duplicate-title code reads the new name.
- Add optional `label` and `description` to `workflow.eventTriggers.<id>`. They are
  stored under `presentation.eventTriggers`, reported by `check --explain`, and
  never change the `workflowRevision`.
- Adopt the shared platform implementations for the access-token algorithm
  roster (still exactly RS256 and ES256), framework-rejection normalization
  (400, 413, 415 and 422 answer the same `request.*` problem codes), the stop
  signal and the Prometheus exposition. Startup still refuses with
  `signal-unavailable` when a stop-signal handler cannot be installed, and now
  installs the SIGINT handler at startup alongside SIGTERM. The `/metrics`
  scrape keeps its series, values and content type.
- BREAKING: `coordinatorctl check` refuses a
  `casework.cancel-review-request/v1` step unless its `request` maps the whole
  output, with no path, of a `casework.submit-review-request/v1` step in the
  same workflow (`definition.review-request-not-run-owned`), as
  `breg.cancel-proposal/v1` already requires of `proposalId`. Every workflow in
  a deployment shares one Casework producer, so this check keeps each run's
  cancel to the request it submitted. The rule also holds on restore: the
  service does not start on a pinned package that breaks it, and a run
  admitted under such a definition is held.
- BREAKING: a live run whose retained definition this version does not
  restore is held alone instead of stopping the deployment. It shows state
  `attention` with failure code `definition-refused`, audited once with the
  restore finding code. Nothing runs for it, and `retry-same`, `reconcile` and
  `cancel` refuse it with 409 `run.definition-incompatible`. Startup,
  readiness, admissions, apply and every other run continue; `attention=true`,
  doctor (`state.heldRunCount`, `state.heldRuns`) and `deployment-status`
  (`heldRuns`) list held runs. A pinned package this version does not restore
  still stops startup.
- Restore refusals give operator context instead of the authoring
  suggestion. A pinned package this version does not restore keeps the
  finding as its code and names its package digest and workflow; a held run
  names its run id and workflow and carries the finding as `findingCode`.
  Both point to "Apply and start" in `DEPLOYMENT.md`. `coordinatorctl check`
  output is unchanged.
- BREAKING: admission accepts a token only when its exact `sub` is listed in
  the caller policy's `subjects`, and refuses any token carrying an `act` claim;
  both answer 403 `operation.not-authorized`. Add `subjects` to every
  `deployment.authentication.policies` entry: the client's own service-account
  subject for a producer, and each operator's subject for an operator policy.
- BREAKING: Functions can no longer call `curry`, and the pure Function
  interpreter ABI is now `v3`. Check refuses a source that uses `curry` and
  suggests passing the value as an argument instead. Every definition frozen
  by 0.45.0 records `v2` and is refused with `definition.abi`, whether or not
  it uses `curry`: settle runs with the 0.45.0 binaries, then check and
  promote the project again.

- A Proposal wait whose read shows BReg applying the Proposal automatically
  (`submitted`, `turn: nobody`) schedules its next read at the read floor,
  `minimumObservationIntervalSeconds` (default 30 seconds), instead of after
  `resultCheckSeconds` (default 900), so a review-free Proposal settles within
  about the floor. The read floor and observation budget still apply.
- `GET /v1/runs` and `coordinatorctl list` take `outcome=<name>`
  (`--outcome`) for the runs that finished with that workflow outcome, matched
  exactly. List cursors carry it; a cursor from a list without it continues
  unchanged. The Rust client's `RunListQuery` gains `outcome`, and the Node.js
  and Python `list` take it as a last argument.
- BREAKING: The Rust client's `RunListQuery` is `#[non_exhaustive]`, so a
  struct literal no longer compiles. Construct it with
  `RunListQuery::new(limit)` and chain `with_cursor`, `with_state`,
  `with_attention`, `with_proposal`, `with_turn` and `with_outcome`, or set
  the public fields on the value `new` returns. A later filter is then added
  without breaking callers; this is the last break of its kind.

## 0.45.0 - 2026-11-03

- BREAKING: Registry Record v1 renames `entityTypeIdentifier` to
  `recordTypeIdentifier` before the 1.0 freeze. `breg.read-record` output
  follows the v1 contract, so a Service reads `meta.recordTypeIdentifier`.
- BREAKING: Generated `EventSubject` schemas are an `anyOf` of the Record and
  Proposal subject shapes, matching BReg event subjects.
- BREAKING: A runtime configuration file is refused with
  `platform.runtime-config.unsafe-file` when it or an ancestor directory is not
  owned by root or the runtime user, or is writable by group or others. A
  root-owned sticky ancestor stays allowed.
- BREAKING: protected state schema version 5 adds the latest Proposal
  observation to each wait that follows a BReg Proposal. Version 4 namespaces
  from 0.44.0 are refused. Settle their runs with the 0.44.0 binaries, then
  apply to a fresh namespace and database identity.
- BREAKING: the pure Function interpreter ABI is now `v2` because the
  profile gained helpers. Every definition frozen by 0.44.0 records `v1` and
  is refused with `definition.abi`, whether or not it has a Function, so no
  0.44.0 run continues on this version. Settle runs with the 0.44.0
  binaries, then check and promote the project again. A 1.0 install starts
  on `v2`.
- BREAKING: upgrade the Coordinator clients with the server. The 0.44.0
  Rust, Python and Node clients refuse unknown fields, so they refuse an
  inspection that carries `holdDetail`, `lastObservation` or `requestLink`.
  Rust callers that build `RunListQuery`, `WaitStatus`, `StepStatus` or
  `BRegProposalSubmission` as struct literals must set the new fields.
- Add the BReg Proposal operations `breg.read-proposal/v1`,
  `breg.start-proposal/v1`, `breg.submit-proposal/v1` and
  `breg.cancel-proposal/v1`. Each names a Proposal of one pinned Proposal
  Action, and the host-owned Proposal completion follows it by Proposal Get
  until it is applied, rejected or cancelled, or returned to the party after
  this run submitted it. Start and submit replay as frozen commands under
  stable keys; check refuses a cancel that does not name a Proposal the run
  opened. No operation decides a Proposal.
- A `breg` connection takes `resultCheckSeconds` (60 to 86,400, default 900)
  for how often a Proposal wait reads, and a `requestLink` template: `https`,
  or `http` on a loopback IP address, as for connection endpoints.
  Neither enters the binding digest, so both can change while runs wait.
- `coordinatorctl check` warns `coordinator.follow.long` for a Proposal wait
  longer than 90 days and `coordinator.follow.timeout-unrouted` for one with
  no `onTimeout` route.
- Add `breg.read-in-force/v1`: one `:as-of` read for the record of a
  date-interval Record type in force for a structured `subject` on a `date`.
  It sends the date as a calendar date. No record is the declared refusal
  `none-in-force`, which needs an `onDeclaredRefusal` route; two records hold
  the run with `in-force-ambiguous`, and inspection names both record
  identifiers and the date. Check refuses a Record type without a date
  interval (`definition.read-in-force-entity`) and warns
  `coordinator.read-in-force.may-be-ambiguous` when no `temporal-non-overlap`
  constraint is scoped only by fields the subject names. It needs a BReg
  record schema that carries the `x-registry-temporal` marker.
- Add `breg.lookup-record/v1`: one BReg `:lookup` for the record that a
  structured set of `values` (one to sixteen text, number or flag fields)
  resolves to under a compiled `selector`, with the record's provenance and
  `observedAt`. BReg's single value-free `lookup.unresolved` is the declared
  refusal `unresolved`. Check refuses `unresolved` routed straight to a step
  that creates or changes a record (`definition.unresolved-route`), because no
  match, two matches and a hidden row look alike. A review request or a message
  may follow directly. The provenance of a lookup has no ETag, because BReg
  sends none on a lookup. Check refuses `breg.lookup-record/v1` and
  `breg.read-in-force/v1` on a connection that sets `taskAuthority`, because
  neither takes a grant.
- Add `breg.read-record/v2`: the input and record envelope of
  `breg.read-record/v1` plus a `provenance` member with the record and
  revision identifiers, the ETag and `observedAt`, the Coordinator's clock when
  the read returned. `breg.read-record/v1` is unchanged. Both new operations
  accept `record: {contract: <import>}`, which limits `domainData` to the
  record type's API names as it does for `breg.read-record/v1`.
- The BReg profile must grant `lookup` for `breg.lookup-record/v1` and `get`
  for `breg.read-record/v2`. Check does not read profiles, so a missing grant
  shows at run time as `product-forbidden`.
- `coordinatorctl check` now refuses a `fields` mapping that sets fewer or more members than the
  schema's `minProperties` or `maxProperties` allow, instead of leaving the
  mismatch to the run.
- Add Check now: `POST /v1/runs/{run}/check` and `coordinatorctl check-now`
  bring forward the next read of a step's open wait. It keeps the read floor,
  counts against the wait's read budget, needs only the inspect grant, is
  audited as `check-now`, and answers `409 check.not-waiting` when the step
  has no pending wait, including a wait held for recovery.
- A `fields` mapping member can be a nested `fields` mapping, up to 4 levels
  and 64 members across levels, so a Workflow builds a structured input
  without a Function. Check reports `mapping.fields-depth` and
  `mapping.fields-count`, and checks each nested member against the input
  schema at its path.
- A `choose` step can route on `type: compare`, with `all` or `any` over one
  to sixteen conditions (`equals`, `oneOf`, `less`, `greater`, `present`),
  to the cases `matched` and `unmatched`. Dates order as calendar dates. A
  missing or wrongly typed value fails the run with `choice-invalid` rather
  than routing to `unmatched`.
- Inspection shows each Proposal wait's `lastObservation` (state, turn,
  submission version, any hand-off refusal code, `observedAt` and
  `stateSince`) and, when the BReg connection sets `requestLink`, its
  `requestLink`.
- `GET /v1/runs` and `coordinatorctl list` take `proposal=<id>` (`--proposal`)
  for the runs waiting on one BReg Proposal and `turn=party|official|nobody`
  (`--turn`) for runs whose Proposal wait last read that turn. List cursors
  carry these filters; a cursor issued by 0.44.0 is refused, so start the
  list again.
- Doctor reports `state.proposalWaitsByTurn`, the Proposal waits counted by
  their last observed turn plus those not yet observed, from stored rows
  without calling BReg.
- The Rust, Python and Node Coordinator clients decode a wait's
  `lastObservation` and `requestLink` on inspection, a held step's
  `holdDetail`, and their run lists take the `proposal` and `turn` filters.
- Functions can call Rhai's string helpers (`trim`, `split`, `starts_with`, `index_of`,
  `sub_string`, `pad`, `replace`, and the rest of its string package) and these number helpers:
  `parse_int`, `parse_float`, `to_int`, `to_float`, `sqrt`, `floor`, `ceiling`, `round`, `int`,
  `fraction`, `is_nan`, `is_finite`, `is_infinite`, `to_degrees`, `to_radians`, `PI` and `E`, next to
  the arithmetic package's `abs`, `sign`, `min` and `max`. The trigonometric, hyperbolic,
  exponential and logarithmic functions (`sin`, `exp`, `ln`, `log`, `hypot` and the like) are not
  available, because their last digits depend on the host's math library and Function results are
  recomputed. `replace` and `pad` refuse a result over the string limit before building it, and
  `pad` refuses an empty padding string. A Function result that holds NaN or an infinite number is
  refused with `function.execution` instead of becoming JSON `null`.
- `coordinatorctl check` reports a call to a name the pure profile lacks as
  `coordinator.function.unknown-call`, with its line and column, before any Function runs. It also reads a string literal given to `Fn`, `is_def_fn` or an array
  method such as `map` as a function name. It is an authoring aid; the engine still refuses an
  unknown name when the Function runs.
- `coordinatorctl explain functions` lists the helpers a Function may call, the interpreter ABI
  and the limits.

## 0.44.0 - 2026-10-27

First release of Registry Coordinator.

- v0.44.0 ships the `coordinator` and `coordinatorctl` binaries, their
  installer, and the Coordinator namespace in the unified Node.js and Python
  clients. The Coordinator image remains held.
- `coordinatorctl check --project` reads an optional
  `check-acceptances.yaml`, keeps exactly matched warnings visible with their
  reasons, and excludes only those accepted warnings from `--deny-warnings`.
- Coordinator executes finite, acyclic Workflows across durable waits, outages, and restarts.
  Projects separate generated contracts, reusable types, named pure Functions, local exact
  Operation aliases, and one Workflow graph. Functions take one typed object of named inputs.
- Runtime bindings use one tagged `connections` map. Caller policies are keyed by exact verified
  client identity and scope run actions through `workflows`.
- Scheduling operations can read appointments, create and release holds, confirm holds, and
  reschedule or cancel appointments under task-bound authority. Each operation declares whether
  exact-command replay, original-result lookup, or a non-repeatable uncertainty hold is available.
- Starts require an expected computed `workflowRevision`. Workflow discovery and generated
  TypeScript/Python wrappers provide revision-pinned typed `start`, `get`, and `cancel` through
  the Coordinator client bindings. Unknown admission preserves its original revision and key.
- Named completions share `completion: {step, name}` across Casework results and bounded external
  job observation. Persistent read floors, retry ceilings, and
  observation budgets survive restarts and wake-ups. Blocked or uncertain evidence remains held.
- `external.command/v1` sends one bounded POST to the exact `commandPath` an operator configures
  on an `external-http` connection. The command and its request id are persisted before the first
  send and the id travels as `Idempotency-Key`; a required pure `interpret` Function maps the
  validated response to an accepted result, a declared refusal, or an uncertain hold. Before
  any uncertain attempt, a 429 is treated as not processed and retried only when another
  attempt fits the remaining attempt and deadline budgets; otherwise the run ends without
  `retry-same`. Once an attempt has an unknown effect, a later 429 or declared refusal holds
  the run. A 503 is retried with the effect held as unknown only when another attempt fits both
  budgets; otherwise it holds the run at once. Lost acknowledgements, timeouts, redirects,
  other server errors, and unusable responses hold the run, and `retry-same` resends the same
  command with the same id. Scenarios reply to it with `type: response`, never with a
  synthetic `success` or `declared-refusal`, and only with a status that reaches the
  interpretation Function; a
  redirect, 429 or 5xx takes an `uncertain` or `retryable` reply instead. Providers must
  deduplicate on the request id.
- Base Registry Engine (BReg) Action aliases import owner-generated exact contracts for immediate
  Actions, which can route declared no-effect refusals explicitly. The applicant drives a Proposal
  in BReg; a Workflow follows it by product event or record read.
- Workflows can request independently authorized Casework review. Signed product events can start
  typed workflows through explicit source bindings.
  Receiving products retain effect authority and recheck their conditions before committing.
- Inspection reports accepted or unknown effects and bounded wait state without protected inputs,
  raw product responses, prepared requests, or correlation values. Encrypted PostgreSQL custody,
  durable audit, retention tombstones, and explicit fenced restore recovery protect work.
- Protected state schema version 4 directly replaces earlier pilot layouts. Earlier schema
  versions are refused; there is no in-place conversion or legacy authoring syntax.
  Recreate an unreleased development database made before the leased-job CHECK required
  `lease_expires_at IS NOT NULL` to obtain that constraint. Such a database still reports
  version 4: startup does not detect or migrate its older CHECK.
- Maintained examples cover standalone Casework review, product events, and external job
  completion. Native service checks compose BReg, Casework, Scheduling, and Messaging; the
  deferred-appointment journey retains a real 961-second wait and original receipt recovery. Offline scenarios and message acceptance do not establish provider delivery.
- Signed event intake accepts deliveries up to the 1 MiB Version 1 signable bound, verifies them
  through the shared hooks receiver, and answers a larger one with `request.body-too-large`.
  Delivery counters are canonical positive decimals up to the signed 64-bit range. The admitted
  event value still fits the 128 KiB structured value profile; an event over that profile is
  refused with `event.too-large` (413), which names the bounds and asks the producer to project
  fewer or smaller fields into the event.

- BREAKING: a discovery `jwks_uri` on another origin than the
  `deployment.authentication` issuer must use HTTPS and is refused when it
  resolves to a private or loopback address, under `development-loopback` too.
  The issuer and a declared `jwksSource.uri` may resolve to a private or
  loopback address, and `deployment.authentication.allowInsecureHttp: true`
  permits plain HTTP beyond loopback to them. Migration: declare the key
  endpoint as `jwksSource: {type: uri, uri: ...}` or serve it from the
  issuer's origin.
