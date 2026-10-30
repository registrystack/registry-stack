# Registry Coordinator security review notes

Review notes for security-sensitive Coordinator changes, held in tracked
material because commit messages do not survive a squash. Each section names
the threat it answers, the defaults the product ships, where Rust enforces it,
the tests that pin it, and the residual risk it accepts.

## Lapsed read leases

### Threat

A worker can exit after leasing a read but before recording its result. Holding
every such job delays a workflow even though repeating the operation is safe.
Conversely, treating every lapsed lease as retryable could repeat a mutation,
evaluation or same-command effect whose remote outcome is unknown. A late
completion from the original worker could also race the replacement attempt.

### Enforcement and defaults

`Store::decode_lapsed` in `crates/registry-coordinator/src/store.rs` opens the
authenticated definition snapshot for the selected run and resolves the exact
leased step. Only a call whose catalog recovery is `read-again` receives
Dispatch's `RetryThenHold` policy. Every mutation, evaluation, same-command
call, wait and local step retains `Hold`; no database flag, schema change or
mutable runtime catalog decision is involved.

`RetryThenHold` uses the existing backoff, ten-attempt limit and original run
deadline. It schedules another read while those bounds allow it, but converts
the dead-letter or expiry edge to `unknown`, so repeated failure still reaches
operator review. Dispatch commits the `lease-lapsed` transition audit before
release and fences completion by generation, attempt and lease token. A stale
worker cannot commit after the replacement attempt starts.

### Tests

- `crates/registry-coordinator/tests/read_lease_recovery.rs`:
  `lapsed_read_retries_and_fences_the_old_attempt`,
  `lapsed_mutation_holds_unknown_for_operator_review`,
  `lapsed_read_holds_when_attempts_are_spent`, and
  `lapsed_read_holds_after_its_deadline` exercise the PostgreSQL transition,
  audit pair, retry count, deadline and stale-worker fence.

These are maintained references, not claims that the tests ran in this note.

### Accepted residuals

- A replacement read can observe newer source state than the interrupted read
  would have returned. `read-again` promises a safe current observation, not a
  historical response replay.
- A source incorrectly configured as a read can still have side effects. The
  closed operation catalog, fixed HTTP method and reviewed package are the
  boundary; Coordinator cannot prove a provider's implementation is read-only.
- A read that repeatedly loses its worker still stops at `attention` when its
  existing attempt or deadline bound is spent. Recovery does not extend either
  budget.

## Scheduling lifecycle recovery

### Threat

Coordinator can lose the response after Scheduling has committed capacity. A
fresh command, an ordinary current-state read, or replay of an unkeyed release
could duplicate or misstate that effect.

### Enforcement and defaults

Each Scheduling lifecycle operation declares its own recovery behavior in the
Coordinator operation catalog. Reads can run again. Appointment creation and
hold confirmation retain the exact key and request and may use Scheduling's
original-result receipt. Hold creation, rescheduling, and cancellation retain
the exact keyed command but expose no receipt lookup; current appointment state
does not settle them. Hold release carries no key, so an ambiguous dispatch is
held and cannot be sent again. Every commitment obtains fresh task-bound
Scheduling authority for each durable attempt. The Scheduling client performs
no hidden mutation retry inside Coordinator.

### Tests

- `crates/registry-coordinator/tests/scheduling_adapter.rs`:
  `lifecycle_operations_use_exact_public_client_routes_bodies_and_keys`,
  `unkeyed_hold_release_holds_an_ambiguous_dispatch_without_replay`,
  `only_appointment_creation_and_confirmation_have_original_result_receipts`,
  and `standing_reads_are_bounded_and_never_authorize_a_commitment`.
- `crates/registry-coordinator/src/operations.rs`:
  `operations_use_registered_execution_semantics`.

### Accepted residuals

- Scheduling exposes no original-result receipt for hold creation,
  rescheduling, or cancellation. Idempotency expiry leaves the run held for
  investigation; Coordinator does not infer an outcome from later state.
- Scheduling hold release is deliberately unkeyed. A timeout, broken exchange,
  invalid response, or server failure after dispatch remains uncertain until an
  operator resolves or cancels the held run.

## Bounded external command

### Threat

`external.command/v1` adds an outbound mutation to a provider outside Registry
Stack and a recovery path that can send it again. Workflow data could try to
steer the request to another host, path or credential. A lost acknowledgement,
timeout, redirect or server error, including a busy 503 whose retry never
settles, could be misread as failure, so a fresh command would apply the effect
twice. A response, command body, request id or credential could leak through
logs, problem details, `status` or `inspect`.

### Enforcement and defaults

- The destination is operator configuration. `ExternalHttpConfig` in
  `crates/registry-coordinator/src/external_http.rs` holds one exact relative
  `commandPath` beside `baseUrl` and `authorization`; the Workflow supplies only
  a JSON object body. `ExternalHttpConnection::command` sends one POST, follows
  no redirect, and validates the destination under the same fetch policy as
  `external.get/v1`. A connection without `commandPath` is read-only, and
  `RuntimeConfig::validate_workflow` (`workflow-binding`) refuses a command
  alias bound to it or to another connection type at `coordinatorctl check`.
- The command and its request id are frozen and persisted before the first
  send. The id is derived from the run's start identity and the step, and is
  sent as `Idempotency-Key` on every attempt; the catalog entry in
  `crates/registry-coordinator/src/operations.rs` declares same-command
  recovery, so `retry-same` and restart replay the frozen request and never mint
  a new id.
- Request bodies and responses are limited to 65,536 bytes, and each attempt to
  the connection's timeout, at most 2,000 milliseconds, which also covers DNS
  resolution and token acquisition. Only status 429, and status 503 before the
  final attempt, are retried automatically, under the existing spacing rules. A
  429 is trusted to mean the command was not processed. A 503 may follow an
  effect, so `send_command` returns `CallOutcome::UncertainRetryable` and the
  worker records the attempt as uncertain while it retries: a deadline or retry
  limit reached before a later attempt settles it holds the run with the effect
  unknown, and `Store::write_attempt` never reports such a run `expired` or
  `failed`. The worker keeps that retry only when the longest wait the retry
  schedule allows, counted from the end of the attempt's lease, clears the run
  deadline (`retry_or_hold` in `crates/registry-coordinator/src/worker.rs`).
  Otherwise it reports the attempt uncertain without a retry, so Dispatch holds
  the job `unknown` instead of expiring it, and `retry-same` can send the same
  command under the same id while the deadline is in the future. A command
  honours a `Retry-After` only as one delta-seconds value of
  at most 86,400 and otherwise ignores it. Once the request may have left, a
  lost or broken exchange, a timeout, a redirect, any other 5xx, and an
  oversize, malformed or schema-invalid response are uncertain and hold the
  run.
- `interpret_command` in `external_http.rs` checks the response against the
  alias's `responseSchema`, then runs the project's pinned pure Function. Only
  `accepted` with a result matching the step's declared output, or `refused`
  with a declared code, leaves the hold; everything else, including a Function
  error, is uncertain. The worker and offline scenarios use the same function:
  a scenario replies to a command step with a `response` that function
  interprets, and scenario validation (`scenario.reply`) refuses a `success` or
  `declared-refusal` reply to the step, so no scenario can reach a result or
  refusal route the Function would not produce. The transport and scenario
  validation share one status classification (`command_status` in
  `external_http.rs`), so a `response` reply with a status the worker holds or
  retries before interpretation (a redirect, a 429 or any 5xx) is refused too,
  with the `uncertain` or `retryable` reply that models it named in the repair.
- Outcomes carry fixed failure codes only. No body, response, request id or
  token is logged or placed in a problem, `status` or `inspect`.

### Tests

- `crates/registry-coordinator/tests/external_command.rs`:
  `a_command_posts_the_frozen_body_and_request_id_to_the_configured_path`,
  `workflow_input_cannot_choose_destination_headers_or_credentials`,
  `a_lost_acknowledgement_is_uncertain_and_the_same_request_id_is_sent_again`,
  `a_timeout_after_sending_is_uncertain_and_never_a_provider_failure`,
  `failures_before_anything_is_sent_stay_retryable_or_refused`,
  `an_oversize_or_unusable_response_is_held_without_releasing_its_body`,
  `a_redirect_is_not_followed_and_the_credential_stays_at_the_origin`,
  `provider_statuses_are_classified_without_claiming_a_provider_failure`,
  `no_secret_body_or_request_id_reaches_logs_or_outcomes`,
  `the_runtime_routes_a_frozen_command_with_its_original_request_id`, and
  `the_command_path_is_an_exact_operator_owned_relative_path`.
- `crates/registry-coordinator/tests/external_command_project.rs`:
  `check_refuses_a_command_without_its_bound_command_connection`,
  `the_workflow_cannot_name_a_destination_path_or_credential`,
  `the_worker_interprets_a_response_into_one_of_three_results`,
  `a_command_without_a_refused_state_has_no_refusal_route`,
  `scenarios_interpret_provider_responses_with_the_pinned_function`,
  `a_command_reply_reaches_its_result_only_through_the_interpret_function`, and
  `a_command_response_reply_carries_only_a_status_the_worker_interprets`.
- `crates/registry-coordinator/tests/external_command_postgres.rs`, under
  PostgreSQL: `a_lost_acknowledgement_holds_and_retry_same_sends_the_same_command`,
  `a_timeout_holds_as_uncertain_and_never_claims_a_provider_failure`,
  `a_restart_between_persist_and_send_sends_the_prepared_command_once`,
  `a_busy_503_the_deadline_ends_holds_the_same_command_for_recovery`,
  `a_deadline_that_passes_before_a_busy_503_is_retried_holds_the_effect`, and
  `a_busy_503_then_an_accepted_command_clears_the_unknown_effect`, each
  asserting that `status` and `inspect` carry no body, request id or token.
- `crates/registry-coordinator/src/worker.rs`:
  `a_busy_answer_that_may_follow_an_effect_retries_with_the_effect_unknown` and
  `a_busy_answer_that_may_follow_an_effect_retries_only_when_the_retry_fits`.
- `crates/registry-coordinator/src/operations.rs`:
  `operations_use_registered_execution_semantics`.

These are maintained references, not claims that the tests ran in this note.

### Accepted residuals

- Same-command recovery is only as safe as the provider's deduplication on
  `Idempotency-Key`. Coordinator cannot verify it; the deployment runbook makes
  it a provider requirement, and an operator should not use `retry-same`
  against a provider that lacks it.
- The operation has no original-result receipt, so `reconcile` cannot settle an
  uncertain command. An operator checks the provider's own records, then
  retries or cancels the held run.
- An accepted result is the provider's answer as the project's Function reads
  it. Coordinator does not independently verify the provider's effect, and a
  Function that maps an ambiguous answer to `accepted` is an authoring defect
  that scenarios and review must catch.
- After an uncertain attempt, a later declared refusal or 429 is held rather
  than routed or retried, so a provider that replays a refusal for a repeated
  key leaves the run for an operator to cancel. A retried 503 counts as an
  uncertain attempt, so a 503 followed by a refusal or 429 reaches this hold
  too.
- The check that keeps a 503's retry counts from the end of the attempt's
  lease, by which a live worker normally records its answer. A worker that
  records it later, after its lease has ended, can still see Dispatch expire
  the job; the run then shows `attention` with the effect unknown, but
  `retry-same` refuses the expired job and the operator checks the provider's
  records and cancels the run. Closing that window needs Dispatch itself to
  hold, rather than expire, a retryable answer that may follow an effect.
- A 429 is trusted to mean the provider did not process the command. A
  provider that answers 429 after applying it lets the final attempt end the
  run `failed` with `external-rate-limited`; the deployment runbook forbids
  that answer.

## Coordinatorctl access-token files

### Threat

An authenticated `coordinatorctl` command reads `--token-file` before it calls
the service. Opening a FIFO with an ordinary blocking read can hold the command
indefinitely, and following a symbolic link means the named path does not
identify the file the operator intended to use.

### Enforcement and defaults

On Unix, `coordinatorctl` opens the token path read-only with `NOFOLLOW`,
`NONBLOCK`, and `CLOEXEC`, then verifies from the opened descriptor that it is
a regular file before reading any bytes. Other platforms reject a symlink or
non-regular path before opening it and verify that the opened handle is a
regular file. The existing 16,384-byte bound, compact-token validation, and
value-free diagnostics remain unchanged. This check applies only to
`--token-file`; ordinary authored input files keep their existing contract.

### Tests

- `crates/registry-coordinator/tests/cli_remote.rs`:
  `token_file_refuses_symlinks_and_fifos_without_blocking` bounds the child
  process wait, exercises a symbolic link and FIFO, and proves neither output
  stream contains the synthetic token.
- The same target's
  `a_relative_token_file_is_read_from_the_current_directory` keeps the normal
  regular-file path and relative-path behavior covered.

### Accepted residuals

- `coordinatorctl` remains local operator tooling on a trusted single-user
  machine. The Unix open is race-safe for the final path component; broader
  filesystem and directory-component races remain accepted for this adopter
  CLI rather than introducing a directory-descriptor traversal policy.

## Raw API connection authentication

### Threat

An operator assumes the raw API command reuses the legacy Coordinator token
reader, or assumes a saved bearer or `private_key_jwt` connection grants
workflow authority by itself.

### Enforcement and defaults

Coordinator retains no local caller session, so `coordinatorctl api` refuses
`--client`. The operator selects a saved connection or an explicit one-off
URL. A saved connection's automatic authentication is exactly one of
anonymous, a referenced opaque bearer, or renewable `private_key_jwt`, under
the shared
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary).
Anonymous supplies no automatic credential, but the raw command may still
supply one explicit `Authorization` header. The helper confines the
destination and headers, acquires any selected automatic credential, and
releases only the raw bounded response. It carries no caller policy, workflow,
run ownership, or downstream product authority. Coordinator still
authenticates and authorizes each protected route, and every receiving product
still decides an effect requested by a run.

This path deliberately does not reuse the legacy reader described above.
Legacy authenticated Coordinator commands keep their 16,384-byte compact-JWT
validation and, on Unix, `NOFOLLOW` token open. Direct
`api --url --token-file` instead uses the shared opaque-bearer contract: at
most 8 KiB and a symlink to a regular file is accepted. Saved bearer and
private-key references use the platform secret resolver's separate strict
file policy. These differences preserve both existing contracts rather than
silently changing older commands.

### Tests

- `crates/registry-coordinator/tests/api_cli.rs`:
  `api_and_saved_connections_are_available_without_a_runtime_config` and
  `raw_api_refuses_report_format_before_network_access`.
- The shared saved-credential, transport, regular-file, and process tests
  named in the `registry-cli-api` security boundary.
- The legacy reader remains pinned by
  `token_file_refuses_symlinks_and_fifos_without_blocking` and
  `a_relative_token_file_is_read_from_the_current_directory` in
  `crates/registry-coordinator/tests/cli_remote.rs`.

These are maintained references, not claims that the tests ran in this note.

## OIDC issuer transport and private addresses

### Threat

The Coordinator fetches discovery and signing keys for
`deployment.authentication`. A fetch an attacker can steer may reach internal
services or cloud metadata, and a key set read over plain HTTP can be
substituted by an on-path attacker, whose keys would then mint access tokens
the Coordinator accepts.

### Enforcement and defaults

The Coordinator fetches under the shared issuer network policy that Casework,
Messaging, and Scheduling use, instead of the strict public policy, or the
development loopback policy under `development-loopback`:

- The declared issuer and a declared `jwksSource.uri` may resolve to a private
  or loopback address on any origin; both are operator configuration.
- A discovered `jwks_uri` inherits that allowance only on the issuer's own
  origin. On another origin it must use HTTPS and is refused when it resolves
  to a private or loopback address, under `development-loopback` too.
- Cloud metadata and link-local addresses are refused for declared and
  discovered endpoints alike. Redirects remain disabled.
- Plain HTTP is accepted at load only with
  `deployment.authentication.allowInsecureHttp: true`, or on loopback under
  `development-loopback`. That setting never extends plain HTTP to a
  discovered endpoint on another origin.

`OidcIssuerConfig::check` in `crates/registry-platform-config/src/blocks.rs`,
reached from `AccessConfig::findings` in
`crates/registry-coordinator/src/access.rs` when the runtime file is loaded,
refuses a plain HTTP issuer or key URI the rules above do not admit, at its
member and with the setting that would admit it. `AccessConfig::authenticator`
builds `IssuerNetworkPolicy` from the same block, fetches discovery through
`fetch_discovery_for_issuer`, and keeps the endpoint policy that function
returns for every later key refresh; a declared key URI keeps
`declared_jwks_fetch_policy`. When the opt-in is set, startup logs the fixed
warning from `insecure_http_startup_diagnostic`.

### Tests

- `crates/registry-coordinator/tests/deployment_surface.rs`:
  `a_remote_http_issuer_is_refused_without_the_opt_in` and
  `runtime_reads_the_explicit_http_issuer_opt_in`.
- `crates/registry-coordinator/src/access.rs`:
  `http_issuer_opt_in_has_a_startup_diagnostic`.
- `crates/registry-platform-oidc/src/lib.rs`, for the shared policy:
  `non_loopback_http_requires_the_named_opt_in_while_loopback_does_not`,
  `declared_loopback_http_jwks_under_an_https_issuer_is_accepted_without_the_opt_in`,
  `a_cross_origin_jwks_must_use_https_even_under_the_http_opt_in`,
  `discovered_cross_origin_private_or_loopback_jwks_stays_refused`, and
  `cloud_metadata_is_refused_for_declared_and_discovered_key_endpoints`.

### Accepted residuals

- Outside `development-loopback`, the declared issuer and a declared key URI
  may now resolve to a private address. An operator who declares an internal
  address points the Coordinator at it; the allowance covers only what the
  operator wrote, and cloud metadata stays refused.
- With `allowInsecureHttp: true`, an on-path attacker between the Coordinator
  and the issuer can substitute keys. The setting is explicit, named in the
  startup warning, and confined to the issuer's origin and the declared key
  URI.
- A deployment whose discovery document names a key endpoint on another
  private origin is refused at startup. The changelog names the migration:
  declare the key endpoint as `jwksSource.uri`, or serve it from the issuer's
  origin.

## Rhai 1.27 dependency review

The workspace selects Rhai's `compact_str` backend, keeping Coordinator's
owned strings, `ImmutableString` values, identifiers, and object-map keys off
`smartstring`'s reported unsound conversion. Rhai still declares
`smartstring` unconditionally, so the unused package remains in the resolved
dependency and advisory graph. The workspace exception stays scoped to that
residual until upstream removes the edge.

Coordinator keeps the 100,000-operation maximum and every authored lower
limit, along with its existing call-depth, expression-depth, source, string,
array, map, and result bounds. Rhai 1.27 now charges operations performed by a
script callback that a native function invokes. Coordinator registers no
native helper that invokes a script callback, and its maintained Rhai files
use no callback-based collection method. A separately authored workflow that
does use one may reach its unchanged declared limit sooner and should pass
`coordinatorctl test --project <directory>` before promotion.

The interpreter identity in each frozen definition now names Rhai 1.27.0, so
authoring the same project produces a new workflow revision. Before upgrading,
operators must drain runs frozen under the 1.26.1 identity, then re-author and
promote workflows under 1.27.0. The new runtime deliberately refuses recovery
from an old snapshot instead of silently reinterpreting it with changed engine
semantics.

The shared platform test
`rhai_maps_use_compact_string_keys_and_owned_unicode_round_trips` guards the
backend selection. `pure_profile_has_no_clock_sleep_or_io_and_limits_computation`,
`resource_limits_include_recursion_input_values_and_non_object_commands`, and
the `authoring_findings` suite retain the Coordinator resource and value-free
diagnostic boundaries. Existing package and protected CI gates cover the
change; no new blocking gate is introduced.

## BReg Proposal calls and follows

### Threat

A workflow uses Coordinator's workload identity to decide a request that a
person or review authority must decide; cancels a request the run did not
open; sends a second start or submit on retry and opens a duplicate request;
or settles a follow from a stale or forged signal and routes a run as if a
request were applied.

### Enforcement and defaults

- The catalog has `breg.read-proposal/v1`, `breg.start-proposal/v1`,
  `breg.submit-proposal/v1` and `breg.cancel-proposal/v1` and no operation
  that approves, rejects, decides or applies a Proposal. The unit test
  `no_operation_decides_a_proposal` in `src/operations.rs` holds that rule
  for every catalog operation. `breg.invoke-action/v1` keeps refusing a
  Proposal Action, and the Proposal operations refuse an immediate Action, at
  check time and again at preparation against the live contract.
- Start and submit are frozen commands. Submit sends the start command and
  then the empty submit transition under a second idempotency key derived
  from the first (`<key>:submit`); a retry replays both, so BReg returns the
  original receipts instead of opening a second request.
- Cancel freezes the current Proposal's cancel transition, rebinds it to a
  fresh read before sending, and sends nothing when the Proposal is already
  cancelled. Check refuses a cancel whose `proposalId` is not mapped from the
  output of a start or submit step in the same workflow
  (`definition.proposal-not-run-owned`); BReg's own cancel grant still
  decides.
- A follow settles only from the current Proposal Get under the connection
  profile's get grant, never from an event. 401, 403, 404 or a missing get
  grant holds the run with `proposal-unreadable`; a Proposal of another
  Action holds with `completion-invalid-response`. A submit follow holds with
  `proposal-handoff-refused` when the review authority refused the hand-off;
  only the allowlisted refusal code is read.
- The settled output carries only what BReg discloses to the profile: the
  outcome, ids, submission version, Action revision, the decision's status,
  time and public reason, and the input members the profile may read.
- A follow's wait keeps only the latest read's Proposal state, turn,
  submission version and allowlisted hand-off refusal code, with when it was
  read and when that state and turn were first seen. These columns are not
  encrypted: they hold no person's value and no Proposal id, and the row is
  deleted with the wait. Inspection adds the connection's `requestLink` with
  the Proposal id filled in, only for a caller already authorized to inspect
  the run; the id grants nothing without BReg's own grant. The link must be
  `https` unless its host is a loopback IP address, the same rule as a
  connection endpoint: a plain-http link can only point at the operator's own
  machine, never across a network, and a host name such as `localhost` is
  refused because name resolution is outside the Coordinator's control.
- The run list finds waits on one Proposal through the keyed wait commitment
  over the database identity and the Proposal id, so the database and the
  list cursor never hold the id in clear. The commitment leaves out the BReg
  connection so the list can compute it from the id alone; two connections
  whose Proposals share an id would share a key, which at most widens a list
  result the caller is already authorized to see. Each page still reapplies
  the caller's owner and workflow scope, and a cursor is refused unless its
  version, owner, workflow scope and every filter match.
- Doctor counts Proposal waits by turn from stored rows and calls no product.

Builder cost: a workflow that cancels must map `proposalId` from its own start
or submit step. Operator cost: the BReg connection profile needs the Proposal
get grant in addition to the Action's start grant.

### Tests

- `crates/registry-coordinator/tests/breg_proposal_follow.rs` (check-time
  rules, including `a_run_cancels_only_a_proposal_it_started_or_submitted`).
- `crates/registry-coordinator/tests/breg_proposal_adapter.rs` (frozen start
  and submit keys, cancel rebind, read of another Action's Proposal, and the
  observation table per operation).
- `crates/registry-coordinator/tests/breg_proposal_wait_postgres.rs` (the
  kept observation, its end with the wait, the request link, the `proposal`
  and `turn` list filters and their cursor binding, and the doctor count).

These are maintained references, not claims that the tests ran in this note.

## Pure profile helper set

The pure profile adds Rhai's `MoreStringPackage` and a hand-picked set of
number helpers (see below). The
interpreter ABI moved to `v2` because the callable set is part of what a frozen
definition means; a definition frozen under `v1` is refused with
`definition.abi` and no `v1` acceptance exists. Neither package registers a
clock, file, network or callback-invoking function.

Every string-producing helper was checked against the 16,384-byte string limit
and for loops that an argument can stop from ending. Two package functions were
unsafe and are replaced by host overloads (the engine looks up host-registered
functions before package functions):

- `pad(string, length, padding)` with an empty padding string never returns in
  the package: it is a native loop, so neither the operation limit nor the
  string limit can stop it, and it would hold a worker thread for good. The
  host overload refuses empty padding with an execution error and works out the
  result length in bytes before it builds anything.
  `pad_with_an_empty_padding_string_is_refused_instead_of_looping` runs both an
  authored `""` and one read from an input under a timeout.
  `pad_refuses_before_it_builds_a_string_over_the_budget` and
  `padded_len_is_the_length_pad_would_build` hold the size check. `pad` with a
  character is left as the package has it: it loops once per missing
  character, and the engine checks that character count against the byte limit
  first, so the most it builds before the final check is four times the limit.
- `replace` built its whole result and the engine refused it afterwards, so a
  16,000-byte string with a 16,000-byte substitute would first allocate about
  256 MB. The host `replace` overloads work out the result length from the match
  count and refuse before building it. The unit tests
  `replace_refuses_before_it_builds_a_string_over_the_budget` and
  `replaced_len_is_the_length_replace_would_build` hold that.

The other string helpers either shrink their input, are bounded by their input
length, or grow it by a constant factor. The package source has no other loop
that an argument controls (`split`, `index_of`, `sub_string`, `crop`,
`truncate`, `to_chars`, `trim`, `remove`, `pop`, `set` and `get`);
`package_string_helpers_end_on_empty_zero_and_extreme_arguments` calls each with
empty, zero, negative and extreme arguments under a timeout. Repeat-like growth
through `+=` stays under the limit
(`helpers_that_make_longer_strings_stay_inside_the_string_budget`).

Rhai's `BasicMathPackage` is not registered whole. It brings floating-point
transcendental functions (`sin`, `exp`, `ln`, `hypot` and the like) whose
results come from the platform's math library and may differ in the last
digits between operating systems, CPU architectures or library versions.
Function results are recomputed, not only read back: a held wait is recomputed
when waits replay, the next WaitUntil is evaluated again, and each job attempt
runs the Function again. A deadline computed with such a function could land a
second apart on two hosts. The host registers only functions that are
deterministic: `sqrt` (correctly rounded by IEEE 754), `floor`, `ceiling`,
`round`, `int`, `fraction`, `is_nan`, `is_finite`, `is_infinite`, `to_degrees`,
`to_radians`, `PI`, `E`, `parse_int`, `parse_float`, `to_int` and `to_float`,
next to the arithmetic package's `abs`, `sign`, `min` and `max`.
`only_math_whose_result_is_the_same_on_every_host_is_available` holds the
list. Float `**` (`powf`, in the arithmetic package) was already in the `v1`
profile and is unchanged; it is tracked separately.

A Function result holding NaN or an infinite float (`0.0 / 0.0`, `sqrt(-1.0)`)
is refused with `function.execution` where results turn into JSON, instead of
becoming `null` (`a_result_holding_nan_or_infinity_is_refused_not_turned_into_null`).

The unknown-call check walks the syntax tree and function table, which Rhai
exposes only under its `internals` feature. The workspace enables that
feature; the Rhai version is pinned exactly (`=1.27.0`), so the unstable
surface cannot change under a routine update. The check is an authoring aid,
not a security boundary: the engine still refuses any name it lacks when the
Function runs.
