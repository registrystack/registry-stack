# Registry Coordinator security model

This is the public security model for Registry Coordinator. It states what the
product holds, what it does not, and what an operator must do for the
invariants to hold. Coordinator has no machine-checked invariant matrix, so
each invariant here names its threat, the code that enforces it, what it
refuses, and the tests that pin it. Test names are maintained references to
the repository's own suites.

Terminology follows [PRODUCT-CONTRACT.md](PRODUCT-CONTRACT.md). Deployment
steps are in [DEPLOYMENT.md](DEPLOYMENT.md).

## 1. Scope and trust boundaries

- **Operator.** Owns the runtime configuration: connection base URLs, the
  external command path, credentials, issuer settings, the BReg connection
  profile and the Adapter payment connection. Operator configuration is
  trusted; workflow data is not.
- **Workflow author.** Authors a project that Coordinator freezes into a
  definition. An author supplies bodies, mappings and pure Functions. An author
  does not choose destinations, headers, credentials or recovery behavior; the
  closed operation catalog does.
- **Providers.** Casework, Scheduling, BReg, Adapter payments and external HTTP
  providers decide every effect a run requests. Coordinator holds workload
  identity, not decision authority, and each receiving product still
  authorizes the call.
- **Caller.** Authenticates with an access token verified against the
  configured OIDC issuer. Coordinator authenticates and authorizes every
  protected route and reapplies the caller's owner and workflow scope on every
  list page. Admission accepts a token only when its caller policy lists the
  token's exact `sub`, and refuses a delegated token (COORDINATOR-INV-10).
  Start input is the caller's assertion: Coordinator does not compare it with
  the caller's `sub`.
- **Host users.** `coordinatorctl` is local operator tooling for a trusted
  single-user machine.
- **Database.** PostgreSQL holds run, wait and job state. Coordinator does not
  defend against a database superuser.

## 2. Invariants

### COORDINATOR-INV-01: lapsed leases retry only reads

**Threat.** A worker can exit after leasing a read but before recording its
result. Holding every such job delays a workflow though repeating the operation
is safe. Treating every lapsed lease as retryable could instead repeat a
mutation, evaluation or same-command effect whose remote outcome is unknown. A
late completion from the original worker could race the replacement attempt.

**Enforcement.** `Store::decode_lapsed` in
`crates/registry-coordinator/src/store.rs` opens the authenticated definition
snapshot for the run and resolves the exact leased step. Only a call whose
catalog recovery is `read-again` receives Dispatch's `RetryThenHold` policy.
Every mutation, evaluation, same-command call, wait and local step keeps
`Hold`. `RetryThenHold` uses the existing backoff, a ten-attempt limit and the
original run deadline, and converts the dead-letter or expiry edge to
`unknown`, so repeated failure reaches operator review. Dispatch commits the
`lease-lapsed` transition audit before release and fences completion by
generation, attempt and lease token.

**Refused.** A lapsed mutation, evaluation or same-command call is never
re-sent automatically. A stale worker cannot commit after the replacement
attempt starts. Recovery does not extend the attempt or deadline budget.

**Tests.** `crates/registry-coordinator/tests/read_lease_recovery.rs`:
`lapsed_read_retries_and_fences_the_old_attempt`,
`lapsed_mutation_holds_unknown_for_operator_review`,
`lapsed_read_holds_when_attempts_are_spent`,
`lapsed_read_holds_after_its_deadline` (PostgreSQL).

### COORDINATOR-INV-02: Scheduling commands are never replayed on inference

**Threat.** Coordinator can lose the response after Scheduling committed
capacity. A fresh command, an ordinary current-state read, or replay of an
unkeyed release could duplicate or misstate that effect.

**Enforcement.** Each Scheduling lifecycle operation declares its recovery
behavior in the operation catalog (`crates/registry-coordinator/src/operations.rs`).
Reads run again. Appointment creation and hold confirmation keep the exact key
and request and may use Scheduling's original-result receipt. Hold creation,
rescheduling and cancellation keep the exact keyed command but have no receipt
lookup, and current appointment state does not settle them. Hold release
carries no key, so an ambiguous dispatch is held. Every commitment obtains
fresh task-bound Scheduling authority per durable attempt. The Scheduling
client performs no hidden mutation retry inside Coordinator.

**Refused.** An unkeyed hold release is never sent twice. Standing reads never
authorize a commitment.

**Tests.** `crates/registry-coordinator/tests/scheduling_adapter.rs`:
`lifecycle_operations_use_exact_public_client_routes_bodies_and_keys`,
`unkeyed_hold_release_holds_an_ambiguous_dispatch_without_replay`,
`only_appointment_creation_and_confirmation_have_original_result_receipts`,
`standing_reads_are_bounded_and_never_authorize_a_commitment`. In
`src/operations.rs`: `operations_use_registered_execution_semantics`.

### COORDINATOR-INV-03: the external command is bounded and sent once in effect

**Threat.** `external.command/v1` is an outbound mutation to a provider outside
Registry Stack, with a recovery path that can send it again. Workflow data
could try to steer the request to another host, path or credential. A lost
acknowledgement, timeout, redirect or server error (including a busy 503 whose
retry never settles) could be misread as failure, so a fresh command would
apply the effect twice. A response, body, request id or credential could leak
through logs, problem details, `status` or `inspect`.

**Enforcement.**

- The destination is operator configuration. `ExternalHttpConfig` in
  `crates/registry-coordinator/src/external_http.rs` holds one exact relative
  `commandPath` beside `baseUrl` and `authorization`; the workflow supplies
  only a JSON object body. `ExternalHttpConnection::command` sends one POST,
  follows no redirect, and validates the destination under the same fetch
  policy as `external.get/v1`. A connection without `commandPath` is read-only,
  and `RuntimeConfig::validate_workflow` (`workflow-binding`) refuses a command
  alias bound to it or to another connection type at `coordinatorctl check`.
- The command and its request id are frozen and persisted before the first
  send. The id derives from the run's start identity and the step, and is sent
  as `Idempotency-Key` on every attempt. The catalog declares same-command
  recovery, so `retry-same` and restart replay the frozen request and never
  mint a new id.
- Request bodies and responses are limited to 65,536 bytes, and each attempt to
  the connection's timeout, at most 2,000 milliseconds, which also covers DNS
  resolution and token acquisition. Only status 429, and status 503 before the
  final attempt, are retried automatically. A 429 is trusted to mean the
  command was not processed. A 503 may follow an effect, so `send_command`
  returns `CallOutcome::UncertainRetryable` and the worker records the attempt
  as uncertain while it retries. A deadline or retry limit reached before a
  later attempt settles it holds the run with the effect unknown, and
  `Store::write_attempt` never reports such a run `expired` or `failed`. The
  worker keeps the retry only when the longest wait the schedule allows,
  counted from the end of the attempt's lease, clears the run deadline
  (`retry_or_hold` in `crates/registry-coordinator/src/worker.rs`); otherwise it
  reports the attempt uncertain without a retry, so Dispatch holds the job
  `unknown` and `retry-same` can send the same command under the same id while
  the deadline is in the future. `Retry-After` is honoured only as one
  delta-seconds value of at most 86,400. Once the request may have left, a lost
  or broken exchange, a timeout, a redirect, any other 5xx, and an oversize,
  malformed or schema-invalid response are uncertain and hold the run.
- `interpret_command` checks the response against the alias's
  `responseSchema`, then runs the project's pinned pure Function. Only
  `accepted` with a result matching the step's declared output, or `refused`
  with a declared code, leaves the hold; everything else, including a Function
  error, is uncertain. The worker and offline scenarios use the same function,
  and scenario validation (`scenario.reply`) refuses a `success` or
  `declared-refusal` reply to the step, so no scenario reaches a result or
  refusal route the Function would not produce. Transport and scenario
  validation share one status classification (`command_status`), so a
  `response` reply with a status the worker holds or retries before
  interpretation (a redirect, a 429 or any 5xx) is refused too.
- Outcomes carry fixed failure codes only. No body, response, request id or
  token is logged or placed in a problem, `status` or `inspect`.

**Refused.** A workflow-chosen destination, header or credential; a redirect; a
fresh request id on recovery; an oversize or unusable response; any outcome
that would claim a provider failure after the request may have left.

**Tests.** `crates/registry-coordinator/tests/external_command.rs`:
`a_command_posts_the_frozen_body_and_request_id_to_the_configured_path`,
`workflow_input_cannot_choose_destination_headers_or_credentials`,
`a_lost_acknowledgement_is_uncertain_and_the_same_request_id_is_sent_again`,
`a_timeout_after_sending_is_uncertain_and_never_a_provider_failure`,
`failures_before_anything_is_sent_stay_retryable_or_refused`,
`an_oversize_or_unusable_response_is_held_without_releasing_its_body`,
`a_redirect_is_not_followed_and_the_credential_stays_at_the_origin`,
`provider_statuses_are_classified_without_claiming_a_provider_failure`,
`no_secret_body_or_request_id_reaches_logs_or_outcomes`,
`the_runtime_routes_a_frozen_command_with_its_original_request_id`,
`the_command_path_is_an_exact_operator_owned_relative_path`.
`tests/external_command_project.rs`:
`check_refuses_a_command_without_its_bound_command_connection`,
`the_workflow_cannot_name_a_destination_path_or_credential`,
`the_worker_interprets_a_response_into_one_of_three_results`,
`a_command_without_a_refused_state_has_no_refusal_route`,
`scenarios_interpret_provider_responses_with_the_pinned_function`,
`a_command_reply_reaches_its_result_only_through_the_interpret_function`,
`a_command_response_reply_carries_only_a_status_the_worker_interprets`.
`tests/external_command_postgres.rs` (PostgreSQL; each asserts `status` and
`inspect` carry no body, request id or token):
`a_lost_acknowledgement_holds_and_retry_same_sends_the_same_command`,
`a_timeout_holds_as_uncertain_and_never_claims_a_provider_failure`,
`a_restart_between_persist_and_send_sends_the_prepared_command_once`,
`a_busy_503_the_deadline_ends_holds_the_same_command_for_recovery`,
`a_deadline_that_passes_before_a_busy_503_is_retried_holds_the_effect`,
`a_busy_503_then_an_accepted_command_clears_the_unknown_effect`. In
`src/worker.rs`:
`a_busy_answer_that_may_follow_an_effect_retries_with_the_effect_unknown`,
`a_busy_answer_that_may_follow_an_effect_retries_only_when_the_retry_fits`.

### COORDINATOR-INV-04: `coordinatorctl --token-file` reads only a regular file

**Threat.** An authenticated `coordinatorctl` command reads `--token-file`
before it calls the service. A blocking read of a FIFO can hold the command
indefinitely, and following a symbolic link means the named path does not
identify the file the operator intended.

**Enforcement.** On Unix, `coordinatorctl` opens the token path read-only with
`NOFOLLOW`, `NONBLOCK` and `CLOEXEC` (`crates/registry-coordinator/src/cli.rs`),
then verifies from the opened descriptor that it is a regular file before
reading any byte. Other platforms reject a symlink or non-regular path before
opening it and verify the opened handle. The read is bounded at 16,384 bytes,
the token is validated as a compact token, and diagnostics carry no value. The
check applies only to `--token-file`; ordinary authored input files keep their
own contract.

**Refused.** A symbolic link, a FIFO, or any non-regular file as a token path.

**Tests.** `crates/registry-coordinator/tests/cli_remote.rs`:
`token_file_refuses_symlinks_and_fifos_without_blocking` (bounds the child wait
and proves neither output stream contains the synthetic token) and
`a_relative_token_file_is_read_from_the_current_directory`.

### COORDINATOR-INV-05: the raw API command grants no workflow authority

**Threat.** An operator assumes the raw API command reuses the token reader of
the other authenticated commands, or assumes a saved bearer or
`private_key_jwt` connection grants workflow authority by itself.

**Enforcement.** Coordinator retains no local caller session, so
`coordinatorctl api` refuses `--client`. The operator selects a saved
connection or an explicit one-off URL. A saved connection authenticates by
exactly one of anonymous, a referenced opaque bearer, or renewable
`private_key_jwt`, under the shared
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary).
Anonymous supplies no automatic credential, though the raw command may still
carry one explicit `Authorization` header. The helper confines destination and
headers, acquires any selected credential, and releases only the raw bounded
response. It carries no caller policy, workflow, run ownership or downstream
product authority. Coordinator still authenticates and authorizes each
protected route, and every receiving product still decides an effect a run
requests.

The two token readers differ on purpose. The authenticated Coordinator commands
keep the 16,384-byte compact-token validation and the Unix `NOFOLLOW` open
(INV-04). Direct `api --url --token-file` uses the shared opaque-bearer
contract: at most 8 KiB, and a symlink to a regular file is accepted. Saved
bearer and private-key references use the platform secret resolver's separate
strict file policy.

**Refused.** `--client` on the raw API command; a report format before any
network access.

**Tests.** `crates/registry-coordinator/tests/api_cli.rs`:
`api_and_saved_connections_are_available_without_a_runtime_config`,
`raw_api_refuses_report_format_before_network_access`; the shared tests named
in the `registry-cli-api` security boundary; and INV-04's tests for the other
reader.

### COORDINATOR-INV-06: OIDC discovery and key fetches cannot be steered inward

**Threat.** Coordinator fetches discovery and signing keys for
`deployment.authentication`. A fetch an attacker can steer may reach internal
services or cloud metadata, and a key set read over plain HTTP can be
substituted by an on-path attacker, whose keys would then mint access tokens
Coordinator accepts.

**Enforcement.** Coordinator fetches under the shared issuer network policy
that Casework, Messaging and Scheduling use, or the development loopback policy
under `development-loopback`:

- The declared issuer and a declared `jwksSource.uri` may resolve to a private
  or loopback address on any origin; both are operator configuration.
- A discovered `jwks_uri` inherits that allowance only on the issuer's own
  origin. On another origin it must use HTTPS and is refused when it resolves
  to a private or loopback address, under `development-loopback` too.
- Cloud metadata and link-local addresses are refused for declared and
  discovered endpoints alike. Redirects are disabled.
- Plain HTTP is accepted at load only with
  `deployment.authentication.allowInsecureHttp: true`, or on loopback under
  `development-loopback`. The setting never extends plain HTTP to a discovered
  endpoint on another origin.

`OidcIssuerConfig::check` in `crates/registry-platform-config/src/blocks.rs`,
reached from `AccessConfig::findings` in
`crates/registry-coordinator/src/access.rs` when the runtime file is loaded,
refuses a plain HTTP issuer or key URI these rules do not admit, naming the
member and the setting that would admit it. `AccessConfig::authenticator`
builds `IssuerNetworkPolicy` from the same block, fetches discovery through
`fetch_discovery_for_issuer`, and keeps the endpoint policy that function
returns for every later key refresh; a declared key URI keeps
`declared_jwks_fetch_policy`. When the opt-in is set, startup logs the fixed
warning from `insecure_http_startup_diagnostic`.

**Refused.** A plain-HTTP issuer or key URI without the opt-in; a discovered
key endpoint on another origin that is plain HTTP, private or loopback; cloud
metadata and link-local addresses anywhere; redirects.

**Tests.** `crates/registry-coordinator/tests/deployment_surface.rs`:
`a_remote_http_issuer_is_refused_without_the_opt_in`,
`runtime_reads_the_explicit_http_issuer_opt_in`. In `src/access.rs`:
`http_issuer_opt_in_has_a_startup_diagnostic`. Shared policy in
`crates/registry-platform-oidc/src/lib.rs`:
`non_loopback_http_requires_the_named_opt_in_while_loopback_does_not`,
`declared_loopback_http_jwks_under_an_https_issuer_is_accepted_without_the_opt_in`,
`a_cross_origin_jwks_must_use_https_even_under_the_http_opt_in`,
`discovered_cross_origin_private_or_loopback_jwks_stays_refused`,
`cloud_metadata_is_refused_for_declared_and_discovered_key_endpoints`.

### COORDINATOR-INV-07: a run never decides, and cancels only what it opened, a BReg Proposal

**Threat.** A workflow uses Coordinator's workload identity to decide a request
that a person or review authority must decide; cancels a request the run did
not open; sends a second start or submit on retry and opens a duplicate
request; or settles a follow from a stale or forged signal and routes the run
as if a request were applied.

**Enforcement.**

- The catalog has `breg.read-proposal/v1`, `breg.start-proposal/v1`,
  `breg.submit-proposal/v1` and `breg.cancel-proposal/v1` and no operation that
  approves, rejects, decides or applies a Proposal.
  `no_operation_decides_a_proposal` in `src/operations.rs` holds that for every
  catalog operation. `breg.invoke-action/v1` refuses a Proposal Action, and the
  Proposal operations refuse an immediate Action, at check time and again at
  preparation against the live contract.
- Start and submit are frozen commands. Submit sends the start command and then
  the empty submit transition under a second idempotency key derived from the
  first (`<key>:submit`); a retry replays both, so BReg returns the original
  receipts instead of opening a second request.
- Cancel freezes the current Proposal's cancel transition, rebinds it to a
  fresh read before sending, and sends nothing when the Proposal is already
  cancelled. Check refuses a cancel whose `proposalId` is not mapped from the
  output of a start or submit step in the same workflow
  (`definition.proposal-not-run-owned`); BReg's own cancel grant still decides.
- A follow settles only from the current Proposal Get under the connection
  profile's get grant, never from an event. A 401, 403, 404 or missing get
  grant holds the run with `proposal-unreadable`; a Proposal of another Action
  holds with `completion-invalid-response`. A submit follow holds with
  `proposal-handoff-refused` when the review authority refused the hand-off;
  only the allowlisted refusal code is read.
- The settled output carries only what BReg discloses to the profile: the
  outcome, ids, submission version, Action revision, the decision's status,
  time and public reason, and the input members the profile may read.
- A follow's wait keeps only the latest read's Proposal state, turn, submission
  version and allowlisted hand-off refusal code, with when it was read and when
  that state and turn were first seen. These columns are not encrypted: they
  hold no person's value and no Proposal id, and the row is deleted with the
  wait. Inspection adds the connection's `requestLink` with the Proposal id
  filled in, only for a caller already authorized to inspect the run; the id
  grants nothing without BReg's own grant. The link must be `https` unless its
  host is a loopback IP address, the same rule as a connection endpoint; a host
  name such as `localhost` is refused because name resolution is outside
  Coordinator's control.
- The run list finds waits on one Proposal through the keyed wait commitment
  over the database identity and the Proposal id, so neither the database nor
  the list cursor holds the id in clear. Each page reapplies the caller's owner
  and workflow scope, and a cursor is refused unless its version, owner,
  workflow scope and every filter match.
- Doctor counts Proposal waits by turn from stored rows and calls no product.

**Refused.** Any decide or apply of a Proposal; a cancel of a Proposal the run
did not open; a second start or submit on retry; settlement from an event.

**Tests.** `crates/registry-coordinator/tests/breg_proposal_follow.rs`
(check-time rules, including `a_run_cancels_only_a_proposal_it_started_or_submitted`);
`tests/breg_proposal_adapter.rs` (frozen start and submit keys, cancel rebind,
read of another Action's Proposal, the observation table per operation);
`tests/breg_proposal_wait_postgres.rs` (the kept observation and its end with
the wait, the request link, the `proposal` and `turn` list filters and their
cursor binding, the doctor count).

### COORDINATOR-INV-08: BReg control metadata has its own response ceiling

**Threat.** Applying the 64 KiB business-response ceiling to caller-filtered
BReg control metadata can prevent preparation of an otherwise valid Action.
Treating that oversize answer as a transient transport error repeats an
unchanged failure. Widening the response limit globally would admit larger
business data.

**Enforcement.** `adapters::breg_metadata_client`
(`crates/registry-coordinator/src/adapters.rs`) derives a client only for
`registry_contract` reads, using the BReg client's `MAX_BREG_METADATA_BYTES`
ceiling (8 MiB). `BaseRegistryClient::with_maximum_response_bytes` reuses the
same immutable credential provider, HTTP pool and source binding; the original
64 KiB client still sends target-condition, record, Action and Proposal
requests. `breg_action::failure` and `adapters::read_failure` refuse oversized
reads with `invalid-response`. Mutation classification first preserves the BReg
client's unknown-outcome signal, so an oversized mutation answer stays
uncertain. No new transport retry, authority, key, condition or Action revision
is created.

**Refused.** A metadata answer beyond 8 MiB; any business answer beyond 64 KiB.

**Tests.** `crates/registry-coordinator/tests/breg_action_adapter.rs` (metadata
above 64 KiB followed by an exact prepared Action, metadata beyond the 8 MiB
ceiling, an oversized target-condition response, an oversized mutation answer)
and `crates/registry-breg-client/tests/http_boundary.rs` (independent derived
limits, unchanged credentials and original limits, zero refusing before I/O).
These HTTP fixtures do not establish database transaction or deployed service
behavior.

### COORDINATOR-INV-09: the pure Function profile is bounded and deterministic

**Threat.** A pure Function runs author-supplied code inside the worker. An
argument-controlled loop or allocation could hold a worker thread or exhaust
memory, a host-dependent result could differ when a wait replays or a job
attempt recomputes, and a changed engine could reinterpret a frozen definition.

**Enforcement.**

- The engine is Rhai pinned exactly (`=1.27.0`) with the `compact_str` backend,
  which keeps Coordinator strings, `ImmutableString` values, identifiers and
  object-map keys off `smartstring`'s reported unsound conversion
  (`rhai_maps_use_compact_string_keys_and_owned_unicode_round_trips` guards the
  selection). Rhai still declares `smartstring` unconditionally, so the unused
  package remains in the resolved dependency and advisory graph under a scoped
  workspace exception.
- Limits: 100,000 operations (every authored lower limit applies), 32 calls, 64
  expression levels, 65,536 source bytes, 16,384-byte strings, 256 array items,
  256 map members, 131,072 JSON bytes and depth 32. The profile has no clock,
  sleep or I/O.
- `curry` is disabled, because Rhai does not count data curried into a
  function pointer against these limits and every copy of the pointer copies
  that data. Check refuses a source that uses it and names `curry`
  (`curry_is_refused_in_every_call_form`,
  `a_function_that_curries_is_refused_at_check_with_a_way_forward`).
- The interpreter identity in each frozen definition (`INTERPRETER_ABI` in
  `src/functions.rs`) names Rhai 1.27.0 and ABI `v3`, because the callable set
  is part of what a definition means. A definition frozen under another identity
  is refused with `definition.abi`, and a live run under it is held
  (COORDINATOR-INV-12); Coordinator never reinterprets an old snapshot under
  changed engine semantics.
- The profile adds Rhai's `MoreStringPackage` and a hand-picked set of math
  helpers. Neither registers a clock, file, network or callback-invoking
  function. Coordinator registers no native helper that invokes a script
  callback, and its maintained Rhai files use no callback-based collection
  method; because Rhai charges operations performed by such a callback, an
  authored workflow that uses one reaches its declared limit sooner and should
  pass `coordinatorctl test --project <directory>` before promotion.
- Host overloads of `pad` and `replace` work out the result length in bytes
  before building anything, so a result over the string budget is refused
  before allocation. `pad` with an empty padding string is refused with an
  execution error, because the package loop would never end. `pad` with a
  character loops once per missing character, after the engine checks that
  character count against the byte limit, so the most it builds before the final
  check is four times the limit. The other string helpers shrink their input,
  are bounded by it, or grow it by a constant factor, and repeat-like growth
  through `+=` stays under the limit.
- Rhai's `BasicMathPackage` is not registered whole, because its
  floating-point transcendental functions take results from the platform math
  library and may differ in the last digits between operating systems, CPU
  architectures or library versions. Results are recomputed, not only read
  back (a held wait is recomputed when waits replay, the next WaitUntil is
  evaluated again, and each job attempt runs the Function again), so a deadline
  computed with such a function could land a second apart on two hosts. The
  host registers only deterministic functions: `sqrt`, `floor`, `ceiling`,
  `round`, `int`, `fraction`, `is_nan`, `is_finite`, `is_infinite`,
  `to_degrees`, `to_radians`, `PI`, `E`, `parse_int`, `parse_float`, `to_int`
  and `to_float`, next to the arithmetic package's `abs`, `sign`, `min` and
  `max`.
- A Function result holding NaN or an infinite float (`0.0 / 0.0`,
  `sqrt(-1.0)`) is refused with `function.execution` where results turn into
  JSON, instead of becoming `null`.
- The unknown-call check walks the syntax tree and function table, which Rhai
  exposes only under its `internals` feature, enabled in the workspace. It is
  an authoring aid, not a security boundary: the engine refuses any name it
  lacks when the Function runs.

**Refused.** Empty-padding `pad`; `pad` or `replace` results over the string
budget; NaN and infinity results; a definition frozen under another
interpreter identity; any function outside the registered set.

**Tests.** `crates/registry-coordinator/tests/helper_functions.rs`:
`pad_with_an_empty_padding_string_is_refused_instead_of_looping`,
`package_string_helpers_end_on_empty_zero_and_extreme_arguments`,
`helpers_that_make_longer_strings_stay_inside_the_string_budget`,
`only_math_whose_result_is_the_same_on_every_host_is_available`,
`a_result_holding_nan_or_infinity_is_refused_not_turned_into_null`. In
`src/functions.rs`: `pad_refuses_before_it_builds_a_string_over_the_budget`,
`padded_len_is_the_length_pad_would_build`,
`replace_refuses_before_it_builds_a_string_over_the_budget`,
`replaced_len_is_the_length_replace_would_build`.
`tests/authoring.rs`:
`pure_profile_has_no_clock_sleep_or_io_and_limits_computation`,
`resource_limits_include_recursion_input_values_and_non_object_commands`.
`crates/registry-platform-script/src/rhai.rs`:
`rhai_maps_use_compact_string_keys_and_owned_unicode_round_trips`. The
`authoring_findings` suite retains the value-free diagnostic boundary.

### COORDINATOR-INV-10: only listed subjects start runs, and delegated tokens are refused

**Threat.** A run's start input names the records, subjects and recipients the
workflow reads, changes or notifies, and every downstream call runs under the
connection's own service credential or a task grant. Destinations check that
service identity, not the person a run concerns. If a token issued to a person,
or to a client acting for a person, could start a run, its holder could name
another person's record and the workflow would act on it with Coordinator's
authority: a confused deputy.

**Enforcement.** Every caller policy lists `subjects`: one to sixty-four
distinct exact token `sub` values, each at most 512 bytes without control
characters. A producer policy lists its client's own service-account subject;
an operator policy lists the named people who operate the deployment. The list
has no unrestricted form. `Authenticator::authenticate` in
`crates/registry-coordinator/src/access.rs` verifies the token, refuses any
token carrying an `act` claim, and admits it only when its matched client's
policy lists its `sub` and its required scopes are present.
`AccessConfig::findings` refuses an empty, oversized or out-of-bound `subjects`
list when the runtime file is loaded; the shared reader refuses a missing list,
a repeated subject and control characters. A token exchanged without an actor
keeps the exchanging client's own service subject and carries no `act`, so it
is admitted when that subject is listed; a delegated exchange puts the person
in `sub` and the client in `act`, and is refused. The verified `iss`, `sub`
and client remain the run owner and the admission idempotency identity.

**Refused.** A token whose `sub` the matched policy does not list, and any
token carrying `act`, both with 403 `operation.not-authorized` before any run,
key or audit row is written; a policy without `subjects`.

**Tests.** `crates/registry-coordinator/tests/deployment_surface.rs`:
`a_policy_admits_only_the_subjects_it_lists`,
`a_token_carrying_act_is_refused_and_an_exchange_without_one_is_not`.
`tests/deployment_postgres.rs`:
`a_listed_client_token_for_an_unlisted_subject_is_refused_at_start_and_creates_no_run`,
`start_input_is_not_bound_to_the_caller_subject`. `tests/runtime_config.rs`:
`caller_policies_list_the_exact_subjects_they_admit`.

### COORDINATOR-INV-11: a run cancels only a review request it submitted

**Threat.** Every workflow in a deployment calls Casework under the same review
producer identity, so Casework cannot tell which run submitted a review
request. A cancel whose `request` is built from input, a literal, a Function or
another step could withdraw a review that another run submitted.

**Enforcement.** Check refuses a `casework.cancel-review-request/v1` step
unless its input is a fields mapping whose `request` member reads the whole
output, with no path, of a `casework.submit-review-request/v1` call step in the
same workflow (`definition.review-request-not-run-owned`, at
`steps.<name>.input`). Ordinary step reference checks hold that the submit step
was accepted on every route to the cancel, so the request is the one this run
submitted. `cancel_not_run_owned` in `src/definition.rs` enforces this rule and
the Proposal rule of COORDINATOR-INV-07 as one structural check. The check runs
on restore as well as on check and package (`Definition::from_snapshot`): the
service does not start on a pinned package that breaks it, and a run admitted
under such a definition is held (COORDINATOR-INV-12). Casework still authorizes
each cancel under the producer's own identity; the check adds no authority.

**Refused.** A review cancel whose `request` is anything other than the whole
output of the run's own submit step, including an object rebuilt member by
member.

**Tests.** `crates/registry-coordinator/tests/wait_for_authoring.rs`:
`a_run_cancels_only_a_review_request_it_submitted`,
`a_review_cancel_built_by_a_function_is_refused`,
`a_snapshot_whose_review_cancel_is_not_run_owned_does_not_restore`.
`tests/catalog_scenarios.rs` checks the maintained top-level examples,
including `reviewed-notice` and `standalone-review`.

### COORDINATOR-INV-12: a run whose retained definition does not restore is held alone

**Threat.** A retained run executes the definition frozen in its snapshot. When
a later version refuses that definition on restore, for a structural rule or an
interpreter ABI change, running it anyway could take an effect the rule now
forbids, such as withdrawing a review another run submitted. Refusing the whole
deployment for one such run turns every other run and every admission into an
outage.

**Enforcement.** The serving check at startup and in readiness
(`check_runtime_bindings` in `src/store/recovery.rs`) restores every live run's
snapshot under the admission lock. `Definition::from_snapshot` is pure, so its
refusal is a property of the snapshot: the run is held with reason
`definition-refused` and the scan continues. `hold_definition_refused` writes
the durable audit request (`action: definition-refused`, the keyed run and step
references and the static `findingCode`) before the hold commits, then sets the
run to `attention` with failure code `definition-refused`. A run already held,
erased or terminal is skipped, so each run is audited once. Dispatch never
claims a held run and does not expire it at its deadline. A worker that meets a
refused definition holds the run through the same helper before it prepares or
sends anything. `retry-same`, `reconcile` and `cancel` restore the snapshot
first and refuse with 409 `run.definition-incompatible` before any command or
cancel step, authored cleanup included, is routed. A hold changes no uncertain
outcome, prepared command, spent key or restore-review mark. Held runs appear
in `attention=true`, the doctor report and `deployment-status` (`heldRuns`).

**Refused.** Any step, retry, reconcile or cancel of a held run. A snapshot that
cannot be opened, a failed query or a failed transaction verification still
fails the serving check and holds nothing, and a pinned package this version
does not restore still stops startup, naming its package digest, workflow and
finding code.

**Tests.** `crates/registry-coordinator/tests/deployment_postgres.rs`:
`a_run_whose_retained_definition_does_not_restore_is_held_alone`,
`an_unreadable_snapshot_or_store_outage_fails_the_check_and_holds_nothing`.
`tests/postgres_state.rs`:
`inspection_refuses_recovery_after_deadline_receipt_expiry_and_unsupported_abi`.
`tests/review_wait_postgres.rs`:
`cancelling_a_wait_whose_definition_does_not_restore_never_routes_its_cleanup`.
`src/deployment.rs`: `a_pinned_package_that_does_not_restore_gives_operator_context`.

### COORDINATOR-INV-13: a failure route cannot hide authority or an uncertain effect

**Threat.** A workflow fallback intended for an unavailable read could hide an
authorization refusal or continue after a mutation or model evaluation may
have completed. It could also treat a provider error body as workflow data.

**Enforcement.** `Definition::check` accepts `onFailure` only on catalog
operations classified as reads or evaluations and includes it in the frozen
acyclic graph. The graph propagates no call output on that edge. The worker
takes it only on the final ordinary attempt, with no prior uncertainty, for
the closed availability categories in `availability_failure`. Preparation
never enables the route. The accepted transition carries no output and keeps
only the bounded category as the run failure code while its successor is
current; inspection retains it on the completed call job. Restart uses the
retained attempt count, definition and edge.

**Refused.** Mutations; unknown targets; credential, configuration,
authorization, preparation, binding, command, response and protocol failures;
unknown retryable text; and every uncertain outcome. A lost or timed-out model
reply stays `evaluation-uncertain` and cannot route.

**Tests.** `crates/registry-coordinator/tests/authored_project.rs`:
`reads_and_evaluations_accept_on_failure_but_mutations_refuse_it` and
`a_failure_route_has_no_call_output_and_names_a_declared_step`.
`src/worker.rs`:
`only_exhausted_explicit_availability_can_take_a_failure_edge`.
`tests/postgres_state.rs`:
`an_exhausted_read_routes_after_restart_with_a_bounded_category_and_no_output`
and `an_authorization_refusal_never_takes_a_read_failure_route` (PostgreSQL).

### COORDINATOR-INV-14: a calendar occurrence admits at most one Run

**Threat.** A restart, competing replica, package replacement or restored
database could evaluate the same institutional time twice and create two Runs.
After downtime, replaying every missed month could also release an unreviewed
burst of downstream work. A restore hold that stopped ordinary starts but not
calendar starts would reopen ingress through the scheduler.

**Enforcement.** `CalendarSchedule` accepts only the reviewed monthly first or
last day subset and delegates named-zone gap and fold resolution to
`registry-platform-calendar`. `Store::admit_calendar_due` locks the workflow
and trigger cursor with `SKIP LOCKED`, so a cursor another replica holds is
left to that replica. It evaluates through PostgreSQL transaction time,
selects the latest due occurrence, and counts every older due occurrence as
skipped. Before a due check writes, it verifies custody and the active
workflow digest and refuses either hold, writes its audit record, then takes
the ordinary `admission_lock` and checks the active workflow digest and both
holds again under it. The Run, first job and advanced cursor commit in the
same transaction. The ordinary start identity binds the workflow, trigger and
exact occurrence instant, so a rewound cursor recovers the existing Run
instead of inserting another one. A new cursor starts at first observation
and creates no historical Run. The cursor records the trigger's canonical
cron and timezone: a new Workflow revision with the same schedule keeps the
cursor, and a changed schedule moves the cursor monotonically to the check's
database time before any evaluation under it, admits nothing, and stores and
audits the previous schedule's skipped count. Calendar checks run in their
own loop beside the ordinary worker, so lock contention delays only the
calendar, never admitted Runs.

**Refused.** Unsupported cron fields, another day of month, a non-IANA
timezone, a Workflow input that does not accept the scheduledAt-only object,
changed activation or key custody, any admission or restore hold, and
unavailable durable audit.

**Tests.** `src/calendar_trigger.rs`:
`only_the_reviewed_monthly_cron_subset_is_accepted`,
`a_fold_produces_one_earlier_instant_and_an_exclusive_successor`, and
`catch_up_selects_only_the_latest_due_instant_and_counts_every_skipped_one`.
`tests/calendar_trigger_authoring.rs`:
`a_calendar_trigger_is_checked_explained_and_restored`,
`calendar_admission_is_latest_only_atomic_and_fenced`,
`a_revision_keeps_due_occurrences_unless_its_schedule_changed` and
`an_audit_outage_admits_and_reschedules_nothing` (PostgreSQL).

### COORDINATOR-INV-15: payment completion requires exact authoritative evidence

**Threat.** A workflow could supply an amount, provider route, header, receipt or BReg destination;
reuse an acceptance for another bill or collection; treat pending, unknown or a timed-out wait as
payment; or start a fresh provider effect after an ambiguous response or unresolved receipt.

**Enforcement.** The native payment catalog accepts only `billId` and positive `billVersion` when
requesting collection, and only `collectionId` when reading a collection or recording its receipt.
`PaymentConnectionConfig` fixes the Adapter origin, Adapter payment connection and ordinary service
authorization. The maintained payment client validates strict typed responses and exact bill or
collection correlation before returning them. A request is durably keyed. Reconciliation uses only
Adapter's read-only original-request endpoint with that saved key and body under current connection
authorization. Provider-protocol failures, malformed or mismatched success documents, broken
post-dispatch exchanges, `recovery-held`, and `outcome-unknown` remain uncertain. An unresolved or
expired receipt proves no absence and grants no fresh effect.

The host-owned `collection` completion retains the accepted collection, bill, binding revision and
simulation marker. Each observation performs a fresh authorized read through the same logical
payment connection. `accepted`, `pending`, and `unknown` keep the wait pending. `confirmed` and
`failed` settle only the collection attempt; only Adapter-verified `confirmed` state can satisfy the
separate, idempotently keyed `payments.record-receipt/v1` call. Coordinator carries no BReg
bill-binding or receipt grant. A timeout changes none of these facts.

**Refused.** Workflow-selected amount, paid state, provider destination, header, receipt or BReg
destination; another command's acceptance; another collection's observation; receipt recording for
anything Adapter has not verified as confirmed; any inference that pending, unknown, timeout or a
missing receipt authorizes release or replacement.

**Tests.** `crates/registry-payment-client/tests/http_boundary.rs`:
`collection_request_sends_only_authoritative_bill_identity`,
`original_request_receipt_is_a_read_with_the_exact_key_and_body`,
`a_response_for_another_command_or_collection_is_a_protocol_failure`,
`malformed_or_duplicate_payment_evidence_fails_visibly`,
`typed_problem_codes_preserve_authentication_and_uncertainty_semantics`, and
`record_receipt_requires_confirmed_exactly_correlated_evidence`.
`crates/registry-coordinator/tests/payment_adapter.rs`:
`collection_request_and_recovery_use_the_exact_original_command`,
`ambiguous_mutation_response_holds_until_read_only_recovery_resolves`,
`payment_authentication_failure_is_a_value_free_refusal`, and
`payment_completion_settles_only_terminal_exactly_bound_state`.

## 3. Operator obligations

1. Provide idempotency for external commands: the provider must deduplicate on
   `Idempotency-Key` and must not answer 429 for a command it applied. Do not
   use `retry-same` against a provider that lacks deduplication
   ([DEPLOYMENT.md](DEPLOYMENT.md) states the provider requirements).
2. After a held external command, check the provider's own records, then
   `retry-same` or cancel the run. `reconcile` cannot settle it.
3. Resolve held Scheduling runs (hold creation, rescheduling and cancellation
   past idempotency expiry, and any ambiguous hold release) by investigating
   and resolving or cancelling the run.
4. Declare only issuer and key addresses you intend Coordinator to reach. A
   declared private address is honoured; set `allowInsecureHttp: true` only
   where the path to the issuer is trusted.
5. For a discovery document that names a key endpoint on another private origin,
   declare the endpoint as `jwksSource.uri` or serve it from the issuer's origin.
6. Grant the BReg connection profile the Proposal get grant in addition to the
   Action's start grant.
7. Run `coordinatorctl` only on a trusted single-user machine, and keep token
   files as regular files.
8. Run `coordinatorctl test --project <directory>` before promoting a workflow
   that uses a callback-based collection method. Watch for held runs in
   `attention=true`, the doctor report and `deployment-status` (`heldRuns`): a
   live run whose retained definition a version does not restore, under
   another interpreter identity or a restore rule it breaks, is held with
   `definition-refused`, and only a release that accepts its definition can end
   it (COORDINATOR-INV-12).
9. Treat a project's Function as reviewed code: a Function that maps an
   ambiguous provider answer to `accepted` is an authoring defect that
   scenarios and review must catch.
10. List in each caller policy's `subjects` only the identities it should
    admit: a producer client's own service-account subject, or the named
    operators. Update the list after the identity provider changes a client's
    subject, for example when the client or its service account is recreated
    ([DEPLOYMENT.md](DEPLOYMENT.md) says how to find it).
11. A backend that starts runs must already have authorized, for the person it
    acts for, every record, subject and recipient identifier it passes, and
    any input digest it computes. Coordinator and the destinations cannot
    check this.
12. Run workflows that must not share a Casework producer identity in separate
    deployments: one deployment is one trust domain.
13. Give Coordinator only the Adapter payment capability. Keep the BReg bill-binding and receipt
    grants on Adapter's reporter identity, and investigate an unresolved original-request receipt
    before any same-command recovery or cancellation decision.

## 4. Accepted residuals

### COORDINATOR-RES-01: a replacement read may observe newer state

**Condition.** A lapsed `read-again` call is retried after its lease lapses.
**Consequence.** The replacement can observe newer source state than the
interrupted read would have returned; `read-again` promises a safe current
observation, not a historical replay. **Mitigation.** Do not model a read whose
answer must equal an earlier one.

### COORDINATOR-RES-02: a misconfigured read can have side effects

**Condition.** A source that is wired as a read has side effects. **Consequence.**
It is retried after a lapsed lease. Coordinator cannot prove a provider's
implementation is read-only; the closed operation catalog, fixed HTTP method
and reviewed package are the boundary. **Mitigation.** Review providers before
binding them as reads.

### COORDINATOR-RES-03: a read that keeps losing its worker stops at `attention`

**Condition.** The read's existing attempt or deadline bound is spent.
**Consequence.** The run holds for operator review; recovery does not extend
either budget. **Mitigation.** Investigate the worker failure and resolve the
run.

### COORDINATOR-RES-04: Scheduling mutations without a receipt stay held

**Condition.** Scheduling exposes no original-result receipt for hold creation,
rescheduling or cancellation, and idempotency expires. **Consequence.** The run
is held; Coordinator does not infer an outcome from later state.
**Mitigation.** Investigate in Scheduling, then resolve or cancel the run.

### COORDINATOR-RES-05: Scheduling hold release stays uncertain

**Condition.** Hold release is unkeyed, and a timeout, broken exchange, invalid
response or server failure follows dispatch. **Consequence.** The outcome stays
uncertain and is never re-sent. **Mitigation.** Resolve or cancel the held run
after checking Scheduling.

### COORDINATOR-RES-06: same-command recovery trusts provider deduplication

**Condition.** The provider does not deduplicate on `Idempotency-Key`.
**Consequence.** `retry-same` can apply the effect twice; Coordinator cannot
verify deduplication. **Mitigation.** Operator obligation 1.

### COORDINATOR-RES-07: no receipt settles an uncertain external command

**Condition.** `external.command/v1` has no original-result receipt.
**Consequence.** `reconcile` cannot settle an uncertain command.
**Mitigation.** Check the provider's records, then retry or cancel the held run.

### COORDINATOR-RES-08: an accepted result is the Function's reading

**Condition.** Coordinator does not independently verify the provider's effect.
**Consequence.** A Function that maps an ambiguous answer to `accepted` records
an effect that may not have happened. **Mitigation.** Cover ambiguous answers
in scenarios and review.

### COORDINATOR-RES-09: a refusal or 429 after an uncertain attempt is held

**Condition.** A later declared refusal or 429 follows an uncertain attempt; a
retried 503 counts as one. **Consequence.** The answer is held, not routed or
retried, so a provider that replays a refusal for a repeated key leaves the run
for an operator to cancel. **Mitigation.** Cancel the run after checking the
provider.

### COORDINATOR-RES-10: lease-versus-expiry window for a retried 503

**Condition.** The check that keeps a 503's retry counts from the end of the
attempt's lease, by which a live worker normally records its answer. A worker
that records its answer after its lease has ended can still see Dispatch expire
the job. **Consequence.** The run shows `attention` with the effect unknown,
and `retry-same` refuses the expired job. Closing the window needs Dispatch
itself to hold, rather than expire, a retryable answer that may follow an
effect. **Mitigation.** Check the provider's records, then cancel the run.

### COORDINATOR-RES-11: a 429 that followed an applied command ends the run `failed`

**Condition.** The provider answers 429 after applying the command.
**Consequence.** The final attempt ends the run `failed` with
`external-rate-limited`, though the effect happened. **Mitigation.** The
provider must not answer 429 for an applied command (operator obligation 1).

### COORDINATOR-RES-12: the token-file open guards only the final path component

**Condition.** `coordinatorctl` runs on a machine where another local user can
alter directory components of the token path. **Consequence.** The Unix open is
race-safe for the final component only; broader filesystem and
directory-component races are not guarded. **Mitigation.** Use a trusted
single-user machine.

### COORDINATOR-RES-13: declared OIDC addresses may be private

**Condition.** Outside `development-loopback`, the declared issuer and a
declared key URI may resolve to a private address. **Consequence.** An operator
who declares an internal address points Coordinator at it; the allowance covers
only what the operator wrote, and cloud metadata stays refused.
**Mitigation.** Declare only intended addresses.

### COORDINATOR-RES-14: plain-HTTP issuer allows key substitution

**Condition.** `allowInsecureHttp: true` is set and an on-path attacker sits
between Coordinator and the issuer. **Consequence.** The attacker can
substitute keys. The setting is explicit, named in the startup warning, and
confined to the issuer's origin and the declared key URI. **Mitigation.** Keep
the setting unset outside trusted networks.

### COORDINATOR-RES-15: a cross-origin private key endpoint is refused at startup

**Condition.** A discovery document names a key endpoint on another private
origin. **Consequence.** Startup refuses it; this is an availability cost, not
an integrity loss. **Mitigation.** Operator obligation 5.

### COORDINATOR-RES-16: Proposal wait commitments omit the BReg connection

**Condition.** Two BReg connections have Proposals that share an id.
**Consequence.** The two waits share a commitment key, which at most widens a
list result the caller is already authorized to see; owner and workflow scope
are reapplied on every page. **Mitigation.** None needed.

### COORDINATOR-RES-17: an oversized BReg mutation answer is uncertain

**Condition.** A mutation answer exceeds the response ceiling. **Consequence.**
The outcome stays uncertain and needs the existing same-command recovery or
operator resolution. **Mitigation.** Resolve through recovery or the operator.

### COORDINATOR-RES-18: `smartstring` remains in the dependency graph

**Condition.** Rhai declares `smartstring` unconditionally. **Consequence.**
The unused package stays in the resolved dependency and advisory graph, though
Coordinator's strings avoid its reported unsound conversion. **Mitigation.**
The workspace advisory exception is scoped to this residual.

### COORDINATOR-RES-19: float `**` is not on the deterministic math list

**Condition.** A Function uses float `**` (`powf`, in the arithmetic package).
**Consequence.** Its result is not covered by the deterministic-math rule, so
last digits could differ across hosts. **Mitigation.** Do not derive a
deadline or a comparison threshold from float `**`.

### COORDINATOR-RES-20: a trusted backend can pass an identifier it has not authorized

**Condition.** A listed backend passes a record, subject or recipient
identifier it has not authorized for the person it acts for. **Consequence.**
Coordinator cannot tell, because the input is the backend's assertion, and
destinations check the connection's service identity, task grant and their own
policy, not the person a run concerns, so they do not catch it either.
**Mitigation.** Operator obligation 11.

### COORDINATOR-RES-21: a listed subject is trusted for everything its policy names

**Condition.** A listed backend credential is compromised. **Consequence.**
The subject binding does not contain it: the holder can start every workflow
and action the policy names. **Mitigation.** Keep each policy's workflows and
scopes to what its client needs, and protect the client credential.

### COORDINATOR-RES-22: subjects are compared exactly

**Condition.** The identity provider changes a client's service-account
subject. **Consequence.** That client's starts are refused until `subjects` is
updated. **Mitigation.** Operator obligation 10.

### COORDINATOR-RES-23: a consent read before a Messaging send is advisory

**Condition.** In the reviewed-notice pattern, the workflow reads consent
(`noticeAllowed`) again just before the Messaging send. **Consequence.** The
read is advisory at commit time: consent revoked between the read and the send
is not seen. Messaging does not own consent to be contacted
([Messaging README](../messaging/README.md), Product boundary).
**Mitigation.** Where revoked consent must stop a send, the source of record or
Messaging's own policy has to refuse it.

### COORDINATOR-RES-24: an input digest is the starter's assertion

**Condition.** In the reviewed-notice example, the trusted starter computes
`applicationDigest` over the bounded projection and the workflow passes it to
Casework as the review subject's digest. **Consequence.** The workflow checks
only that the record's identifier and revision still match the input, so the
digest is an input trust assumption, not a consent check. **Mitigation.**
Operator obligation 11.

### COORDINATOR-RES-25: workflows in one deployment share a Casework producer

**Condition.** Several workflows run in one deployment. **Consequence.** They
call Casework under one producer identity; the review-cancel rule
(COORDINATOR-INV-11) is structural over the reviewed, pinned definition and
adds no runtime check, and Casework remains the authority for each cancel.
**Mitigation.** Operator obligation 12.

### COORDINATOR-RES-26: this version cannot end a held run

**Condition.** A live run is held with `definition-refused`. **Consequence.**
`retry-same`, `reconcile` and `cancel` refuse it, and nothing runs for it; only
a release that accepts its definition can end it. A run held while an earlier
process's lease on its step is still open keeps that lease until it lapses;
the lapse holds the step with its own failure code, replacing
`definition-refused` on the run, and the next serving check holds the run
again with a second audit record. Nothing runs for it in between, because
every path restores the snapshot before acting. A held run that had failed and
is still recoverable keeps its job failure code, while the run's failure code
becomes `definition-refused`. **Mitigation.** Operator obligation 8.

### COORDINATOR-RES-27: a held run's finding code is recomputed

**Condition.** A report lists a held run. **Consequence.** The finding code is
not stored on the run: it is in the hold's audit record, and each report
recomputes it from the retained snapshot. Doctor restores retained snapshots
to list held runs, so a snapshot that cannot be opened fails the doctor report
as it fails the serving check. **Mitigation.** None needed; an unreadable
snapshot is already a serving-check failure to investigate.

## 5. Reporting

Report suspected vulnerabilities as described in the repository's
[SECURITY.md](../../SECURITY.md).
