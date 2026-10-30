from typing import Generic, Literal, TypeAlias, TypedDict, TypeVar

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
# Run identifiers are lowercase hyphenated UUIDs, checked by the native
# binding before any request is sent.
RunId: TypeAlias = str
# RFC 3339 instants, parsed by the runtime.
Instant: TypeAlias = str
# Coordinator-authored operation identifier.
OperationId: TypeAlias = str

class StartRunRequest(TypedDict):
    workflow: str
    workflowRevision: str
    input: JsonValue

class WorkflowContract(TypedDict):
    workflow: str
    workflowRevision: str
    input: JsonValue
    outcomes: dict[str, JsonValue]

class RunStatus(TypedDict):
    runId: RunId
    workflow: str
    workflowRevision: str

    bindingDigest: str
    step: str
    state: str
    outcome: str | None
    output: JsonValue | None
    failureCode: str | None
    # Where a refused call input left its operation contract, as an RFC 6901
    # pointer that names no value.
    failurePath: str | None
    admittedAt: Instant
    deadlineAt: Instant
    nextDueAt: Instant | None
    uncertain: bool
    restoreReviewRequired: bool
    cancelRequested: bool
    authoredCancelRequested: bool

class HoldDetail(TypedDict):
    """The records and date behind a held step."""

    date: str
    recordIdentifiers: list[str]

class _StepStatusOptional(TypedDict, total=False):
    # What a person needs to clear a hold: for in-force-ambiguous, the two
    # records in force and the date.
    holdDetail: HoldDetail

class StepStatus(_StepStatusOptional):
    step: str
    state: str
    generation: int
    attempt: int
    nextDueAt: Instant | None
    leaseExpiresAt: Instant | None
    commandPrepared: bool
    uncertain: bool
    receiptExpired: bool
    failureCode: str | None
    # Where a refused call input left its operation contract, as an RFC 6901
    # pointer that names no value.
    failurePath: str | None

RetryBlockReason: TypeAlias = Literal[
    "not-recoverable",
    "deadline-reached",
    "receipt-expired",
    "binding-changed",
    "other-binding-live",
    "snapshot-incompatible",
    "cancelled",
    "restore-hold",
    "restore-review-required",
    "payload-erased",
    "evaluation-uncertain",
]
OperationEffect: TypeAlias = Literal["read", "mutation", "evaluation"]
OperationKeyRequirement: TypeAlias = Literal["none", "required"]
OperationRecovery: TypeAlias = Literal[
    "read-again", "same-command-and-receipt", "same-command", "hold-after-dispatch",
]

class OperationIdentity(TypedDict):
    """Pinned public contract metadata. It does not establish current authority."""

    id: OperationId
    version: int
    product: str
    effect: OperationEffect
    keyRequirement: OperationKeyRequirement
    requiresPreparation: bool
    recovery: OperationRecovery
    readReceipt: bool

class _RecoveryStatusOptional(TypedDict, total=False):
    operation: OperationIdentity

class RecoveryStatus(_RecoveryStatusOptional):
    retryAllowed: bool
    reason: RetryBlockReason | None

EffectState: TypeAlias = Literal["accepted", "unknown"]
class EffectStatus(TypedDict):
    step: str
    operation: OperationIdentity
    operationRevision: str
    state: EffectState

class _LastObservationOptional(TypedDict, total=False):
    turn: str
    handoffRefusal: str

class LastObservation(_LastObservationOptional):
    """The latest answered read of a followed BReg Proposal. stateSince is when
    Coordinator first saw the current state and turn, not when BReg entered it."""

    state: str
    submissionVersion: int
    observedAt: Instant
    stateSince: Instant

class _WaitStatusOptional(TypedDict, total=False):
    lastObservation: LastObservation
    requestLink: str

class WaitStatus(_WaitStatusOptional):
    step: str
    acceptedStep: str
    completion: str
    completionRevision: str
    timeoutAt: Instant
    nextObservationAt: Instant | None
    notBefore: Instant
    minimumIntervalSeconds: int
    observations: int
    observationLimit: int

class RunInspection(TypedDict):
    run: RunStatus
    steps: list[StepStatus]
    effects: list[EffectStatus]
    waits: list[WaitStatus]
    recovery: RecoveryStatus

RunListState: TypeAlias = Literal[
    "running",
    "finished",
    "failed",
    "cancelled",
    "cancelled-after-effect",
    "expired",
    "attention",
    "cancel-requested",
]

ProposalTurn: TypeAlias = Literal["party", "official", "nobody"]

class _RunListOptional(TypedDict, total=False):
    nextCursor: str

class RunList(_RunListOptional):
    """One stable page of runs the caller may read, newest admission first."""

    runs: list[RunStatus]

class RetryScheduled(TypedDict):
    """The runtime accepted a same-command retry; the worker has not run it yet."""

    runId: RunId
    status: Literal["retry-scheduled"]

T = TypeVar("T")

class Complete(TypedDict, Generic[T]):
    kind: Literal["complete"]
    value: T

CoordinatorErrorKind: TypeAlias = Literal[
    "configuration", "invalid-request", "transport", "problem", "protocol",
]
CoordinatorProtocolFailure: TypeAlias = Literal[
    "header-bounds", "media-type", "body", "problem", "status", "protocol",
]

class CoordinatorClientError(Exception):
    kind: CoordinatorErrorKind
    # The `family.reason` code of the Coordinator's RFC 9457 problem document,
    # such as "run.not-visible"; set only when kind is "problem".
    code: str | None
    status: int | None
    transport_kind: str | None
    protocol_failure: CoordinatorProtocolFailure | None
    # Whether the call may have taken effect although this error was raised:
    # a timeout or broken exchange after sending, an unusable answer, or a
    # 5xx. When True after `start`, recover by sending it again with the same
    # identity, key, workflow, revision and input; a new key could admit a second run. When True
    # after `retry_same` or `cancel`, which take no key and are never resent,
    # read the run before asking again. False for a configuration or request
    # defect, a connection never established, and every 4xx refusal.
    outcome_unknown: bool

class CoordinatorClient:
    def __init__(self, base_url: str, attempt_timeout_seconds: float | None = None, connect_timeout_seconds: float | None = None, maximum_response_bytes: int | None = None, user_agent: str | None = None, trusted_root_certificates: bytes | None = None, maximum_mutation_retries: int | None = None) -> None: ...
    # Admit `{workflow, workflowRevision, input}` under the caller's key; resent under the same key
    # up to `maximum_mutation_retries` times when the outcome is unknown. The key
    # is scoped to the caller and the workflow, so the same key under two workflows
    # starts two runs, and an allowed workflow the deployment does not serve is
    # refused with 404 `workflow.not-served`, a known outcome never resent.
    # Fresh starts must match the active revision. Unknown-admission recovery keeps
    # the original revision even after activation changes.
    def start(self, token: str, idempotency_key: str, request: StartRunRequest) -> Complete[RunStatus]: ...
    # Discover the active typed contract under current start authority; starts no run.
    def workflow(self, token: str, workflow: str) -> Complete[WorkflowContract]: ...
    def status(self, token: str, run_id: RunId) -> Complete[RunStatus]: ...
    def inspect(self, token: str, run_id: RunId) -> Complete[RunInspection]: ...
    # Observe the original operation's receipt; never resubmits the operation.
    def reconcile(self, token: str, run_id: RunId, reason: str) -> Complete[RunInspection]: ...
    # Schedule the run's saved command again, unchanged, when its inspection
    # allows a retry. Takes no key, so it is sent exactly once. `reason` is 1
    # to 256 bytes without control characters, checked before sending.
    def retry_same(self, token: str, run_id: RunId, reason: str) -> Complete[RetryScheduled]: ...
    # Stop further progression; never undoes a product effect. Takes no key,
    # so it is sent exactly once. `reason` is bounded as for `retry_same`.
    def cancel(self, token: str, run_id: RunId, reason: str) -> Complete[RunStatus]: ...
    # One stable page of caller-visible runs. Pass nextCursor unchanged with
    # the same caller, state, attention, proposal, and turn values.
    # attention=True selects the effective states attention and failed.
    # proposal selects runs waiting on that BReg Proposal; turn selects runs
    # whose Proposal wait last showed that turn. Declared last: mypy reads
    # `list` in any later annotation in this class as this method.
    def list(self, token: str, limit: int, cursor: str | None = None, state: RunListState | None = None, attention: bool | None = None, proposal: str | None = None, turn: ProposalTurn | None = None) -> Complete[RunList]: ...

__version__: str
